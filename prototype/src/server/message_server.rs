use std::{
    cell::{RefCell, UnsafeCell},
    net::SocketAddr,
    os::fd::AsRawFd,
    rc::{Rc, Weak},
    time::{Duration, Instant},
};

use crate::{
    config::{IOConfig, ServerConfig, ServerThreadConfig},
    io::{
        BufferPoolConfig, ThreadBuffers,
        buffer::IoBuf,
        local_buffer_pool,
        session::{SessionAddr, SessionManager},
        stream::MessageConsumer,
        uring::{IOEnterIntent, OpId},
        watermark::{PacketConsumer, WatermarkRecv},
    },
    runtime::{
        Executor, ThreadRuntime,
        bounded_task_list::BoundedTaskList,
        future::{HeapFuture, allocate_heap_future},
        mesh::{self, MeshConfig},
        rcwaker::RcWaker,
    },
    server::server_runtime::{server_exec, server_rt},
    trace::{MetricMap, MetricMapToBenchmarkParams, RequestTracer},
    types::{
        id::JournalId,
        message::{AddEntryResponse, JournalMessageReceiver, JournalRequest, JournalResponse},
        packet::{PacketHeader, RequestPacket, ResponsePacket},
        wire::WireMessage,
    },
};
use perf_event_block::PerfEventTimesliced;
use reqtrace::{MicrosecondMeasurement, trace};

use super::server_runtime::{InternalRuntimeAction, ServerExecutor, ServerShutdownResult};

impl Into<JournalResponse> for ServerShutdownResult {
    fn into(self) -> JournalResponse {
        match self {
            ServerShutdownResult::Ok => JournalResponse::ShutdownSucessful,
            _ => JournalResponse::ShutdownCancelled,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ReplyTarget {
    Udp(SocketAddr),
    Stream(SessionAddr),
}

/// Hands TCP requests to their `MessageServer` and collects ended streams.
struct ServerSink<JournalStore: JournalMessageReceiver + 'static> {
    server: Weak<MessageServer<JournalStore>>,
    ended: Rc<RefCell<Vec<SessionAddr>>>,
}

impl<JournalStore> MessageConsumer for ServerSink<JournalStore>
where
    JournalStore: JournalMessageReceiver + 'static,
{
    fn consume(&self, result: i32, addr: SessionAddr, buf: Option<&[u8]>) {
        let Some(msg) = buf else {
            assert!(result < 0, "stream end without an error");
            self.ended.borrow_mut().push(addr);
            return;
        };
        let Some(server) = self.server.upgrade() else {
            return;
        };
        let (pkt, _msgbytes) = match RequestPacket::decode_from(msg) {
            Ok(pkt) => pkt,
            Err(decode_err) => {
                log::error!("Error decoding stream message: {:?}, ignoring.", decode_err);
                return;
            }
        };
        debug_assert_eq!(_msgbytes, msg.len());
        server.spawn_request_op(ReplyTarget::Stream(addr), pkt);
    }
}

struct MessageServer<JournalStore: JournalMessageReceiver + 'static> {
    cfg: &'static ServerConfig,
    store: Rc<JournalStore>,
    exec: Rc<ServerExecutor>,
    request_tasks: UnsafeCell<BoundedTaskList<Self::RequestContinuation>>,
    request_task_pool: ThreadBuffers,
    others: mesh::Senders<(RequestPacket, SocketAddr)>,
    sock: std::net::UdpSocket,
    sessions: SessionManager<ServerSink<JournalStore>>,
    /// streams ended by their session, closed once no put is in flight
    ended_streams: Rc<RefCell<Vec<SessionAddr>>>,
    /// in-flight stream puts per stream
    stream_puts: RefCell<Vec<(SessionAddr, usize)>>,
    port: u16,
    id: usize,
    mesh_stats: UnsafeCell<(usize, usize)>,
}

// doesn't work when defining within impl for some reason; unstable feature
type RequestHandlerType<JournalStore: JournalMessageReceiver + 'static> =
    impl Future<Output = InternalRuntimeAction> + use<JournalStore>;

impl<JournalStore> MessageServer<JournalStore>
where
    JournalStore: JournalMessageReceiver + 'static,
{
    #[allow(dead_code)]
    type RequestContinuation = HeapFuture<RequestHandlerType<JournalStore>>;
    const REQUEST_FUTURE_SIZE: usize = std::mem::size_of::<RequestHandlerType<JournalStore>>();
    const SESSION_SLOTS: usize = 64;

    fn new(
        cfg: &'static ServerConfig,
        store: Rc<JournalStore>,
        exec: Rc<ServerExecutor>,
        others: mesh::Senders<(RequestPacket, SocketAddr)>,
        sock: std::net::UdpSocket,
        port: u16,
        id: usize,
    ) -> Rc<Self> {
        let bound = exec.config().tasks_per_thread;
        let request_task_pool = local_buffer_pool(
            Self::REQUEST_FUTURE_SIZE,
            BufferPoolConfig::build_with(|buf_cfg| buf_cfg.prealloc_size = bound * Self::REQUEST_FUTURE_SIZE.next_power_of_two()),
        );
        Rc::new_cyclic(|server| {
            let ended_streams = Rc::new(RefCell::new(Vec::new()));
            let sink = ServerSink {
                server: server.clone(),
                ended: ended_streams.clone(),
            };
            let addr = sock.local_addr().expect("error getting local address");
            let listener = exec.io().tcp_listener(addr).expect("error binding tcp listener");
            let mut sessions = SessionManager::new(exec.io().clone(), Some(listener), Self::SESSION_SLOTS, sink);
            sessions.start_accepting();
            Self {
                cfg,
                store,
                exec,
                request_tasks: UnsafeCell::new(BoundedTaskList::new(bound)),
                request_task_pool,
                others,
                sock,
                sessions,
                ended_streams,
                stream_puts: RefCell::new(Vec::new()),
                port,
                id,
                mesh_stats: UnsafeCell::new((0, 0)),
            }
        })
    }

    /// Handles session events, then closes ended streams without puts in flight.
    fn manage_sessions(&self) -> usize {
        let events = self.sessions.manage().expect("session manage failed");
        let puts = self.stream_puts.borrow();
        self.ended_streams.borrow_mut().retain(|addr| {
            let busy = puts.iter().any(|(a, _)| a == addr);
            if !busy {
                self.sessions.close_stream(addr);
            }
            busy
        });
        events
    }

    fn take_stats(&self) -> JournalStore::Metrics {
        self.store.take_stats()
    }

    fn run2(self: &Rc<Self>, mut mesh: mesh::mailbox::Receiver<(RequestPacket, SocketAddr)>) -> ServerShutdownResult {
        let recv = Rc::new(WatermarkRecv::new(self.sock.as_raw_fd(), self.exec.io().clone(), 32 as u16, self));
        // let (mut long_loops, mut loops) = (0, 0);
        // let mut loop_timer = MicrosecondMeasurement::new_started();
        let mut last_stats = Instant::now();
        while !self.exec.wind_down.get() {
            loop {
                let sessions = self.manage_sessions();
                if last_stats.elapsed() >= Duration::from_secs(1) {
                    last_stats = Instant::now();
                    let stats = self.sessions.take_send_stats();
                    if stats.staged > 0 {
                        stats.print("server", self.id);
                    }
                }
                let mut reqlen = self.poll_requests();
                let genericlen = self.exec.poll_generic_tasks();
                reqlen += self.poll_requests();
                let mut progress = sessions + reqlen + genericlen;

                while let Ok(msg) = mesh.try_recv() {
                    unsafe { &mut *self.mesh_stats.get() }.1 += 1;
                    self.spawn_request_op(ReplyTarget::Udp(msg.1), msg.0);
                    progress += 1;
                }

                if progress == 0 {
                    break;
                }
                self.exec.enter_io_direct(IOEnterIntent::Submit);
                recv.poll_completed();
            }
            if self.exec.check_mailbox() == 0 {
                self.exec.enter_io_direct(IOEnterIntent::Starved);
            }

            if self.exec.wind_down.get() {
                recv.start_winding_down();
            }
        }
        // println!("id {} (thread {:?}) has {} journals, {:?} mesh sends/recvs", self.id, std::thread::current().id(), self.store.journal_count(), unsafe { *self.mesh_stats.get() });
        // println!("{}/{} = {}% long loops", long_loops, loops, 100.0 * (long_loops as f64) / (loops as f64));
        ServerShutdownResult::Ok // XXX
    }

    fn run(self: &Rc<Self>, mut mesh: mesh::mailbox::Receiver<(RequestPacket, SocketAddr)>) -> ServerShutdownResult {
        let recv = Rc::new(WatermarkRecv::new(self.sock.as_raw_fd(), self.exec.io().clone(), 32 as u16, self));
        let (mut long_loops, mut loops) = (0, 0);
        let mut loop_timer = MicrosecondMeasurement::new_started();
        while !self.exec.wind_down.get() {
            let micros = loop_timer.next_measurement();
            loops += 1;
            if micros > 20.0 {
                long_loops += 1;
                if long_loops % 100 == 0 {
                    log::trace!("long loop {}/{} with {}", long_loops, loops, self.stats_string());
                }
            }
            let mut progress = 0;
            //  || recv.active_op_count() > 0 {
            self.exec.check_mailbox();
            progress += recv.poll_completed();
            progress += self.poll_requests();
            while let Ok(msg) = mesh.try_recv() {
                unsafe { &mut *self.mesh_stats.get() }.1 += 1;
                self.spawn_request_op(ReplyTarget::Udp(msg.1), msg.0);
                progress += 1;
            }
            progress += self.exec.poll_generic_tasks();
            self.exec.enter_io(progress);
            if self.exec.wind_down.get() {
                recv.start_winding_down();
            }
        }
        // println!("id {} (thread {:?}) has {} journals, {:?} mesh sends/recvs", self.id, std::thread::current().id(), self.store.journal_count(), unsafe { *self.mesh_stats.get() });
        // println!("{}/{} = {}% long loops", long_loops, loops, 100.0 * (long_loops as f64) / (loops as f64));
        log::trace!("message_server STOPPED polling {}", self.exec.wind_down.get());
        ServerShutdownResult::Ok // XXX
    }

    fn pick_receiver(&self, id: JournalId) -> usize {
        self.others.pick_receiver_uuid(id)
    }

    fn poll_requests(self: &Rc<Self>) -> usize {
        self.with_open_requests(|t| self.exec.poll_runtime_tasks(t, |idx| RequestTaskWaker::new_rc_waker(self, idx)))
    }

    #[define_opaque(RequestHandlerType)]
    fn handle_request_wrapped(self: Rc<Self>, fwd: ReplyTarget, pkt: RequestPacket) -> RequestHandlerType<JournalStore> {
        async move { self.handle_request(fwd, pkt).await }
    }

    async fn handle_request(self: Rc<Self>, fwd: ReplyTarget, pkt: RequestPacket) -> InternalRuntimeAction {
        let _time_sum = MicrosecondMeasurement::new_started();
        let mut _time_range = _time_sum.clone();
        let tracer = RequestTracer::default();
        let id = match pkt.request.journal_id() {
            Some(id) => id,
            None => {
                return if std::hint::unlikely(pkt.request == JournalRequest::Shutdown) {
                    if matches!(fwd, ReplyTarget::Udp(addr) if addr.port() == 0) {
                        InternalRuntimeAction::Shutdown
                    } else {
                        let res = self.shutdown().await;
                        // actually await this net send result here to ensure response
                        // is sent to client before the entire runtime shuts down
                        let header = PacketHeader {
                            msg_id: pkt.header.msg_id,
                            reply_to: self.port,
                            stream_id: pkt.header.stream_id,
                            fragment_len: 0,
                        };
                        log::info!("replying to shutdown request {:?} with {:?}", pkt.header, header);
                        self.net_send(header, res.clone().into(), fwd).await;
                        InternalRuntimeAction::DidShutDown(res)
                    }
                } else {
                    InternalRuntimeAction::Continue
                };
            }
        };
        let target_proc = self.pick_receiver(id);
        if target_proc == self.id {
            // XXX for latency testing purposes
            // let this: &'static Self = unsafe { std::mem::transmute(self) };
            let header = PacketHeader {
                msg_id: pkt.header.msg_id,
                reply_to: self.port,
                stream_id: pkt.header.stream_id,
                fragment_len: 0,
            };
            log::trace!(
                "Processing packet {} with logid {} myself ({}) at {}us",
                pkt.header.msg_id,
                id,
                target_proc,
                _time_range.stop_measurement()
            );
            log::trace!("Proc {} at {}", pkt.header.msg_id, _time_range.stop_measurement());
            let mut response = trace!(tracer.store_accept, self.store.accept_tracing(&pkt.request, &tracer).await);
            log::trace!("Replying to Packet {} to {:?} at {}us", pkt.header.msg_id, fwd, _time_range.stop_measurement());
            #[cfg(feature = "trace-requests")]
            if let JournalResponse::AddEntry(AddEntryResponse{ ref mut tracer, .. }) = response {
                tracer.server_qlen = self.exec.get_current_qlen();
                tracer.server_uring_outstanding = self.exec.io().current_outstanding();
                tracer.server_total_time.set_cycles(_time_range.stop_measurement_raw())
            }
            trace!(tracer.send_call, self.net_send(header, response, fwd).await);
            #[cfg(feature = "trace-requests")]
            {
                let total_time = _time_sum.stop_measurement();
                tracer.print_if_long(total_time, format!("[{:?}] {}", pkt, self.stats_string()));
            }
            // can't happen in current implementation, caught above in id match
            // let shutdown = response == JournalResponse::ShutdownSucessful || response == JournalResponse::ShutdownCancelled;
            // InternalMessageHandlerAction::DidShutDown(response)
            InternalRuntimeAction::Continue
        } else {
            let ReplyTarget::Udp(fwd) = fwd else {
                log::error!("stream request for journal {} owned by thread {}, not {}", id, target_proc, self.id);
                std::process::abort();
            };
            // TODO spawn so as to not block next recv?
            log::trace!("Forwarding packet over chan: {} -> {}", self.id, target_proc);
            // XXX clone: expensive logging
            unsafe { &mut *self.mesh_stats.get() }.0 += 1;
            let fwd_res = self.others.send_to(target_proc, (pkt, fwd)).await;
            match fwd_res {
                Ok(_) => {}
                Err(_) => {
                    log::error!("Got mesh send error");
                    // TODO reply with some error to client here ourselves?
                }
            }
            // Self::log_proc_time(t_start, "internal forwarding", pkt.header.msg_id, &pkt.request);
            InternalRuntimeAction::Continue
        }
    }

    fn stats_string(&self) -> String {
        format!(
            "(MessageServer :exec {} :requests {})",
            self.exec.executor_stats(),
            self.with_open_requests(|r| r.task_stats_str())
        )
    }

    async fn net_send(&self, header: PacketHeader, request: JournalResponse, target: ReplyTarget) {
        let mut outgoing = crate::io::local_packet_buffer_pool().pop();
        let _msgid = header.msg_id;
        let pkt = ResponsePacket { header, request };
        let bytes = match pkt.encode_framed(outgoing.as_mut_slice()) {
            Ok(bytes) => bytes,
            Err(encode_err) => {
                log::error!("Got encoding error {:?}", encode_err);
                return;
            }
        };
        outgoing.mark_used(bytes);
        let addr = match target {
            ReplyTarget::Udp(addr) => addr,
            ReplyTarget::Stream(addr) => return self.stream_send(outgoing, addr).await,
        };
        // self.exec.io().clone().ff_send_to(self.sock.as_raw_fd(), addr, outgoing).await;
        let (res, _buf) = self.exec.io().send_to(self.sock.as_raw_fd(), addr, outgoing).await;
        match res {
            Ok(written) => {
                assert!(written == bytes);
            }
            Err(send_err) => {
                log::error!("Error while sending response: {:?}", send_err);
            }
        }
    }

    async fn stream_send(&self, buf: IoBuf, addr: SessionAddr) {
        self.track_stream_put(addr, true);
        let (res, _buf) = self.sessions.put(buf, &addr).await;
        self.track_stream_put(addr, false);
        if let Err(send_err) = res {
            log::error!("Error while sending response on {:?}: {:?}", addr, send_err);
        }
    }

    fn track_stream_put(&self, addr: SessionAddr, start: bool) {
        let mut puts = self.stream_puts.borrow_mut();
        let pos = puts.iter().position(|(a, _)| *a == addr);
        match (pos, start) {
            (Some(pos), true) => puts[pos].1 += 1,
            (None, true) => puts.push((addr, 1)),
            (Some(pos), false) => {
                puts[pos].1 -= 1;
                if puts[pos].1 == 0 {
                    puts.swap_remove(pos);
                }
            }
            (None, false) => panic!("untracked stream put on {:?}", addr),
        }
    }

    async fn shutdown(&self) -> ServerShutdownResult {
        log::trace!("shutting down logger {:?}", self.id);
        let res = match self.store.accept(&JournalRequest::Shutdown).await {
            JournalResponse::ShutdownSucessful => ServerShutdownResult::Ok,
            JournalResponse::ShutdownCancelled => ServerShutdownResult::NotAllJournalsFlushed("".to_string()),
            x => panic!("Received {:?} after requesting shutdown?!", x),
        };
        self.exec.wind_down.set(true);
        if self.id == 0 {
            // XXX prettier way of doing this?
            let msg = RequestPacket {
                header: PacketHeader {
                    msg_id: u64::MAX,
                    reply_to: 0,
                    stream_id: 0,
                    fragment_len: 0,
                },
                request: JournalRequest::Shutdown,
            };
            let addr = ([0, 0, 0, 0], 0u16).into();
            let mut successful_sends = 0;
            for reply in self.others.broadcast_iter(0, (msg, addr)) {
                let id = reply.await;
                if id.is_ok() {
                    successful_sends += 1
                }
            }
            if successful_sends != self.others.size() - 1 {
                let msg = format!(
                    "couln't send shutdown message to {:?} workers ({:?} reached)",
                    self.others.size() - 1,
                    successful_sends
                );
                log::error!("{}", msg);
                return ServerShutdownResult::NotAllJournalsFlushed(msg);
            }
        }
        res
    }

    fn spawn_request_op(self: &Rc<Self>, fwd: ReplyTarget, pkt: RequestPacket) {
        let reqname = format!("(Request :from {:?} :request {} :id {})", fwd, pkt.request, pkt.header.msg_id);
        let this = self.clone();
        let onheap = allocate_heap_future(&self.request_task_pool, this.handle_request_wrapped(fwd, pkt));
        self.with_open_requests(|t| t.add_task_or_panic(reqname, onheap));
    }

    fn wake_request_task(self: &Rc<Self>, tag: u16) {
        self.with_open_requests(|t| t.activate_task(tag));
    }

    pub(super) fn with_open_requests<T, F: FnOnce(&mut BoundedTaskList<Self::RequestContinuation>) -> T>(&self, f: F) -> T {
        f(unsafe { &mut *self.request_tasks.get() })
    }
}

impl<JournalStore> PacketConsumer for &Rc<MessageServer<JournalStore>>
where
    JournalStore: JournalMessageReceiver + 'static,
{
    fn consume_raw(&self, result: i32, from: SocketAddr, buf: IoBuf, _opid: OpId) {
        if result <= 0 {
            log::error!("tried to receive packet with error code {}", result);
            return;
        }
        let bytes = result as usize;
        let (pkt, _msgbytes) = match RequestPacket::decode_from(&buf.as_slice()[..bytes]) {
            Ok(pkt) => pkt,
            Err(decode_err) => {
                log::error!("Error decoding message: {:?} <msg>{:?}</msg>, ignoring.", decode_err, buf.as_slice());
                return;
            }
        };
        debug_assert_eq!(_msgbytes, PacketHeader::WIRE_SIZE + pkt.header.fragment_len as usize);
        log::debug!("spawning request for packet {:?} from op id {:?} at {:?}", pkt.header, _opid, Instant::now());
        self.spawn_request_op(ReplyTarget::Udp(from), pkt);
    }
}

struct RequestTaskWaker<JournalStore> {
    _data: std::marker::PhantomData<JournalStore>,
}
impl<JournalStore> RcWaker for RequestTaskWaker<JournalStore>
where
    JournalStore: JournalMessageReceiver + 'static,
{
    type Handler = MessageServer<JournalStore>;

    fn on_wake(handler: Rc<Self::Handler>, tag: u16) {
        handler.wake_request_task(tag);
    }

    fn on_wake_by_ref(handler: &Rc<Self::Handler>, tag: u16) {
        handler.wake_request_task(tag);
    }
}

////////////////////////////////////////////////////////////////////////////////
pub async fn run_message_server<Factory, Worker>(
    server_cfg: &'static ServerConfig,
    io_cfg: &'static IOConfig,
    base_addr: SocketAddr,
    worker_factory: Factory,
) -> (Vec<ServerShutdownResult>, impl MetricMap)
where
    Factory: Fn(usize) -> Worker + Send + Clone,
    Worker: Future<Output: JournalMessageReceiver + 'static>,
{
    const PERF_PRINT_MILLIS: u64 = 1000;
    let _metrics_init = MetricMapToBenchmarkParams::<<<Worker as Future>::Output as JournalMessageReceiver>::Metrics>::default();
    // let _perf = PerfEventTimesliced::default_events(1, _metrics_init, Duration::from_millis(PERF_PRINT_MILLIS), true);
    // let stats_chan = _perf.sender().clone();
    let results = mesh::create_partial_mesh(
        server_rt(),
        Some(server_cfg.journal_threads()),
        cfg_builder(server_cfg, io_cfg),
        move |myid, mesh| {
            let store = worker_factory(myid);
            let exec = server_rt().current_executor();
            let io = exec.io().clone();
            // let stats_chan = stats_chan.clone();
            //let main = if myid == 0 { Some(main.clone()) } else { None };
            async move {
                let store = std::rc::Rc::new(store.await);
                let port = if myid == 0 { server_cfg.port } else { 0 };
                let sock = io.udp_bind((base_addr.ip(), port)).expect("error binding socket");
                let myport = sock.local_addr().expect("error getting local address").port();
                let (receiver, others) = mesh.join_as_full_node().await;
                let server = MessageServer::new(server_cfg, store, server_exec(), others, sock, myport, myid);
                // exec.spawn_task({
                //     let server = server.clone();
                //     async move {
                //         loop {
                //             let _ = io.sleep(Duration::from_millis(PERF_PRINT_MILLIS)).await; // XXX
                //             let stats = server.take_stats();
                //             if let Err(e) = stats_chan.send(stats.into()) {
                //                 eprintln!("error sending stats to timesliced perf, stopping collector: {:?}", e);
                //                 break;
                //             }
                //         }
                //     }
                // });
                let res = server.run2(receiver);
                (res, server.take_stats())
            }
        },
    )
    .await;
    log::debug!("node {:?} mesh shut down", base_addr);
    let shutdown_results = results
        .iter()
        .map(|res| match res {
            Ok((res, _stats)) => res.clone(),
            Err(e) => ServerShutdownResult::RuntimeError(format!("{}", e)),
        })
        .collect();
    let metrics = MetricMap::merge_all(results.into_iter().filter_map(|res| res.ok()).map(|(_r, s)| s));
    (shutdown_results, metrics)
}

fn cfg_builder(server: &'static ServerConfig, io: &'static IOConfig) -> impl Fn(usize) -> MeshConfig + Clone + Send {
    move |tid: usize| {
        let cfg = ServerThreadConfig { server, io, tid };
        MeshConfig::build_with(|m| {
            m.channel_buffer = server.chan_depth;
            m.executor_config = From::from(cfg);
        })
    }
}
