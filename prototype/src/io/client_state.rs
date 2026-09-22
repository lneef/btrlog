use std::io;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;

use papaya::HashMap;

use super::ThreadUring;
use super::session::{SessionAddr, SessionId, SessionManager};
use super::stream::MessageConsumer;

pub struct ClientState<C: MessageConsumer> {
    manager: SessionManager<C>,
    table: HashMap<SocketAddr, SessionId>,
}

impl<C: MessageConsumer> ClientState<C> {
    fn new(io: ThreadUring, slots: usize, consumer: C) -> Self {
        Self {
            manager: SessionManager::new(io, None::<OwnedFd>, slots, consumer),
            table: HashMap::new(),
        }
    }

    pub async fn get_or_connect(&mut self, ip_port: SocketAddr) -> io::Result<SessionAddr> {
        let guard = &self.table.guard();
        match self.table.get(&ip_port, guard) {
            Some(addr) => Ok(self
                .manager
                .open_stream(*addr)
                .expect("Enought streams per session")),
            None => {
                let res = self.manager.connect(ip_port).await?;
                let stream = self
                    .manager
                    .open_stream(res)
                    .expect("Enough streams per session");
                self.table.insert(ip_port, res, guard);
                Ok(stream)
            }
        }
    }
}
