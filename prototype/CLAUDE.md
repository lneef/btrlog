# Btrlog 

## Scope

The goal is implement a TCP networking layer for BTRLOG. Currently only UDP is implemented. On the send side TCP buffers into iovec for sending to comply with urings one 
outstanding send per stream limit.

### Receive
On the receive side the main eventloop dispatched incoming packets via multishot recv.
- Dispatcher decodes incoming packets into iobuf. Used multishot buffers are resubmitted
- With the new buffer new tasks are spawned

### Send
For send we want to use `iovec` to forward multiple messages over a single stream. To this end we have a staging queue per connection to stage iovec entries which are then forwarded to uring using `send_msg`. The tasks <-> request mapping is kept as a table to iovec indices. Before resubmitting the table is normalized to keep the stream order.

## Structure 
| Path | Description |
|------|-------------|
| `src/lib.rs` | Crate root and feature-gated modules |
| `src/bin/` | CLI binaries (`logger`, `v2_bench`, `roofline_uring`) |
| `src/config.rs` | Configuration structs and CLI flags |
| `src/client/` | Client runtime, quorum logic, stats, journal state |
| `src/server/` | Server runtime, journal, WAL, blob store, message server |
| `src/io/` | Uring networking backend, buffers, watermarks, send and receive logic. Backend specific logic SHOULD be confined to this module|
| `src/runtime/` | Custom runtime primitives and scheduling utilities, Implemetation of custom async executor |
| `src/node/` | Cluster membership and health checks |
| `src/types/` | Shared message, packet, id, and error types |
| `src/bench.rs` | Benchmark support and logger routines |
| `src/trace.rs` | Latency/trace hooks and feature flags |
| `src/util.rs` | Shared helpers |
| `control/` | Infra scripts and cluster orchestration |


## Guidelines

### Implemetation
- Keep comments short and concise. Only comment if it is necessary, prefer to avoid comments. Otherwise comment the `what` not the `why`. 
    - every line should add new info, refer to a new aspect, no multiline prose
    - refrain from using dependent clause within the same line 
    - never use `since` or another causal connective, it always introduces a `why` and a dependent clause
- Add `assert!` for critical, CHEAP to check preconditions and post conditions of operations and `debug_assert!` for more expensive preconditions and post conditions 
    - but keeps assert limited, do not add asserts if the conditions holds trivially
- Write Safe idiomatic Rust wherever possible 
    - Keep unsafe blocks short and aggressively minimize the overall number
       - Whenever you write an unsafe block, ask yourself if there is a better safe implementation 
    - Be aware of circular reference in the async Executor
        - Keep a model of structures referenced mutably by the scheduling/execution loop
    - Avoid hidden allocations on the send/receive networking path
    - Client and Server have some code duplication, logic might be replicated to both peers
    - Use dyn traits on the less hot paths instead of `match` expressions

## Simplicity is Key
- Keep changes minimal, always ask yourself before implementing anything: Is there a simpler alternative. Artifical Complexity is error-prone, simplicity is key to keep the code traceable.
- Do not create multiple layer of abstractions where one suffices
- Focus on the task and only on the task
    - If you think about implementing a feature, but there is no use case for it, don't implement it
- Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify. 

## Evluate before Implementing
- we are dealing with low level code, the failures are unforgiving. State your assumptions for changes clearly. 
- Adhere to the Simplicity paradigm from before
- If something is unclear, stop. Name what's confusing. Ask.

## Buidling and Running
```bash
cargo build 
cargo build --release
```

```bash
sudo ./v2_bench --journal-threads 4 --primary-thread-count 4 --initial-log-count 8 \
    --op-count $((500*1000)) --track-percentiles \
    --min-message-size 128 --max-message-size 128 --zipf-factor 0.0001 \
    --wal-flush-interval-us 0 --log-creation-interval-ms 500 --print-interval-ms 1000 \
    --max-log-push-interval-ms 2 --thread-placement unpinned --io-mode manual-poll --wal mock
```
