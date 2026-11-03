# Vox bounded channel liveness investigation

The driver-side repair was published in Vox revision
`c5b99b276d12a0ee48078ef1307e0a4f36ca9768`, which Mover pins. It bounds
pending writer schemas separately, enforces inbound item credit and preserves
one ordered terminal message. The Mover deadlock regressions now run normally.
The tests below remain a broader verification plan: raw/proxy lanes need their
own corresponding limits, and this is not proof of a whole-process memory bound
or of a working managed-proxy route.

## Reproduction

With one initial item credit and a one-item mailbox, a sender transmits one
item and then closes its channel while the service handler first awaits a timer
or a blocking task. The item occupies the mailbox; the lane driver then awaits
space to enqueue the close. The same driver loop must poll the handler that
would consume the item. Neither advances. The blocking closure itself completes,
and a timer-only RPC without a channel completes. The two ignored Mover
regressions `incomplete_channel_closes_after_async_timer` and
`incomplete_channel_closes_after_blocking_gate` reproduce the issue using
in-memory mutually authenticated TLS, without a listener or filesystem I/O.

The relevant paths are Vox `driver.rs` `Driver::run`, `handle_channel`, and
`handle_schema`, and `vox-types` `ChannelMailboxSender`. `handle_schema` also
awaits the same bounded mailbox for a writer schema. The ordinary item enqueue
can similarly block the driver if a peer sends beyond credit. Thus changing
only close to an unbounded `force_send` is not a sufficient hostile-peer fix.

## Design and remaining limits

The lane driver must never await space in a mailbox whose consumer is a handler
polled by that driver. Use nonblocking enqueue, preserve FIFO order, and close
the affected connection or lane on a detected protocol/resource violation;
never silently discard accepted data. Specifically:

1. Count per-channel inbound item credit from the local advertised initial
   credit. Decrement before accepting an item and replenish only as credit is
   actually granted to the peer; handle early items before handler binding and
   synchronize accounting with grant transmission. A peer exceeding available
   credit is a protocol violation, not a reason to await the mailbox. A full
   item queue despite valid credit is an invariant failure and must fail closed.
2. Bound data, writer-schema metadata, and terminal messages separately while
   preserving their wire order. Reserve bounded terminal capacity even when all
   item credits are occupied. Track the first terminal transition atomically;
   duplicate close/reset, request termination and connection shutdown must not
   repeatedly append terminal entries or recreate retired channels. Preserve
   any queued items before a graceful close and deliver reset/closure as errors.
3. Do not treat writer schemas as item credit. Specify their legal ordering and
   update semantics, cap their count and decoded byte footprint, and reject or
   terminate on overflow without silently changing a valid update sequence. An
   implementation that overwrites a schema needed by an already queued item is
   not acceptable. This needs verification against the Vox schema specification.
4. Charge channels received before handler registration against the existing
   per-lane and per-connection lifetime budgets, bound all retained terminal
   and schema state, and reclaim it consistently on request/lane termination.
   Audit other awaited sends in the driver and biased selection under sustained
   input so they cannot recreate the same deadlock or indefinitely starve a
   handler. Do not increase the advertised item credit to hide the issue.

Bound total connection memory from the configured number of channel IDs,
per-channel item slots and maximum decoded item size, explicit schema and
terminal budgets, lane/request state, transport/frame queues, TLS buffers and
application buffers. Include allocation and decoding overhead; item and schema
limits alone are not a process-memory proof. Oversized frames must be rejected
before large allocation. Ensure a protocol-close path itself cannot block behind
the full queue. Runtime limits and teardown must be validated on every supported
transport, not inferred from the Mover test.

## Required tests

- One item plus close while the handler awaits a timer or blocking task; verify
  item then graceful EOF in order and prove both Mover regressions pass.
- The equivalent reset, request cancellation, lane failure and connection
  failure cases; verify correct errors, prompt completion and one terminal event.
- Full item queue plus writer schema, early item/close before handler binding,
  schema update ordering and duplicate/conflicting schema behavior.
- Raw peers that exceed item credit, flood duplicate terminals or schemas, open
  excessive channel IDs or lanes, and send oversized frames. Verify bounded
  memory/queue state, no orphaned state and prompt protocol/resource closure.
- Credit replenishment races, zero-credit close, concurrent local cancellation,
  receiver drop, registration/termination races and maximum-configuration tests.
- Sustained valid input, a stalled handler and a blocked transport writer, with
  deadlines, to exercise fairness and prove teardown wakes pending operations.
- Existing Vox core/stream/early-delivery suites plus the Mover regressions, and
  a real proxy/TLS route test separately before any operational transfer.

Mover reconnect and publication remain disabled independently of this repair.
