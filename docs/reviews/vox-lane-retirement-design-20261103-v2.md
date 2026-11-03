# Lane retirement and write ownership proposal

Status: design for review; not implemented. The local lane-generation work
rejects a queued batch if it observes the old lane closed before worker entry.
`lane_close_between_worker_check_and_write_is_not_serialized` demonstrates
that this check is not a close/write barrier.

## Scope and identities

Each accepted lane owns one non-reusable lifetime object. Senders, declaration
gates, requests and admitted batches retain that exact object; numeric lane IDs
are wire addresses and are not lifetime capabilities. A replacement cannot
reuse the same numeric wire ID while an older lifetime has an unsettled write.
If retirement cannot be settled within the deadline, retire the connection and
retain the old generation's ownership until teardown is confirmed or the
process terminates. A bounded one-connection failure budget must prevent
unbounded quarantined workers, frames or lane generations.
If abort is unsupported or the writer never settles, reject further work and
fail callers, quarantine at most the bounded connection and its existing
ownership, and do not start a replacement connection or reuse its lane IDs as
a workaround. Explicitly report teardown as incomplete until writer termination
is observed or the process ends.

The lifetime has a synchronized state: `Open`, `Retiring` or `Retired`, plus
ownership of at most one currently executing outbound batch. The outbound
worker is already serial, but the ownership must remain explicit: transport
clones and spawned writer tasks can survive dropping a single future.

## Admission, write and retirement

* A sender reserves queue capacity, then under the admission synchronization
  validates the exact lane generation and `Open` state. Enqueue and transfer of
  the response/channel reservation happen without an intervening await. Work
  rejected before enqueue resolves as definitely not queued. Forced-stop
  overlap remains uncertain unless its commit handshake is strengthened.
  The final `Open` validation and enqueue must linearize against `Open` to
  `Retiring` under the same lock, or under a separately reviewed commit
  handshake with an explicit lock order. Two independent checks leave an
  enqueue-after-retirement gap. Acquiring queue capacity may happen before the
  lock only if the lifetime is revalidated at that commit point.
* Before beginning a batch, the worker acquires a lifetime-bound write lease
  only if that exact lane is `Open`. A queued old-generation batch that cannot
  obtain a lease fails its result and releases its owned resources without
  writing. The lease must remain owned until schema and payload writes have
  settled; it cannot be released just because a timeout cancelled a wrapper
  future while a spawned writer may still be active.
* Retirement linearizes by changing the exact lifetime from `Open` to
  `Retiring`, rejecting future leases and admissions and waking pending
  channel and lane waiters. A batch that already has a write lease is
  **in flight**, not retroactively unsent. The retirement operation waits for
  that lease to settle before declaring the lifetime fully retired or allowing
  wire-ID reuse. It must use one absolute deadline shared with any queue fence,
  protocol close, transport flush and teardown; a fresh timeout at each step is
  not equivalent.
  Write-lease acquisition and the `Retiring` transition must be mutually
  exclusive under that same state synchronization; an independent atomic
  check before acquisition does not establish this ordering.
* Do not hold a synchronous mutex across an await or transport call. State
  transitions and lease acquisition use short critical sections; waiting uses
  a persistent notification or async synchronization that cannot lose wakeups.
  Ownership of the actual transport writer must be tracked through completion.

The existing synchronous `remove_connection_with_reason` and early
`close_all_connections` calls cannot by themselves implement this protocol.
Audit every local close, dropped-handle, rejected-open, received `LaneClose`,
protocol-error, EOF and resource-exhaustion path. Refactor state retirement and
numeric-ID reuse together; do not add another unsynchronized check and call it
a barrier. Driver/control messages and failure notices must carry the original
lifetime and request identity rather than looking up the current numeric ID.

## Protocol and failure distinctions

For a local graceful lane close, stop admission, resolve or fence work already
admitted to that lane, then order `LaneClose` after the eligible writes using a
private control path. The local close result means only the stated local drain
and write outcome; it is not a peer receipt. Preserve the spec's prohibition on
sending lane traffic after `LaneClose`.

For a received `LaneClose`, stop new lane traffic immediately. If a write was
already admitted or started and cannot be proven stopped before it crosses the
wire, the outcome is uncertain: terminate or quarantine the connection rather
than assert that no bytes were sent. Local close initiation, peer EOF,
close-notify, reset/truncation and unknown partitions are distinct outcomes.

On deadline expiry, abort all relevant transport owners and fail unresolved
results. An abort request alone, especially the default no-op `abort()`, does
not prove teardown. Await actual writer completion where the transport supports
it; otherwise report incomplete teardown and prevent reuse. A late success from
an old write cannot authorize a new lane or restore a failed request. Dropped
queue entries and pending permits must resolve exactly once.

The current gate and admission-stop fallbacks catch failed watch notifications
and retry only best-effort. They do not prove that already parked waiters wake
if notification repeatedly fails. Treat that case as a liveness blocker until
an independently guaranteed teardown/wakeup path is implemented and exercised;
an atomic failed bit alone is not a wakeup.

The explicit connection shutdown must interrupt a stalled handler as well as
bound admission, queue drain, protocol close and transport close. It must not
start its deadline only after the receive loop eventually observes the signal.
The existing stalled-handler diagnostic remains a required regression.

## Required verification

Use deterministic barriers before lease acquisition, after lease acquisition
but before write, during partial writes, and during lease release. Cover local
and remote close, simultaneous close/send, queued and prepared producers,
held lane and conduit clones, reused numeric IDs, failed/unsupported abort,
worker panic, deadline expiry and late completion. Verify all sender results
and waiters, no old-generation mutation, and no new generation admission while
old ownership is unsettled. Exercise real loopback TLS and each supported
transport separately; local flush or close-notify is not proof of peer receipt.
Also exercise injected notification failures, poison while a waiter is parked,
nested/reentrant encoding capture, cancellation, weak-gate reclamation and
retained sender/gate references across multiple lane generations.

This proposal does not complete response reservation, gate lifetime cleanup or
connection shutdown, and does not authorize live transfer.
