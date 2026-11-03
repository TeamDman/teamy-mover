# Vox shutdown with retained service lanes

Status: investigation and proposed design only. This is not an implementation,
an accepted design, or permission to enable receipt replay or an operational
listener. It must be independently reviewed along with the existing transfer
design and the concrete implementation.

## Observations

With Mover's pinned Vox revision `c5b99b276d12a0ee48078ef1307e0a4f36ca9768`,
the ignored `peer_shutdown_is_observed_while_service_lane_is_retained` test
uses an in-memory stream and no TLS, filesystem or listener. An explicit client
`shutdown()` did not resolve the server's `closed()` within two seconds while
the service client remained held. After that client was dropped, the same
server signal resolved. The test is deliberately ignored because it expresses
the desired behavior and currently fails.

An independent in-memory bridge test severs the transport instead. Both peers
observe closure with the service client retained. A synthetic Windows receipt
test also severs an in-memory TLS transport after reading the journal and before
returning bytes; the receipt is withheld after the receiver observes closure.
These tests do not prove detection of a silent or partitioned peer, immediate
revocation, actual TCP reset behavior, or safety with a live permit.

The source suggests a lifetime problem: ordinary connection-loop shutdown closes
lane state, while the core's conduit sender is explicitly removed and aborted
only on resource exhaustion. The outbound worker and individual prepared
batches can retain sender references; the stream writer shuts down after its
queue closes. This is a plausible explanation, not proof that it is the sole
cause. The `closed()` signal represents observed control-lane closure, not a
synchronous indication that a remote application has stopped.

## Design constraints for a candidate fix

Do not simply abort the writer on every normal shutdown: queued or in-flight
frames may be discarded, and a TLS stream may miss orderly closure. The Vox
spec requires explicit graceful shutdown; dropping ordinary client handles must
not be its sole trigger. A candidate should:

1. Atomically stop admission of new outbound work when shutdown begins, with
   a documented outcome for calls racing shutdown. It must account for work
   already prepared but not yet queued and release any blocked channel gates.
2. Drain accepted outbound batches in FIFO order and complete their send
   results consistently. If the transport supports orderly close, request it
   without waiting for application-held lane or caller references to disappear.
3. Put an explicit bounded deadline on drain and close. On expiry or transport
   failure, cancel outstanding work, close the transport and return failures;
   never claim unsent bytes were delivered. Define how the current synchronous
   shutdown request exposes completion and how other transports behave.
4. Ensure closure notification follows the actual local connection lifecycle,
   including shutdown, observed EOF and failures, without requiring all public
   handles to be dropped. Do not promise instantaneous awareness of a remote
   process or of a network partition.
5. Preserve framing, schema/channel ordering, bounded queues, explicit handle
   lifetime, and compatible native and WebAssembly behavior. Review any new
   conduit close API for transports whose writer cannot be forcibly interrupted.

Before live replay, independently qualify and retain final-directory, file,
ancestry and transaction handles; bind the approved replay window to the
authenticated connection; and review cancellation, reconnection and the race
between observed closure and reply delivery. A closed-signal check alone is not
a proof of reachability or qualified filesystem state.

## Verification required

Turn the ignored retained-lane reproducer into a passing regression. Add tests
for queued frames and sends racing shutdown, a blocked writer and deadline,
failed or cancelled sends, EOF/reset while lanes and callers are held, peer
half-close, orderly TLS close and truncation, and shutdown with no pending work.
Exercise stream, in-memory and applicable other supported transports, plus the
existing Vox connection, channel, resource-limit and lifecycle suites. The
synthetic Mover tests are not proof of TCP/TLS behavior or power-loss durability.
