# Transfer protocol design review record

On 2026-11-03, an independent review accepted the design below for
implementation of the bounded one-transaction MVP. This is design acceptance,
not an assertion that the implementation, route, filesystem guarantees, or
security tests have passed.

- Reviewed document: `docs/transfer-protocol-design.md`
- Reviewed SHA-256: `1a70391b9a960f3b547053bdec37d0362bacf691213ddf25141a80bab4e9cf3a`
- Separate review thread: `01a19f94-e187-7736-860c-70b1e85d8026`
- Reviewed Vox source revision: `d44d9136fb4d5d1f8084dd7c6a57daf16ca4b710`

The original draft was rejected and revised for cross-process ownership,
authenticated manifest and journal binding, staging isolation, aggregate
resource limits, TLS and CONNECT handling, publication semantics and crash
recovery. The re-review accepted those requirements as fail-closed gates.

The reviewer identified one especially important implementation gate: at the
reviewed Vox revision, inbound lane request and credit limits derive from
peer-provided lane-open settings. A local builder limit by itself does not
establish protection against a malicious peer. Local enforcement and flood tests
must pass before a real transfer. Windows no-replace and durability behavior,
protected staging and sharing, the process memory ceiling, and the managed
CONNECT route also remain unproven until tested on the intended platforms.
Failure to establish a required protection must block the receiver rather than
silently weaken the design. Source deletion is outside the accepted milestone.
