# Design draft: authenticated transfer to an approved destination

Status: **draft for independent review; not implemented or approved for execution**.
This document does not change the planner's behavior or authorize a move, a
listener, credential creation, firewall changes, or deletion. The repository's
executor restriction remains in force until a separately reviewed design is
accepted. Real manifests, receipts, credentials, and absolute paths are private
operational data and do not belong in this repository.

## Scope and boundaries

The first milestone copies a finite, approved set of regular files from a cloud
sender to a new desktop destination directory over an authenticated TLS channel.
The desktop receiver stages and verifies every file before publishing the set.
It does not delete or rename a source, merge with an existing destination, run
commands from a manifest, move arbitrary local trees, or implement the existing
plan format's local move actions. Source deletion and a general local executor
remain separate, later designs, even if a transfer commit is verified.

The original Onboarder checkout and its server demo were not present in the
inspected workspace. Its behavior and suitability have not been checked. Mover
currently has a planning surface only. The reviewed Vox examples provide RPC and
stream building blocks, not an authenticated file-transfer application.

## Approval and transaction identity

Before either endpoint starts, a human or an explicitly authorized workflow
approves one versioned manifest and the receiver's exact destination root and
new final directory name. Approval is an external authorization decision, not
an assertion inside the manifest, a dry-run result, or a `policy_reference`.
Both endpoints receive the same manifest and compute its digest independently.
Before listening or connecting, the operator provisions protected local
configuration on each endpoint containing the approved manifest digest,
transaction ID, expiry, exact destination parent and final name, exact approved
proxy and endpoint address/port, server and client leaf SHA-256 pins, local trust
anchors, and stricter local quotas if any. The receiver verifies its local parent
and stage identities; the sender binds the manifest IDs to its own source
handles. Neither a network request nor a field supplied by the other peer can
change these approvals. Provisioning and renewed client certificates require a
local authorized operator; never silently treat a replacement certificate as
the old identity. The original pin is journaled and any explicit renewal is
recorded as a separately authorized binding to that same transaction.

Version 1 uses RFC 8785 canonical JSON as UTF-8, with no BOM or trailing bytes;
both endpoints parse strictly, recanonicalize, compare exact canonical bytes and
hash them with SHA-256. Reject duplicate keys before canonicalization, unknown
fields, unsupported versions, invalid UTF-8 and non-integer numbers. The only
top-level fields are `version` (integer 1), `transaction_id` (32 lowercase hex
characters generated from 128 random bits), `expires_unix` (integer UTC seconds,
0 through 2^53-1), `file_count`, `aggregate_bytes`, and `files`. `files` is an
ordered array of exactly `file_count` objects containing only `id` (unique
ASCII identifier matching `[a-z0-9_-]{1,32}`), `name`, `size`, and `sha256`
(64 lowercase hex digits). Each size is an integer 0 through 67,108,864; the
checked sum must equal `aggregate_bytes`, at most 134,217,728. Count is 1..16.
The independently provisioned endpoint, destination and pins are part of the
operator's approval record, not client-controlled manifest fields.

Each `name` and the separately approved final directory name are single ASCII
components of 1..128 bytes matching `[A-Za-z0-9][A-Za-z0-9._-]*`, with no
trailing dot, Windows reserved device basename (even with an extension), or
case-insensitive collision. This deliberately excludes Unicode normalization,
separators, alternate data streams and traversal for version 1. Reject hard
links where link count is not exactly one, unsupported filesystems, or any
source/destination path component that is a symlink or reparse point; use
trusted, identity-checked handles and no-follow operations rather than string
prefix checks. Source paths are held separately by the sender and never sent as
destination paths.

Bind every approved file ID locally to an opened regular-file handle, retaining
and verifying volume/file identity, link count and size before and after the
read. Deny concurrent writes where the operating system supports enforceable
sharing restrictions, and require an immutable snapshot or paused writers where
it does not. Hash the bytes actually sent and compare with the approved digest;
any changed identity, metadata or content fails the transaction. Open handles
and hashing alone do not prove an immutable snapshot against all writers.

## Channel and authentication

The cloud uses the platform's supported HTTP CONNECT proxy to reach the exact
desktop tailnet address and port. A proxy denial is a terminal diagnostic; do
not retry through a direct connection, change proxy policy, or route through a
different service to bypass it. The prior proxy HTTP 503 happened before TLS;
it is not proof that a Tailscale policy rule alone will fix the route. Test the
actual permitted path after any authorized policy change.
Connect only to the configured proxy and request only the configured target.
Bound the CONNECT response header to 8 KiB and 10 seconds, reject redirects,
malformed or non-2xx responses, and preserve any bytes already buffered by the
HTTP upgrade when handing the stream to TLS. Proxy credentials, if present,
must not appear in logs or arguments. TLS authenticates endpoints through the
tunnel; the desktop's observed socket source may be the proxy and must not be
treated as proof of the cloud client's identity.

Inside CONNECT, run TLS 1.2 or newer with mutual authentication. Use standard
TLS implementations and a locally scoped trust root. Verify the server's
certificate chain, validity, server-auth usage and IP/DNS subject alternative
name, and additionally compare the approved leaf certificate's SHA-256 pin.
The receiver verifies the client certificate chain, validity and client-auth
usage and additionally pins its approved leaf. Never use an insecure verifier or
turn off certificate or hostname validation. A public certificate/pin can be
exchanged through the coordinating thread; each private key is generated and
kept on its own endpoint, protected from other users, excluded from arguments,
logs and source control, and removed after its bounded lifetime. A private CA
key, if used, has the same endpoint-specific protections. No bearer
token is needed. Check the intended rustls verifier configuration against real
cross-platform tests, especially for a private CA and certificate pinning.
Disable TLS early data and reject application data before the full handshake.
Compare each authenticated leaf to the locally configured transaction pin
before creating the Vox connection. A pin supplements normal chain, validity,
SAN and EKU verification; it never replaces them. Crash-time cleanup is an
operator-recoverable obligation, not a promise of guaranteed key erasure.

The client certificate is a capability for exactly one manifest and
transaction, not a general login. Every `begin`, upload, commit, and status
operation must match the locally approved transaction and manifest digest.
The receiver binds only the approved tailnet interface and port and permits
one active connection and transaction across reconnects. It stops after the
bounded reconciliation window. It rejects other identities before accepting
application requests. A local firewall exception, if demonstrably
needed and separately authorized, must be scoped to this endpoint and permitted
tailnet source and removed on exit. Tailnet membership alone is not application
authentication. The implementation must account for peer identity as seen
through the proxy before relying on a source-IP firewall rule.

## First-milestone resource limits

These are hard upper bounds, not negotiated client preferences; approved local
configuration may only reduce them. One receiver process owns one transaction,
at most one accepted socket including unauthenticated handshakes, one Vox lane,
one active RPC/upload and one upload channel at a time. Reject or close on
additional sockets, lanes, handshakes, channels, or requests, including repeated
control-message floods. Do not rely on the default lane concurrency of 64.
If the selected Vox APIs cannot enforce those limits against malicious peers,
the implementation is blocked until the necessary transport controls exist.

Limit canonical manifest bytes to 64 KiB, files to 16, individual files to
64 MiB, aggregate file data to 128 MiB, a chunk to 16 KiB, and any serialized
incoming or outgoing Vox frame to 64 KiB including encoding overhead. Both
endpoints set their receive-frame limit, and senders reject oversized encoded
frames. The checked Vox implementation has 128-entry send and receive queues:
at 64 KiB per entry these two queues alone can account for 16 MiB, excluding
allocator overhead, in-flight frames, driver/lane queues, channel credits,
TLS records and serialization copies. Account for all those allocations;
bound application/channel queues and use a 256 MiB OS-enforced per-process
memory ceiling on each endpoint, or fail closed where it cannot be enforced.
Measure resident and committed memory under adversarial floods; a queue entry
limit by itself is not a proof of the whole-process bound.

Allow at most 128 MiB of staged file content plus a separately capped 1 MiB of
journal/receipt metadata; check the quota before writes and fail on disk-full.
Use a 10-second proxy/header and TLS-handshake deadline, a 30-second read/write
idle timeout, a 15-minute absolute receiver lifetime including the receipt
window, and a maximum 60-second authenticated reconciliation window. Expiry
and cancellation apply during handshake, upload and reconciliation. Enforce
deadlines against stalled and malicious peers, not only cooperative requests.

## Ownership, journal and local threat model

The trusted desktop OS, administrator, approved operator and receiver process
are in scope as authorities; arbitrary remote peers and other local users are
untrusted. A malicious administrator or kernel is outside this guarantee. The
operator has authorized trusting other processes running under their own Windows
account not to interfere with the staging directory, provided that it is
dedicated and outside ordinary working areas. This threat model does not protect
against a hostile process running as that same account. Other-user write and
delete access to the stage and trusted ancestry must remain excluded through
verification and publication. The amendment requires independent review before
executor implementation.

Use a private application staging root, outside normal working directories,
on the same volume as the destination; fail closed if that location cannot be
established. Create its per-transaction directory and the journal with explicit
restrictive security descriptors, not inherited broad permissions, and check
the entire trusted ancestry, identities, filesystem and descriptors. Do not
share a stage between transactions. Keep the transaction lock and directory
handles throughout verification and publication, and create each approved file
exclusively. Immediately before publication, enumerate and reject all unexpected
entries, check identities, reject reparse points and hard links, flush and hash
each approved file, and confirm the journal binding and absent final name.

NTFS may refuse to rename a directory while children are open. If so, after
verification the receiver may close its child handles just before the rename,
relying on the stated same-account non-interference assumption for that window.
Retain the transaction lock, stage directory handle and verified destination-
parent handle across verification and publication. Use an atomic, same-volume,
handle-relative Windows no-replace rename to the retained destination-parent
handle on a filesystem qualified by the required tests. Test collisions, handle
sharing, reparse and hard-link rejection, identity checks, and cancellation or
process failure at every transition using synthetic files. An ambiguous rename
or interrupted journal update must preserve the objects for inspection and not
produce a success receipt or delete a source. No claim of crash durability follows from a
successful rename; report the explicitly unconfirmed outcome unless the
required filesystem guarantees are independently established.

Before listening, atomically acquire and hold a cross-process exclusive lock on
the transaction record using an OS-backed lock or a pre-existing trusted lock
file opened without sharing, under an identity-checked protected parent. A
same-process mutex alone is insufficient. Only one sender/receiver owner may
advance a transaction. A process crash releases the OS lock; the next owner
must acquire it and perform local recovery, not assume the previous owner did
nothing. Existing conflicting, malformed, expired or ambiguous records fail
closed. An intentional reconciliation window must be explicitly authorized and
bound to the original record and client pin.

Create the journal and unique staging directory with restrictive security
descriptors at creation, under trusted parent directory handles; never create
them broadly accessible and tighten permissions later. Walk and open every
component without following symlinks/reparse points, verify volume and file
identities, and retain the necessary handles. The journal binds the transaction
ID, manifest digest and canonical manifest, original client and server leaf
pins, expiry, destination parent volume/file identity, final component, staging
directory volume/file identity, created file identities, state, and monotonically
increasing journal sequence. Protect the record from unauthorized replacement,
validate its schema and sequence, and write each transition with a checksummed,
flushed same-directory replacement or an equivalently tested atomic journal.
Do not store private keys in it. Cross-process locking, protected configuration
and journal identity are requirements, not guarantees derived from a filename.

Keep staging inaccessible to untrusted other-user writers through verification
and publication, including after closing child handles. Create files exclusively
with no-follow semantics and sharing modes that exclude concurrent writes and
deletes while held; recheck identities and hashes and verify the stage contains
exactly the approved file set. Immediately before publication revalidate stage
and destination-parent identities, reparse status, lock ownership and final-name
absence. Child handles may be released only as described in the same-account
boundary above; retain the stage directory, destination-parent and lock handles.
Fail closed if the remaining protections or atomic no-replace rename cannot be
established on the qualified filesystem.

## Wire protocol and receiver state

Proposed initial wire format: a versioned Vox service over the mutually
authenticated TLS stream, with one authenticated transaction and opaque fixed
file IDs rather than client-provided paths. A small `begin` message identifies
the transaction and manifest digest; an `upload` operation sends an approved
file ID and bounded chunks through a Vox channel; `commit` requests publication;
and `status` returns the transaction state or existing receipt. Operations
cannot change the manifest, destination, caps, or identity. Reject unknown
operations, oversized control frames, concurrent uploads and chunks exceeding
the configured per-chunk limit. Track the exact manifest byte length and
incremental SHA-256 for each file. Apply backpressure and reject early EOF,
extra bytes, wrong length or digest, missing items, duplicates with conflicting
content, and aggregate overflow. Do not log file bodies, private paths,
credentials or private keys. The HTTP CONNECT handshake is only the outer
proxy tunnel; apply strict bounded response parsing and do not forward
application payload until the tunnel and TLS authentication succeed.

The ordered journal states are `approved`, `receiving`, `verified`,
`commit-intent`, `published`, `receipt-recorded`, and `aborted`. Each state
transition is persisted before an operation that depends on it; partial files
and file completion are also recorded and identity-bound. All files are created
exclusively in the same-filesystem stage, streamed, flushed through the file
handles, rehashed and checked before `verified`. Flush and persist the verified
manifest, identities and `commit-intent` before attempting publication. The
commit-intent must include the pre-rename stage volume and file ID, bound to the
approved manifest and destination-parent identity.

Publication is the point of no return: atomically rename the complete stage to
the absent final name using a tested platform-specific **no-replace** operation;
never merge or replace an existing destination. On Windows the candidate is a
same-volume directory rename using a no-replace Windows API, but the exact API,
open-handle sharing flags, filesystem and crash guarantees must be demonstrated
on the supported NTFS configuration before use. `std::fs::rename` alone is not
a portable no-overwrite guarantee. No fallback to per-file copies is allowed.
Persist `published` with the resulting directory identity, then persist the
receipt and `receipt-recorded`; flush file, journal and directory metadata in
the tested order. Do not assume a directory metadata flush is supported or
durable on Windows merely because a call succeeds.

If atomic no-replace cannot be demonstrated, fail before publication. If the
rename is definitely known to have succeeded but directory/journal durability
is not confirmed, report `published-durability-unconfirmed`, preserve the final
directory and journal, and require local verification/reconciliation; never
report durable commit. An ambiguous rename outcome is not known success: preserve
the stage, final object and journal as found and issue no success receipt until
local identity and content reconciliation establishes what happened.
Cancellation before publication reports unpublished and preserves or safely
removes only identity-checked stage data. Cancellation or failure after the
rename must report published or publication-uncertain, never "nothing
published"; it must not delete the destination. A crash between rename and
journal update is ambiguous until recovery compares the final directory's volume
and file ID with the pre-rename stage identity in persisted commit-intent, and
revalidates the exact approved set, regular-file identities, link counts,
reparse restrictions and every file hash. A mismatch or inconclusive check must
remain ambiguous and must not produce a success receipt.

A receipt is deterministic canonical data containing protocol version,
transaction ID, approved manifest digest, outcome, and verified ordered file
IDs, sizes and hashes; it has no variable timestamp. Only call its outcome
`durable` after the required filesystem ordering is established and the receipt
is persisted. For definitely successful or successfully reconciled publication
without proven crash durability, use `published-durability-unconfirmed`; an
ambiguous outcome gets no success receipt. Return the
persisted same bytes only on the authenticated channel. This is evidence of the
receiver's observed state, not proof of a backup or permission to delete a
source.

## Retry, idempotency and recovery

Retries are scoped to the same transaction ID, manifest digest, authenticated
client and absolute expiry; they never create a second destination or widen
authorization. The first milestone permits a failed connection to restart a
file from byte zero, not byte-range resume. A completed, staged file can be
recognized only after its stored size and hash are reverified. Duplicate file
IDs with different bytes or a different manifest fail closed. Reconnects are
allowed sequentially within the one transaction; one active connection does
not imply one connection for the entire transaction. Remove or quarantine an
incomplete file only after identity checks and restart it from byte zero.

After commit, the receiver allows a short, bounded authenticated reconciliation
window: a status request for the same transaction and manifest returns the same
persisted receipt bytes and exact durability outcome, without another
publication. This handles a lost final response.
After the window it closes the listener and removes its ephemeral credentials.
There is no unauthenticated status endpoint. If the process or machine crashes,
the receiver does not automatically reopen network access. A local recovery
command inspects the persisted transaction record and staging/final directory,
then either matches the final volume and file ID against the pre-rename stage
identity in commit-intent and rechecks the exact approved set, regular-file
identities, link counts, reparse restrictions and hashes to reconstruct the
same deterministic receipt,
or reports an incomplete/ambiguous commit for an authorized operator. It must
retain an unconfirmed-durability outcome where crash durability was not proven.
Recovery must never overwrite an existing destination or infer success solely
from its existence. If authorized, a later bounded receiver may serve the same
verified receipt using a freshly provisioned client certificate only after an
explicitly approved new pin is durably bound to this transaction's record;
that is a new access window, not a new commit or an arbitrary new identity.

Cleanup removes only files and directories recorded as created by this
transaction, after checking their identity and containment. Never recursively
delete a computed or unverified path. Abandoned partial data and ambiguous
recovery states are preserved for inspection unless a separately authorized,
identity-checked cleanup is safe. Cleanup of keys and any rule must also run on
error, timeout and cancellation; process termination or machine failure needs a
startup/operator recovery path and cannot be guaranteed by an in-process
`finally` alone. Keep a non-secret audit record of outcome and remaining cleanup.

## Rust implementation path for review

Once this design is independently reviewed and accepted, add a separately
reviewed `transfer send` and `transfer receive` command hierarchy following the
repository's one-subcommand-per-module rule. This is an explicitly scoped new
copy capability, not an implementation of plan execution. Use `tokio` for
bounded asynchronous I/O and the Teamy Vox/Facet/Phon registry packages for the
service and streaming channel. On the sender, use `hyper`/`hyper-util` to make
the proxy CONNECT request and obtain its upgraded byte stream; wrap that tunnel
with `tokio-rustls`/`rustls` as a TLS client. On the receiver, accept only the
approved TCP endpoint and wrap accepted sockets with `tokio-rustls` as a TLS
server. Split each authenticated stream and feed it to Vox `StreamLink::new`.
Use `sha2` for SHA-256 and a reviewed canonical JSON implementation. These are
proposed registry crates, not existing Mover dependencies: choose compatible
pinned versions and features during implementation, and verify CONNECT upgrade,
IP SAN, mutual authentication and pinning behavior in integration tests. Use
standard platform APIs for protected credentials and atomic no-replace publication.

Vox's `rx_streaming` example illustrates a client-to-server channel, but a real
CONNECT tunnel and authenticated TLS stream must be supplied. The generic
`StreamLink` API makes this plausible, not yet proven. Its default 16 MiB
incoming frame limit is not a total transfer quota; use the concrete lower
limits above and prove aggregate limits under adversarial load. Do not assume
Vox/Iroh QUIC or relay traffic works through this cloud HTTP CONNECT proxy;
this proposal does not use Iroh.

## Review and test gates

Independent review should cover the trust and approval boundary, proxy behavior,
certificate validation and lifecycle, platform filesystem operations, receipt
semantics, interrupted commit recovery, and safe cleanup. Before real files or
a live listener, test with synthetic fixtures: wrong/expired client and server
certificates, wrong pin or SAN/EKU, early-data rejection, proxy 503, redirects,
malformed CONNECT responses and buffered upgrade bytes; malformed and oversized
frames/manifests; lane, handshake, channel and request floods with measured
process and queue bounds; hash/size mismatches; traversal, Windows filename
aliases, hard links, all-component reparse points and concurrent stage mutation;
source changes; pre-existing destinations and competing receiver processes;
connection loss, cancellation and crashes at every journal, rename and flush
boundary; duplicate requests, expiry, lost receipts, replay, recovery, cleanup
failure and no source deletion. Include actual supported Windows filesystem,
power-loss/durability and memory-ceiling tests. Source
deletion, if ever proposed later, needs its own explicit authorization, immutable
source identity and content recheck immediately before deletion, a durable
authenticated commit receipt, safe failure behavior, and separate review; the
first milestone never performs it.
