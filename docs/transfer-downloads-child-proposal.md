# Proposed one-shot Downloads destination amendment — NOT APPROVED

This proposal is for independent design and implementation review. It does not
qualify a path, authorize a live listener, or replace the existing gates. The
existing design remains controlling until an amendment is accepted. It neither
changes the Downloads ACL nor treats the additional ACL principals as trusted.

## Narrow scope and departure from the current design

For the approved storytelling transaction only, the final directory would be
the new, absent `storytelling-recovery` child of the user's existing Downloads
directory. The exact Downloads volume and file ID, final component, manifest,
file IDs, lengths, hashes and both certificate pins must be approved and bound
to the transaction. A protected working and journal root must be separately
qualified under the user's profile, outside ordinary Downloads activity and on
the same volume. No existing file or directory may be overwritten or merged.

The current design excludes untrusted write and delete rights over trusted
ancestry. This proposed exception concerns **Downloads itself only**, and only
for the qualified live operation described below. An ACL inspection on this
machine found two additional explicit Modify entries on Downloads. Their mask
`0x001301BF` includes DELETE on Downloads, add-file/add-subdirectory and write
attributes/extended attributes, but not `FILE_DELETE_CHILD`, WRITE_DAC or
WRITE_OWNER. One is `CodexSandboxUsers`; the other SID did not resolve. Group
membership and effective access for other tokens were not established. Raw ACL
bits alone do not establish effective access, absence of privileges, or absence
of previously opened handles; neither principal is presumed harmless.

If review and tests establish the controls below, allow this limited ancestry
exception despite those grants. Do not extend it to the profile, other
ancestors, protected working root, journal, lock, staging directory or files.
Unknown ACEs, owners, permissions, reparse behavior, token privileges, external
handles, or failure to prove the relevant rights and controls must fail closed.
Retained handles are a live-process control, not permanent protection of the
Downloads path after crash, exit or handle release.

## Qualification and live operation

1. Verify the volume is a supported, qualified NTFS volume and open and retain
   the profile and all relevant ancestors by checked handle-relative traversal.
   Pin each expected identity, reject reparse points and unsafe owners and
   effective rights, and verify the named edges from a locally approved root.
   A string path, a DACL scan, or the existing `CheckedDirectoryChain` alone is
   not a qualification: in particular, its current child opens include
   `FILE_SHARE_DELETE`, and its revalidation does not re-establish the root.
2. Open the actual Downloads directory relative to the retained profile handle
   without delete sharing and retain that handle from qualification through
   publication and receipt decision. Establish, on the target Windows/NTFS
   configuration, that a pre-existing delete-capable handle causes a sharing
   failure and that later competing rename/delete opens cannot succeed while
   this handle is held. If a required open conflicts, stop; do not close the
   guard to make a rename work. An attributes-only handle is not sufficient:
   the candidate must request access that participates in sharing checks, such
   as `FILE_LIST_DIRECTORY`, and omit `FILE_SHARE_DELETE`. Test actual granted
   access and sharing, not merely the requested flags. Audit and test whether a
   no-write-sharing guard is needed and workable; do not assume it covers all
   attribute, EA, named-stream or reparse writes.
3. Before any listener, create the separate private work root, journal and
   transaction lock with explicit restrictive descriptors **at creation**,
   rather than inherited Downloads permissions. Bind their volume/file IDs,
   approved Downloads identity and final name, manifest and TLS pins in the
   locked journal. Exclude other-user write, delete and replacement authority
   throughout the protected work ancestry. Keep the OS-backed lock and all
   qualified ancestry, destination-parent, stage and journal handles live.
4. Create a dedicated private staging directory and each manifest file with
   restrictive descriptors, exclusive/no-follow semantics and sharing modes
   preventing concurrent writes and deletes while held. Stream one approved
   file at a time under the existing quotas; verify its exact byte count and
   SHA-256. Reject extra entries, reparse points and hard links. Enumerate data
   streams completely and reject any unapproved named stream on every staged
   file, the stage directory, the dedicated work/journal directories and
   Downloads itself as destination parent; verify the final directory after
   rename. Existing unapproved streams on Downloads also fail closed. The
   approved files have only their expected unnamed data streams; transaction
   directories have no approved named data streams. Use a supported, complete
   NTFS enumeration method that distinguishes named `$DATA` streams from
   directory/index metadata and does not follow an untrusted replacement path.
   Unsupported, incomplete, truncated, inaccessible or ambiguous enumeration
   fails closed. Do not assume hashing the unnamed stream covers named streams.
   Immediately before commit, verify all file and directory identities, exact
   set, link counts, streams, hashes, current parent and named-edge identities,
   effective security and final-name absence. Recheck after publication. These
   checks do not replace proof that untrusted attribute, EA, stream or reparse
   mutation is excluded throughout the critical window; fail closed if it is
   possible or if the protection cannot be established.
5. Persist commit-intent with the pre-rename stage identity. On the qualified
   same volume, use a tested handle-relative atomic no-replace rename from the
   private stage to the retained Downloads handle. Hold the transaction lock,
   stage directory and qualified destination/ancestry handles throughout.
   Child file handles may be closed only in the existing narrowly approved
   same-account non-interference window when NTFS requires it. Keep other-user
   stream and content mutation excluded throughout that interval; test attempts
   to add or change named streams after verification and before rename. Retain
   the transaction lock, stage, journal, destination parent and every qualified
   ancestry handle, including I/O buffers and worker ownership, until pending
   rename or journal I/O settles or the one bounded transaction is quarantined.
   A timeout, cancellation or abort signal does not prove the operation stopped
   or permit a concurrent retry. Quarantine retains all such resources until
   confirmed completion or process termination. After confirmed termination,
   reacquire the lock and reconcile the outcome before any further action.
   A collision or failed check must not overwrite a destination.
6. Record publication only after checking that the final directory is the
   original stage identity and that the exact approved file set, streams and
   hashes remain intact. A successful local rename can be reported only as
   durability unconfirmed unless the separate durability gates are met. Never delete the
   cloud sources. TLS still requires normal certificate validation and exact
   client/server pins; tailnet membership is not transaction authentication.

The allowed same-account assumption is the operator's existing non-interference
approval for the dedicated stage's brief final publish window; it is not a new
assumption about other Windows accounts. Trusted OS, kernel and administrator
behavior remains outside the hostile-local-user guarantee. Handle-sharing and
ACL claims must be tested against realistic effective tokens and privileges,
including identities able to bypass normal discretionary checks; do not
silently expand the trusted set or treat a username/group name as proof.

## Crash and recovery

The journal/lock location is outside Downloads so moving Downloads cannot
silently move the only transaction record. On restart, acquire the transaction
lock, reopen the locally approved root and the exact named ancestry and
Downloads edge without following reparse points, re-establish all guards and
compare persisted volume/file identities. If Downloads is missing, moved,
replaced, inaccessible, or conflicts with a pre-existing incompatible handle,
preserve the journal and any stage/final data and require local inspection.
Never follow an attacker-supplied replacement path, look up a new identity by
name and treat it as the original, issue a success receipt, reopen network
access, or delete source data in that state.

For a possible crash after rename but before its record, compare the final
directory volume and file ID to the stage ID in commit-intent, then verify the
exact regular-file set, identities, link counts, reparse restrictions, all
relevant data streams, lengths and hashes before a durability-unconfirmed
receipt is considered. A mismatch, failed journal sync, still-running I/O or
inconclusive state remains uncertain.
Loss or movement of the folder after the live handles are released is not
prevented by this proposal and is not evidence of durable publication.

## Required evidence before use

Independent review must accept the exception and the actual qualification
implementation. Synthetic, temporary NTFS tests must cover: explicit ACL at
creation and denied effective access for distinct constrained principals;
pre-opened DELETE, write and ACL-capable handles; sharing conflicts; rename of
Downloads and its ancestors before/during/after guard acquisition; attempts to
change attributes, EAs and reparse data on Downloads while its proposed live
handle is held; identity swaps; hard links; existing final names; write/rename
cancellation and pending I/O; process exit at each journal/rename boundary; and
local recovery after Downloads is moved or replaced. Test all applicable
constrained-token combinations and revalidate directory type, volume/file ID,
named parent edge, security and stream state after attempted mutation. A failed
attack or compatible handle for one token is not proof for other tokens; if
the required protection is unproven, fail closed.

Add synthetic alternate-stream tests for staged files and transaction-relevant
directories, including zero-length and nonempty streams, enumeration failures,
and injection attempts after child verification while child file handles are
closed. Test final-directory stream verification after rename and after a
simulated crash/reopen; unexpected or unenumerable streams must prevent a
success receipt and preserve all sources and evidence. Exercise delayed
completion and cancellation in both rename and journal sync, confirming that
stage, journal, lock, destination and ancestry handles remain held or boundedly
quarantined, and that no retry begins until completion or process termination
followed by identity/content/stream reconciliation.
Include the expected case where the required guard cannot be obtained. Tests must
not modify the actual Downloads ACL or other existing user data. Simulated
restarts are not power-loss durability proof. No operational constructor,
listener, credentials or publication is enabled by this proposal.
