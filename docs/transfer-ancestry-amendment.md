# Proposed amendment: distinguish sibling creation from ancestor control

Status: **design independently accepted; qualification mechanism not yet
accepted or enabled**. The existing transfer design remains authoritative
except for this narrow proposed qualification, which may be relied on only
after independent review of its concrete mechanism and passing its gates and
tests. The current publication path remains disabled. This document does not
approve a destination or authorize a listener, credentials, ACL changes, or
source deletion.

## Narrow proposed exception

The existing design excludes other-user write and delete access throughout the
trusted ancestry. Consider a single, explicitly approved local volume-root
directory for which the only permitted mutation right of an otherwise untrusted
principal is the right to create a new subdirectory; read and traverse rights
may also be present. Treat that mutation right as sibling-creation authority,
not by itself as evidence that the principal can delete, rename, replace,
reparse or modify an existing protected child. The exception must not apply to
the destination parent, staging parent, staging directory, journal, final
directory, or any other ancestor. Those remain subject to the original strict
write and delete exclusion. Generic or additional mutation rights do not
qualify as this narrow exception. New sibling names must never be selected as a
substitute for an already approved component.

This is a proposed permission analysis, not a conclusion that any particular
drive is safe. The operator-approved same-account non-interference assumption
remains limited to staging as previously specified. Other user accounts remain
untrusted; a malicious administrator or kernel remains outside the guarantee.

## Required qualification

An ordinary allow ACE marked `INHERIT_ONLY_ACE` does not control access to the
object carrying it, but may propagate to child objects. The root ACL diagnostic
may disregard such an ACE **for the root candidate only** after validating its
type, structure, SID and flags. This does not authorize ignoring it for any
child: each existing descendant needs its own strict ACL and identity checks,
and new private objects need restrictive descriptors at creation. A protected
child can still have unsafe access through an earlier open handle. See
[Microsoft's ACE header documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_ace_header)
and [inheritance description](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-azod/19165a4a-a18d-463f-8272-f758b484bf32).
The diagnostic is not a qualification decision and must not be used as a
publication permit.

Owner classification also requires review. The candidate filter currently
trusts only the approved user, LocalSystem and the built-in Administrators
group. A system-managed volume root may instead be owned by the Windows
TrustedInstaller service SID. The diagnostic must continue rejecting an owner
outside its explicit trusted set until the exact SID's authority and inclusion
in the approved OS trust boundary have been independently reviewed. A
display-name match, an ACL-only result, or the presence of a system service
account alone is not sufficient to trust it.

* Anchor the intended local filesystem and volume-root identity using trusted
  local approval, not a peer-supplied path or a drive letter alone. Reject
  unverified device aliases, remote paths, volume changes, reparse points and
  ambiguous path components. Open each existing component relative to its
  retained verified parent, and revalidate the named edges and identities.
* Establish trusted ownership and effective rights for relevant user and group
  principals, including generic-right mapping, deny and inherit-only ACEs,
  ownership and privileges. Fail closed on an unrecognized descriptor or an
  unprovable privilege boundary. A DACL-only allow-mask scan is not an effective
  access check and does not exclude backup, restore, take-ownership or other
  privileged bypass by a non-administrator account. Checking a single token with
  `AccessCheck` or `AuthzAccessCheck` does not establish the rights, privileges,
  group memberships or pre-existing handles of all other users; an auditable
  method to establish the complete threat boundary is still required.
* For every protected edge, exclude untrusted authority over the existing child
  and its parent that could delete, rename or replace the child, change its
  owner or DACL, or alter it into or through a reparse point. Check both child
  `DELETE` and parent `FILE_DELETE_CHILD`; neither a safe child DACL alone nor
  lack of delete on the parent alone is sufficient. Validate destination-name
  collision and replacement behavior on the qualified filesystem. The proposed
  root exception is only for creating a previously absent sibling.
* Account for handles opened before qualification: later ACL restrictions do
  not retroactively revoke rights on an existing handle. Establish an auditable
  safe origin for protected objects, or another separately reviewed way to
  exclude those handles. Exclusive fresh creation with a restrictive descriptor
  can help for a new stage; it does not by itself prove that an existing
  destination parent or ancestor had no earlier untrusted handles. If that
  cannot be established, fail closed. Retaining handles without delete sharing
  can help protect a live operation but does not prove safety after a crash.
* Create new staging and journal objects under qualified parents with explicit
  restrictive descriptors at creation. Hold the specified transaction lock,
  stage and destination-parent handles; verify exact contents, identities,
  hashes, reparse and link restrictions. The existing same-volume atomic
  no-replace, commit-intent, ambiguous-outcome, recovery and no-source-deletion
  requirements remain unchanged. Requalify after restart before reconciliation;
  do not infer success from a name or from an earlier live handle.

## Review and test conditions

Independent review must accept both this exception and the concrete means of
establishing the gates before implementation may rely on it. Synthetic tests
must cover the exact allowed root ACE and reject each dangerous permission,
generic mappings, deny and inheritance edge cases, untrusted owners and bypass
privileges. Exercise different real tokens/groups where feasible, pre-existing
handles, parent delete-child, child delete, rename and replacement races,
reparse points on every path component, changed directory edges and volume
identity, exclusive stage creation, crash/restart and local recovery. Test on
the intended NTFS configuration and document what each result does and does
not establish. Inability to prove a condition is a blocker, not permission to
assume that condition. A successful rename still does not prove power-loss
durability.
