# Windows staging probe results

These are synthetic observations from 2026-11-03, not a supported-platform
guarantee or approval to enable transfer. The probes operate only on temporary
test data. Both the workspace drive and the system drive containing Downloads
reported NTFS. The native tests were repeated in system temporary storage on
the Downloads volume; no Downloads destination or real user file was touched.

The `windows_journal_lock` tests verified that an existing regular file opened
with zero share mode excludes a second process while the handle is held,
releases when dropped, and rejects a mismatched file identity. A synthetic
hard-linked file was rejected when the test was run outside the sandbox; the
sandbox itself denied creation of that test hard link. A final-component
symbolic link was also rejected in a synthetic test outside the sandbox. This
does not establish safe handling of reparse points in ancestor components.
This primitive **does not**
verify parent traversal, parent identity, ACLs, file creation protection, or a
durable journal. It is not wired into a receiver.

The ignored `windows_handle_rename_probe` tests produced these observations:

- `SetFileInformationByHandle(FileRenameInfo)` with a relative name and a
  directory handle returned `ERROR_INVALID_PARAMETER` for an absent destination
  on the workspace drive. That is one observed failure, not proof that all such
  configurations or Windows versions are unsupported.
- `NtSetInformationFile(FileRenameInformation)` moved a staged directory to
  an absent name relative to the parent handle and returned
  `STATUS_OBJECT_NAME_COLLISION` when the name already existed. Both source and
  existing destination contents were checked. This passed on both tested NTFS
  volumes without staged child file handles held open.
- A staged child file opened with zero sharing rejected a competing write open,
  but an exclusive directory handle did not prevent creating a new child. With
  the staged child file held open, native directory rename returned
  `STATUS_ACCESS_DENIED` for all six tested directory/file sharing combinations,
  including full delete sharing. Some combinations also permitted a competing
  DELETE-access open on the child. The tests deliberately report the matrix;
  they do not turn those observations into a security guarantee.

The conflict matters because the reviewed design requires staged content to
remain protected against an untrusted same-user process through verification
and publication. These probes do not show that merely holding the directory and
file handles meets that requirement while permitting rename. Closing handles
and hoping no concurrent mutation occurs would violate the design. A separately
reviewed isolation approach, such as a suitable restricted identity and ACL,
or another demonstrably safe Windows mechanism is needed. Its creation and
cleanup semantics must be proven before it is used; no account, token, ACL or
service has been created by these probes. Crash recovery and durability remain
unproven even for the no-replace rename that succeeded.

Microsoft's descriptions of [handle-relative rename information](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
and [native rename information](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
provide API context; tests of the exact handle-sharing and filesystem behavior
remain necessary. The ignored tests are exploratory probes, not an automatic
production-readiness gate.

The journal codec currently validates bindings, phase order and checksums in
memory only. It does not yet store per-file identities or receipts, write an
exclusive durable log, or recover a crashed transaction. Real network and
publication paths must stay disabled until all reviewed gates are implemented
and tested.
