# Transfer process memory gate: implementation notes

This is a design and validation note, not permission to start a receiver or a
claim that either endpoint meets the transfer's 256 MiB memory requirement.
The operational commands remain disabled until their full qualification gates
are satisfied.

## Linux sender candidate

The isolated `process_limit` primitive lowers both the soft and hard
`RLIMIT_AS` values to at most 256 MiB and preserves a stricter inherited
limit. It checks `/proc/self/statm` before and after the change because lowering
the limit does not remove pre-existing mappings. It must run in the dedicated
transfer process before runtime workers or credentials are started; it must
fail closed if either size or limit cannot be checked. It is not wired to a
command. It does not bound kernel allocations, multiple processes or child
processes; the first milestone must prohibit subprocesses and measure actual
resident and committed usage under the reviewed adversarial workloads.

The Linux-only test starts a separate synthetic child process, applies the
limit there, and attempts an allocation larger than the limit. A second child
starts with a tighter limit. These tests have not yet been compiled or run on
Linux. The full runtime, including TLS, Vox and the three-file transfer, must
also be tested under the limit: a process can fail safely but unusably if its
virtual mappings or thread stacks already exceed the budget.

## Windows receiver candidate

A job object's `JOB_OBJECT_LIMIT_PROCESS_MEMORY` applies a per-process limit
to committed virtual memory, and nested jobs can impose a stricter effective
limit. The job handle, intended child identity, assignment and configured limit
must be retained and verified; an assignment or verification failure must
stop the transfer. This does not bound kernel resources or prove a whole-system
or multi-process limit. See Microsoft's [extended limit information](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)
and [basic limit information](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information).

Microsoft states that memory operations performed before assignment are not
examined by `AssignProcessToJobObject`. Simply attaching a job to an already
running receiver therefore does not demonstrate the reviewed ceiling from the
start. See [AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject).
A candidate is to create a dedicated child suspended, configure and assign the
job before resuming it, and verify its initial memory accounting and actual
limits before any listener or credential use. Whether that establishes the
desired bound for executable-load allocations, nested jobs, failure paths and
supported Windows versions still needs independent review and synthetic child
tests. No job object, process, configuration, listener or credential is created
by this note.
