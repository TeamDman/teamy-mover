//! Conservative Windows directory ACL checks and private child creation.
//!
//! This is not a staging permit: callers must bind the supplied user SID to the
//! effective token, verify and retain every ancestor handle, establish filesystem
//! semantics and stage creation, and account for privileged users.
//! It does not protect against a hostile process under the trusted account.

use super::manifest::valid_component;
use super::windows_lock::{ExclusiveFile, FileIdentity, directory_identity, regular_file_identity};
use eyre::{Result, ensure};
use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows::Win32::Foundation::{
    ERROR_NO_TOKEN, HANDLE, HLOCAL, LocalFree, OBJ_CASE_INSENSITIVE, STATUS_PENDING, UNICODE_STRING,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetTokenInformation, IsValidAcl, IsValidSecurityDescriptor, IsValidSid, IsWellKnownSid,
    LookupAccountNameW, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PRESENT,
    SE_DACL_PROTECTED, SID_NAME_USE, SidTypeWellKnownGroup, TOKEN_QUERY, TOKEN_USER, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_MODE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_DATA, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

// Only read/traverse rights are accepted for untrusted SIDs. Unknown bits and
// all write, delete, owner or DACL-changing rights fail closed. Directory
// rights use the same low bits as file rights; 0x20 is traverse/execute.
const UNTRUSTED_READ_ONLY: u32 = 0x8000_0000 | 0x2000_0000 | 0x0010_0000 | 0x0002_0000 | 0xA9;
const ADD_SUBDIRECTORY: u32 = 0x0000_0004;
// Inheritable create rights could also apply to protected descendants.
const ACE_INHERITANCE_FLAGS: u8 = 0x01 | 0x02 | 0x08;
const ACE_INHERIT_ONLY: u8 = 0x08;
const MAX_ACES: usize = 512;

struct LocalDescriptor(PSECURITY_DESCRIPTOR);

/// A restrictive descriptor generated for the process user, `LocalSystem` and
/// administrators. It is not evidence of protected ancestry or publication.
pub struct PrivateDirectorySecurity(LocalDescriptor);

/// A newly created synchronous directory handle. This does not qualify the
/// directory for staging or publication. Its file handle cannot be replaced
/// by callers, preserving the synchronous-open property of this wrapper.
#[derive(Debug)]
pub struct CreatedDirectory(File);

impl std::ops::Deref for CreatedDirectory {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for PrivateDirectorySecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateDirectorySecurity")
            .finish_non_exhaustive()
    }
}

impl PrivateDirectorySecurity {
    /// Recheck the generated DACL against the current process token.
    /// This does not validate an object's owner or establish a staging permit.
    ///
    /// # Errors
    /// Returns an error if the token or descriptor is unavailable or unsafe.
    pub fn verify_for_process(&self) -> Result<()> {
        let sid = process_user_sid()?;
        let mut words = sid_storage(&sid)?;
        verify_descriptor_inner(
            self.0.0,
            PSID(words.as_mut_ptr().cast()),
            true,
            false,
            false,
        )
    }
}

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocates this descriptor with LocalAlloc;
        // the owned pointer is freed exactly once after all views are dropped.
        let _freed = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn sid_storage(bytes: &[u8]) -> Result<Vec<u32>> {
    ensure!(bytes.len() >= 8 && bytes[0] == 1, "invalid user SID");
    let count = usize::from(bytes[1]);
    ensure!(
        count <= 15 && bytes.len() == 8 + 4 * count,
        "invalid user SID length"
    );
    let mut words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|part| u32::from_ne_bytes([part[0], part[1], part[2], part[3]]))
        .collect();
    let sid = PSID(words.as_mut_ptr().cast());
    // SAFETY: the buffer is aligned and its revision/count/length are checked.
    ensure!(unsafe { IsValidSid(sid) }.as_bool(), "invalid user SID");
    Ok(words)
}

/// Return the current process token's user SID in binary form. Callers must
/// separately ensure the operation is not running under thread impersonation.
///
/// # Errors
/// Returns an error if the process token or its user SID cannot be validated.
pub fn process_user_sid() -> Result<Vec<u8>> {
    let mut raw = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle; raw is writable.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: process is live and raw receives an owned token handle.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut raw)? };
    ensure!(!raw.0.is_null(), "missing process token");
    // SAFETY: a successful OpenProcessToken returned this uniquely owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw.0) };
    let mut required = 0u32;
    // SAFETY: this size query has no output buffer and required is writable.
    let _size_result = unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            None,
            0,
            &raw mut required,
        )
    };
    let length = usize::try_from(required)?;
    ensure!(
        (std::mem::size_of::<TOKEN_USER>()..=64 * 1024).contains(&length),
        "invalid token user size"
    );
    let mut buffer = vec![0_u64; length.div_ceil(std::mem::size_of::<u64>())];
    let mut returned = 0u32;
    // SAFETY: token is live, buffer is aligned and at least required bytes,
    // and returned is a writable output parameter.
    let token_result = unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            required,
            &raw mut returned,
        )
    };
    token_result?;
    ensure!(
        (std::mem::size_of::<TOKEN_USER>()..=length).contains(&usize::try_from(returned)?),
        "invalid token user length"
    );
    // SAFETY: the initialized buffer includes a complete TOKEN_USER header.
    let info = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let start = info.User.Sid.0 as usize;
    let base = buffer.as_ptr() as usize;
    let end = base
        .checked_add(usize::try_from(returned)?)
        .ok_or_else(|| eyre::eyre!("token buffer overflow"))?;
    ensure!(
        start >= base && start.checked_add(8).is_some_and(|n| n <= end),
        "token SID outside buffer"
    );
    // SAFETY: the bounded token buffer includes the complete SID header.
    let header = unsafe { std::slice::from_raw_parts(start as *const u8, 8) };
    let sid_len = 8 + 4 * usize::from(header[1]);
    ensure!(
        header[0] == 1 && header[1] <= 15 && start.checked_add(sid_len).is_some_and(|n| n <= end),
        "invalid token SID"
    );
    // SAFETY: the entire SID was checked to lie within the live token buffer.
    let sid = unsafe { std::slice::from_raw_parts(start as *const u8, sid_len) }.to_vec();
    let _validated = sid_storage(&sid)?;
    Ok(sid)
}

fn ensure_not_impersonating() -> Result<()> {
    let mut raw = HANDLE::default();
    // SAFETY: GetCurrentThread returns a live pseudo-handle; raw is writable.
    let thread = unsafe { GetCurrentThread() };
    // SAFETY: thread is live and raw is a valid out parameter.
    match unsafe { OpenThreadToken(thread, TOKEN_QUERY, true, &raw mut raw) } {
        Ok(()) => {
            // SAFETY: a successful OpenThreadToken returned an owned handle.
            let _token = unsafe { OwnedHandle::from_raw_handle(raw.0) };
            eyre::bail!("thread impersonation is not allowed");
        }
        Err(error) if error.code() == windows::core::HRESULT::from_win32(ERROR_NO_TOKEN.0) => {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Build and validate an explicit protected DACL for a new private directory.
/// The caller must ensure the operation is not impersonating a different user.
/// This does not create a directory, secure its parent or authorize publication.
///
/// # Errors
/// Returns an error if the process SID or the generated descriptor is invalid.
pub fn private_directory_security() -> Result<PrivateDirectorySecurity> {
    let sid_bytes = process_user_sid()?;
    let mut user_words = sid_storage(&sid_bytes)?;
    let user = PSID(user_words.as_mut_ptr().cast());
    let mut sid_string = windows::core::PWSTR::null();
    // SAFETY: user is a validated, live SID and sid_string is writable.
    unsafe { ConvertSidToStringSidW(user, &raw mut sid_string)? };
    ensure!(!sid_string.0.is_null(), "SID conversion returned no string");
    // SAFETY: Windows returned a NUL-terminated SID string allocated with LocalAlloc.
    let sid_text = unsafe { sid_string.to_string() };
    // SAFETY: the returned string is LocalAlloc-owned and is freed exactly once.
    let _freed = unsafe { LocalFree(Some(HLOCAL(sid_string.0.cast()))) };
    let sid_text = sid_text?;
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid_text})");
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut raw = PSECURITY_DESCRIPTOR::default();
    // SAFETY: wide is NUL-terminated and raw is writable; Windows owns the allocation.
    let descriptor_result = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(wide.as_ptr()),
            1,
            &raw mut raw,
            None,
        )
    };
    descriptor_result?;
    let owned = LocalDescriptor(raw);
    ensure!(
        !owned.0.0.is_null(),
        "missing generated security descriptor"
    );
    // A new object receives its default owner during creation, so the owner
    // must also be checked on the created object's handle before relying on it.
    verify_descriptor_inner(owned.0, user, true, false, false)?;
    Ok(PrivateDirectorySecurity(owned))
}

fn is_trusted_sid(sid: PSID, user: PSID) -> bool {
    // SAFETY: Both SIDs are validated and live for all three read-only calls.
    let valid = unsafe { IsValidSid(sid) }.as_bool();
    if !valid {
        return false;
    }
    // SAFETY: Both SIDs are validated and live for the call.
    let same_user = unsafe { EqualSid(sid, user) }.is_ok();
    // SAFETY: The SID is validated and remains live for the call.
    let system = unsafe { IsWellKnownSid(sid, WinLocalSystemSid) }.as_bool();
    // SAFETY: The SID is validated and remains live for the call.
    let admins = unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) }.as_bool();
    same_user || system || admins
}

// This service SID is documented by Microsoft; compare it with the result of
// resolving the fully qualified local service name before trusting an owner.
const TRUSTED_INSTALLER_SID: windows::core::PCWSTR =
    windows::core::w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

fn matches_root_servicing_owner(owner: PSID) -> Result<bool> {
    let mut resolved = [0_u32; 64];
    let mut sid_size = u32::try_from(std::mem::size_of_val(&resolved))?;
    let mut domain = [0_u16; 256];
    let mut domain_size = u32::try_from(domain.len())?;
    let mut sid_type = SID_NAME_USE::default();
    // SAFETY: both output buffers are aligned, writable, and their lengths
    // match their capacities. The system and account strings are valid.
    unsafe {
        LookupAccountNameW(
            windows::core::PCWSTR::null(),
            windows::core::w!("NT SERVICE\\TrustedInstaller"),
            Some(PSID(resolved.as_mut_ptr().cast())),
            &raw mut sid_size,
            Some(windows::core::PWSTR(domain.as_mut_ptr())),
            &raw mut domain_size,
            &raw mut sid_type,
        )?;
    };
    ensure!(
        (8..=std::mem::size_of_val(&resolved)).contains(&usize::try_from(sid_size)?)
            && usize::try_from(domain_size)? < domain.len()
            && sid_type == SidTypeWellKnownGroup,
        "unexpected servicing SID resolution"
    );
    let domain_text = String::from_utf16(&domain[..usize::try_from(domain_size)?])?;
    ensure!(
        domain_text.eq_ignore_ascii_case("NT SERVICE"),
        "unexpected service domain"
    );
    // SAFETY: the SID buffer is initialized and sid_size was bounded above.
    let sid_bytes = unsafe {
        std::slice::from_raw_parts(resolved.as_ptr().cast::<u8>(), usize::try_from(sid_size)?)
    };
    ensure!(
        sid_bytes[0] == 1
            && sid_bytes[1] <= 15
            && 8 + 4 * usize::from(sid_bytes[1]) <= sid_bytes.len(),
        "invalid resolved servicing SID extent"
    );
    let resolved_sid = PSID(resolved.as_mut_ptr().cast());
    // SAFETY: the returned SID is within the aligned resolution buffer.
    let valid_resolved_sid = unsafe { IsValidSid(resolved_sid) }.as_bool();
    ensure!(valid_resolved_sid, "invalid resolved servicing SID");
    let mut expected = PSID::default();
    // SAFETY: the constant string is NUL-terminated; expected is writable.
    unsafe { ConvertStringSidToSidW(TRUSTED_INSTALLER_SID, &raw mut expected)? };
    ensure!(!expected.0.is_null(), "missing expected servicing SID");
    // SAFETY: both SIDs are validated Windows SIDs and remain live.
    let pinned_matches = unsafe { EqualSid(resolved_sid, expected) }.is_ok();
    // SAFETY: owner is a valid SID returned in the live security descriptor.
    let owner_matches = unsafe { EqualSid(owner, expected) }.is_ok();
    // SAFETY: ConvertStringSidToSidW allocated this SID with LocalAlloc.
    let _freed = unsafe { LocalFree(Some(HLOCAL(expected.0))) };
    ensure!(
        pinned_matches,
        "resolved servicing SID does not match pinned identity"
    );
    Ok(owner_matches)
}

fn verify_ace(
    acl: *mut ACL,
    index: u32,
    user: PSID,
    acl_size: usize,
    root_sibling_create_candidate: bool,
) -> Result<()> {
    let mut ace_ptr = std::ptr::null_mut();
    // SAFETY: the ACL was validated and ace_ptr is a writable out pointer.
    unsafe { GetAce(acl, index, &raw mut ace_ptr)? };
    let base = acl as usize;
    let start = ace_ptr as usize;
    let end = base
        .checked_add(acl_size)
        .ok_or_else(|| eyre::eyre!("ACL size overflow"))?;
    ensure!(
        start >= base
            && start
                .checked_add(std::mem::size_of::<ACE_HEADER>())
                .is_some_and(|n| n <= end),
        "ACE outside ACL"
    );
    // SAFETY: bounds above include the header; unaligned read avoids alignment assumptions.
    let header = unsafe { std::ptr::read_unaligned(ace_ptr.cast::<ACE_HEADER>()) };
    let entry_len = usize::from(header.AceSize);
    ensure!(
        entry_len >= std::mem::size_of::<ACE_HEADER>()
            && start.checked_add(entry_len).is_some_and(|n| n <= end),
        "invalid ACE size"
    );
    match header.AceType {
        1 => Ok(()), // An ordinary deny ACE cannot grant access.
        0 => {
            let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            ensure!(entry_len >= sid_offset + 8, "truncated allow ACE SID");
            // SAFETY: the validated ACE extent includes its fixed header and mask.
            let ace = unsafe { std::ptr::read_unaligned(ace_ptr.cast::<ACCESS_ALLOWED_ACE>()) };
            // SAFETY: the preceding bounds check includes eight bytes of SID header.
            let sid_header =
                unsafe { std::slice::from_raw_parts((start + sid_offset) as *const u8, 8) };
            let sid_len = 8 + 4 * usize::from(sid_header[1]);
            ensure!(
                sid_header[0] == 1 && sid_header[1] <= 15 && sid_offset + sid_len <= entry_len,
                "invalid allow ACE SID"
            );
            let sid = PSID((start + sid_offset) as *mut std::ffi::c_void);
            // SAFETY: the SID header and complete variable-length SID fit in the ACE.
            let valid = unsafe { IsValidSid(sid) }.as_bool();
            ensure!(valid, "invalid allow ACE SID");
            if !is_trusted_sid(sid, user) {
                if root_sibling_create_candidate {
                    ensure!(header.AceFlags & !0x1f == 0, "unsupported allow ACE flags");
                }
                if root_sibling_create_candidate && header.AceFlags & ACE_INHERIT_ONLY != 0 {
                    ensure!(
                        header.AceFlags & 0x03 != 0,
                        "inherit-only ACE has no inheritance target"
                    );
                    // This ACE does not grant access to this root object, but
                    // may grant rights on children. No descendant check may
                    // use this candidate policy; every edge remains strict.
                    return Ok(());
                }
                let permitted = UNTRUSTED_READ_ONLY
                    | if root_sibling_create_candidate {
                        ADD_SUBDIRECTORY
                    } else {
                        0
                    };
                ensure!(
                    ace.Mask & !permitted == 0,
                    "untrusted principal has non-read access"
                );
                if ace.Mask & ADD_SUBDIRECTORY != 0 {
                    ensure!(
                        root_sibling_create_candidate
                            && header.AceFlags & ACE_INHERITANCE_FLAGS == 0,
                        "untrusted create-subdirectory grant is inheritable"
                    );
                }
            }
            Ok(())
        }
        _ => eyre::bail!("unsupported ACE type"),
    }
}

#[cfg(test)]
fn verify_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
    user: PSID,
    require_protected: bool,
) -> Result<()> {
    verify_descriptor_inner(descriptor, user, require_protected, true, false)
}

fn verify_descriptor_inner(
    descriptor: PSECURITY_DESCRIPTOR,
    user: PSID,
    require_protected: bool,
    require_owner: bool,
    root_sibling_create_candidate: bool,
) -> Result<()> {
    // SAFETY: the descriptor is a live Windows-allocated security descriptor.
    let valid = unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool();
    ensure!(valid, "invalid security descriptor");
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: descriptor and out parameters are live and writable.
    unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)? };
    ensure!(control & SE_DACL_PRESENT.0 != 0, "DACL absent");
    if require_protected {
        ensure!(
            control & SE_DACL_PROTECTED.0 != 0,
            "DACL is not protected from inheritance"
        );
    }
    if require_owner {
        let mut owner = PSID::default();
        let mut owner_defaulted = windows::core::BOOL(0);
        // SAFETY: descriptor and out parameters are live and writable.
        let owner_result = unsafe {
            GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted)
        };
        owner_result?;
        ensure!(!owner.0.is_null(), "untrusted or missing owner");
        // SAFETY: owner is part of the validated, live security descriptor.
        ensure!(unsafe { IsValidSid(owner) }.as_bool(), "invalid owner SID");
        let trusted_owner = is_trusted_sid(owner, user)
            || (root_sibling_create_candidate && matches_root_servicing_owner(owner)?);
        ensure!(trusted_owner, "untrusted or missing owner");
    }
    let mut present = windows::core::BOOL(0);
    let mut defaulted = windows::core::BOOL(0);
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: descriptor and out parameters are live and writable.
    let dacl_result = unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    };
    dacl_result?;
    ensure!(
        present.as_bool() && !acl.is_null(),
        "DACL is absent or null"
    );
    // SAFETY: Windows returned the ACL as part of the validated descriptor.
    ensure!(unsafe { IsValidAcl(acl) }.as_bool(), "invalid DACL");
    // SAFETY: the valid ACL contains a complete fixed header.
    let header = unsafe { std::ptr::read_unaligned(acl) };
    ensure!(usize::from(header.AceCount) <= MAX_ACES, "too many ACEs");
    for index in 0..u32::from(header.AceCount) {
        verify_ace(
            acl,
            index,
            user,
            usize::from(header.AclSize),
            root_sibling_create_candidate,
        )?;
    }
    Ok(())
}

/// Check an open directory's owner and DACL against a supplied user SID.
/// This is a restrictive filter, not proof of protected ancestry, current-token
/// identity, filesystem integrity, or absence of privileged bypass rights.
///
/// # Errors
/// Rejects unknown ACE types, untrusted ownership or non-read grants, absent
/// or null DACLs, malformed data, and unprotected DACLs when required.
pub fn verify_directory_acl(
    directory: &File,
    user_sid: &[u8],
    require_protected: bool,
) -> Result<()> {
    inspect_directory_acl(directory, user_sid, require_protected, false)
}

/// Inspect an alleged volume-root ACL for the proposed sibling-creation case.
/// A successful result is only an ACL candidate: it does not verify that the
/// handle is a volume root, establish ancestry, check effective tokens or
/// privileges, account for pre-existing handles, or authorize any operation.
/// No production publication or ancestry gate may rely on this result until
/// the concrete mechanism is independently reviewed and all gates pass.
///
/// # Errors
/// Rejects effective untrusted mutation grants except non-inheritable
/// create-subdirectory, and rejects unsafe descriptors or directory handles.
/// Inherit-only allow ACEs can grant rights to descendants and are ignored
/// only for this non-authorizing root diagnostic; descendants must be checked
/// separately using the strict filter.
pub fn inspect_root_acl_candidate(directory: &File, user_sid: &[u8]) -> Result<()> {
    inspect_directory_acl(directory, user_sid, false, true)
}

fn inspect_directory_acl(
    directory: &File,
    user_sid: &[u8],
    require_protected: bool,
    root_sibling_create_candidate: bool,
) -> Result<()> {
    directory_identity(directory)?;
    inspect_object_acl(
        directory,
        user_sid,
        require_protected,
        root_sibling_create_candidate,
    )
}

fn inspect_object_acl(
    object: &File,
    user_sid: &[u8],
    require_protected: bool,
    root_sibling_create_candidate: bool,
) -> Result<()> {
    let mut user_words = sid_storage(user_sid)?;
    let user = PSID(user_words.as_mut_ptr().cast());
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the retained object handle and out pointer are live. Windows
    // allocates the returned self-relative descriptor with LocalAlloc.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(object.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
    };
    let owned = LocalDescriptor(descriptor);
    ensure!(
        status.0 == 0,
        "GetSecurityInfo failed with code {}",
        status.0
    );
    ensure!(!owned.0.0.is_null(), "missing security descriptor");
    verify_descriptor_inner(
        owned.0,
        user,
        require_protected,
        true,
        root_sibling_create_candidate,
    )
}

/// Open and inspect one directory component relative to a retained parent.
/// This validates both immediate ACLs and rejects a reparse-point child, but
/// the caller must separately establish and retain the full ancestry and
/// qualify the filesystem. It never creates or alters an object.
///
/// # Errors
/// Rejects impersonation, unsafe ACLs/identity, invalid names or failed opens.
pub fn open_checked_child(
    parent: &File,
    expected_parent: FileIdentity,
    name: &str,
    allow_create: bool,
) -> Result<File> {
    open_checked_child_with_sharing(
        parent,
        expected_parent,
        name,
        allow_create,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

/// Open a strictly checked child with directory-list access and without delete
/// sharing. This remains a non-authorizing primitive: strict ACL checks still
/// apply, and the caller must separately qualify the root, ancestry, effective
/// access, pre-existing handles, filesystem and retained transaction resources.
/// In particular, it does not authorize or qualify the Downloads exception.
///
/// # Errors
/// Rejects unsafe ACLs, identities, names, or incompatible existing handles.
pub fn open_checked_child_without_delete_share(
    parent: &File,
    expected_parent: FileIdentity,
    name: &str,
    allow_create: bool,
) -> Result<File> {
    open_checked_child_with_sharing(
        parent,
        expected_parent,
        name,
        allow_create,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
}

fn open_checked_child_with_sharing(
    parent: &File,
    expected_parent: FileIdentity,
    name: &str,
    allow_create: bool,
    share_mode: FILE_SHARE_MODE,
) -> Result<File> {
    ensure!(valid_component(name), "invalid directory component");
    ensure_not_impersonating()?;
    let user = process_user_sid()?;
    ensure!(
        directory_identity(parent)? == expected_parent,
        "parent identity mismatch"
    );
    verify_directory_acl(parent, &user, false)?;
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(
        wide.len()
            .checked_mul(2)
            .ok_or_else(|| eyre::eyre!("component length overflow"))?,
    )?;
    let object_name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: windows::core::PWSTR(wide.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())?,
        RootDirectory: HANDLE(parent.as_raw_handle()),
        ObjectName: &raw const object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut access =
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | READ_CONTROL | SYNCHRONIZE;
    if allow_create {
        access |= FILE_ADD_SUBDIRECTORY;
    }
    let mut raw = HANDLE::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the retained parent and UTF-16 component stay live; out
    // parameters are writable. FILE_OPEN_REPARSE_POINT opens the leaf itself.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            access,
            &raw const attributes,
            &raw mut status_block,
            None,
            FILE_ATTRIBUTE_DIRECTORY,
            share_mode,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            None,
            0,
        )
    };
    if status.0 != 0 {
        if !raw.0.is_null() && raw.0 as isize != -1 {
            // SAFETY: any unexpected valid returned handle is uniquely owned.
            let _unexpected_handle = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        }
        eyre::bail!(
            "directory open failed with NTSTATUS {:#x}",
            u32::from_ne_bytes(status.0.to_ne_bytes())
        );
    }
    ensure!(
        !raw.0.is_null() && raw.0 as isize != -1,
        "open returned an invalid handle"
    );
    // SAFETY: successful NtCreateFile returns a uniquely owned handle.
    let child = unsafe { File::from_raw_handle(raw.0) };
    let identity = directory_identity(&child)?;
    ensure!(
        identity.volume_serial == expected_parent.volume_serial,
        "child volume mismatch"
    );
    ensure!(
        directory_identity(parent)? == expected_parent,
        "parent identity changed"
    );
    verify_directory_acl(&child, &user, false)?;
    Ok(child)
}

/// Retained directory handles opened one component at a time from an approved
/// root. This is not a staging permit or filesystem qualification, and the
/// caller must establish that the supplied root is the intended trusted root.
pub struct CheckedDirectoryChain {
    directories: Vec<File>,
    identities: Vec<FileIdentity>,
    components: Vec<String>,
}

impl std::fmt::Debug for CheckedDirectoryChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedDirectoryChain")
            .field("component_count", &self.components.len())
            .finish_non_exhaustive()
    }
}

impl CheckedDirectoryChain {
    /// The retained leaf handle. A caller must revalidate the chain and all
    /// remaining staging gates before relying on it for mutation.
    #[must_use]
    pub fn leaf(&self) -> Option<&File> {
        self.directories.last()
    }

    /// Identity of the retained leaf directory.
    #[must_use]
    pub fn leaf_identity(&self) -> Option<FileIdentity> {
        self.identities.last().copied()
    }

    /// Open each named component relative to its already checked parent.
    /// `expected_root` must come from local approval, not a remote peer.
    ///
    /// # Errors
    /// Returns an error for unsafe identity, ACL, reparse point, or path input.
    pub fn from_approved_root(
        root: File,
        expected_root: FileIdentity,
        components: &[&str],
        allow_create_at_leaf: bool,
    ) -> Result<Self> {
        ensure!(components.len() <= 64, "too many directory components");
        ensure_not_impersonating()?;
        let user = process_user_sid()?;
        ensure!(
            directory_identity(&root)? == expected_root,
            "root identity mismatch"
        );
        verify_directory_acl(&root, &user, false)?;
        let mut directories = vec![root];
        let mut identities = vec![expected_root];
        let mut names = Vec::with_capacity(components.len());
        for (index, component) in components.iter().enumerate() {
            let parent = directories
                .last()
                .ok_or_else(|| eyre::eyre!("missing parent"))?;
            let parent_id = *identities
                .last()
                .ok_or_else(|| eyre::eyre!("missing parent identity"))?;
            let create = allow_create_at_leaf && index + 1 == components.len();
            let child = open_checked_child(parent, parent_id, component, create)?;
            identities.push(directory_identity(&child)?);
            directories.push(child);
            names.push((*component).to_owned());
        }
        Ok(Self {
            directories,
            identities,
            components: names,
        })
    }

    /// Recheck retained handles and reopen every named edge to detect namespace
    /// replacement. It does not re-establish the initially approved root path.
    ///
    /// # Errors
    /// Returns an error if a retained identity, ACL or named edge changed.
    pub fn revalidate(&self) -> Result<()> {
        ensure_not_impersonating()?;
        let user = process_user_sid()?;
        for (handle, identity) in self.directories.iter().zip(&self.identities) {
            ensure!(
                directory_identity(handle)? == *identity,
                "retained directory identity changed"
            );
            verify_directory_acl(handle, &user, false)?;
        }
        for (index, name) in self.components.iter().enumerate() {
            let reopened = open_checked_child(
                &self.directories[index],
                self.identities[index],
                name,
                false,
            )?;
            ensure!(
                directory_identity(&reopened)? == self.identities[index + 1],
                "directory edge identity changed"
            );
        }
        Ok(())
    }
}

/// Create an empty, exclusively held private file relative to a retained
/// directory. This is a low-level primitive, not a staging permit: callers
/// must separately establish protected ancestry, effective access, an approved
/// file-to-manifest binding, transaction ownership and filesystem semantics.
/// No existing entry is opened or replaced. If post-create validation fails,
/// the new entry is preserved for inspection rather than deleted or retried.
/// Run filesystem work through a caller-owned blocking-I/O deadline.
///
/// # Errors
/// Rejects impersonation, unsafe names, mismatched parent identity, insecure
/// parent/file ACLs, existing entries, and unconfirmed filesystem operations.
pub fn create_private_file(
    parent: &File,
    expected_parent: FileIdentity,
    name: &str,
) -> Result<ExclusiveFile> {
    ensure!(valid_component(name), "invalid private file component");
    ensure_not_impersonating()?;
    let user = process_user_sid()?;
    ensure!(
        directory_identity(parent)? == expected_parent,
        "parent identity mismatch"
    );
    verify_directory_acl(parent, &user, true)?;
    let security = private_directory_security()?;
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(
        wide.len()
            .checked_mul(2)
            .ok_or_else(|| eyre::eyre!("component length overflow"))?,
    )?;
    let object_name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: windows::core::PWSTR(wide.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())?,
        RootDirectory: HANDLE(parent.as_raw_handle()),
        ObjectName: &raw const object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security.0.0.0.cast(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut raw = HANDLE::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the retained parent, component and descriptor remain live;
    // output pointers are writable. FILE_CREATE does not open an existing
    // name, and zero sharing denies competing opens while the handle is held.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status_block,
            None,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_MODE(0),
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            None,
            0,
        )
    };
    if status.0 != 0 {
        if !raw.0.is_null() && raw.0 as isize != -1 {
            // SAFETY: any non-null, non-invalid handle returned is owned here.
            let _unexpected = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        }
        eyre::bail!(
            "private file creation was not confirmed; inspect before retrying (NTSTATUS {:#x})",
            u32::from_ne_bytes(status.0.to_ne_bytes())
        );
    }
    ensure!(
        !raw.0.is_null() && raw.0 as isize != -1,
        "file creation returned an invalid handle; inspect before retrying"
    );
    // SAFETY: successful NtCreateFile returned a uniquely owned file handle.
    let file = unsafe { File::from_raw_handle(raw.0) };
    let result = (|| {
        let identity = regular_file_identity(&file)?;
        ensure!(
            identity.volume_serial == expected_parent.volume_serial,
            "file volume mismatch"
        );
        ensure!(file.metadata()?.len() == 0, "created file is not empty");
        ensure!(
            directory_identity(parent)? == expected_parent,
            "parent identity changed"
        );
        inspect_object_acl(&file, &user, true, false)?;
        verify_directory_acl(parent, &user, true)?;
        Ok(())
    })();
    if let Err(error) = result {
        return Err(
            error.wrap_err("file created but validation failed; preserve it for inspection")
        );
    }
    // The only handle returned by our FILE_CREATE used share mode zero and has
    // not been duplicated or exposed; transfer ownership to ExclusiveFile.
    ExclusiveFile::from_opened_no_share(file)
}

/// Reopen an expected private regular file relative to a retained directory,
/// without sharing or following a reparse point. This does not qualify the
/// directory's ancestry, prove publication, or authorize a receipt.
///
/// This must run inside the single-flight worker that owns the journal, lock,
/// stage, destination and ancestry handles. An unexpected pending open parks
/// that worker until process termination so its output buffers and all outer
/// resources remain live; a timeout does not permit retry.
///
/// # Errors
/// Rejects mismatched identities, unsafe ACLs or names, unsupported opens and
/// competing handles. An unexpected pending open is quarantined, not returned.
pub(crate) fn reopen_private_file_no_share(
    parent: &File,
    expected_parent: FileIdentity,
    name: &str,
    expected_file: FileIdentity,
) -> Result<ExclusiveFile> {
    ensure!(valid_component(name), "invalid private file component");
    ensure_not_impersonating()?;
    let user = process_user_sid()?;
    ensure!(
        directory_identity(parent)? == expected_parent,
        "parent identity mismatch"
    );
    ensure!(
        expected_file.volume_serial == expected_parent.volume_serial,
        "file volume mismatch"
    );
    verify_directory_acl(parent, &user, true)?;
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(
        wide.len()
            .checked_mul(2)
            .ok_or_else(|| eyre::eyre!("component length overflow"))?,
    )?;
    let object_name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: windows::core::PWSTR(wide.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())?,
        RootDirectory: HANDLE(parent.as_raw_handle()),
        ObjectName: &raw const object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut raw = HANDLE::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the worker retains the parent, name, output locations and all
    // outer transaction resources through this synchronous open. Pending is
    // handled by parking this same worker without dropping any of them.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status_block,
            None,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_MODE(0),
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            None,
            0,
        )
    };
    if status == STATUS_PENDING {
        loop {
            std::hint::black_box((
                wide.as_ptr(),
                &raw const object_name,
                &raw const attributes,
                &raw const raw,
                &raw const status_block,
                parent.as_raw_handle(),
            ));
            std::thread::park();
        }
    }
    if status.0 != 0 {
        if !raw.0.is_null() && raw.0 as isize != -1 {
            // SAFETY: any valid returned handle is uniquely owned here.
            let _unexpected = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        }
        eyre::bail!(
            "private file reopen failed with NTSTATUS {:#x}",
            u32::from_ne_bytes(status.0.to_ne_bytes())
        );
    }
    ensure!(
        !raw.0.is_null() && raw.0 as isize != -1,
        "invalid reopened file handle"
    );
    // SAFETY: a successful open returns a new uniquely owned handle.
    let file = unsafe { File::from_raw_handle(raw.0) };
    ensure!(
        regular_file_identity(&file)? == expected_file,
        "file identity mismatch"
    );
    ensure!(
        directory_identity(parent)? == expected_parent,
        "parent identity changed"
    );
    inspect_object_acl(&file, &user, true, false)?;
    verify_directory_acl(parent, &user, true)?;
    ExclusiveFile::from_opened_no_share(file)
}

/// Exclusively create one private child directory relative to a retained parent
/// handle. This checks the immediate parent and new object's identity and DACL,
/// but does not qualify the parent's ancestry or filesystem, establish a
/// staging permit, or authorize publication. Run blocking filesystem work
/// through a caller-owned deadline and retain all trusted ancestor handles.
/// If post-creation validation fails, the created object is preserved for review.
///
/// # Errors
/// Rejects impersonation, unsafe parent ACL/identity, nonportable names, existing
/// entries, and any unsupported or unverifiable create or ACL operation.
pub fn create_private_child(
    parent: &File,
    expected_parent: FileIdentity,
    name: &str,
) -> Result<CreatedDirectory> {
    ensure!(valid_component(name), "invalid private directory component");
    ensure_not_impersonating()?;
    let user = process_user_sid()?;
    ensure!(
        directory_identity(parent)? == expected_parent,
        "parent identity mismatch"
    );
    verify_directory_acl(parent, &user, false)?;
    let security = private_directory_security()?;
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(
        wide.len()
            .checked_mul(2)
            .ok_or_else(|| eyre::eyre!("component length overflow"))?,
    )?;
    let object_name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: windows::core::PWSTR(wide.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())?,
        RootDirectory: HANDLE(parent.as_raw_handle()),
        ObjectName: &raw const object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security.0.0.0.cast(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut raw = HANDLE::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: parent, UTF-16 component and security descriptor remain live;
    // out parameters are writable. FILE_CREATE never replaces an existing name.
    let status = unsafe {
        NtCreateFile(
            &raw mut raw,
            DELETE
                | FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE,
            &raw const attributes,
            &raw mut status_block,
            None,
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            None,
            0,
        )
    };
    if status.0 != 0 {
        if !raw.0.is_null() && raw.0 as isize != -1 {
            // SAFETY: a non-null, non-invalid handle returned by NtCreateFile
            // is owned here even on an unexpected non-success status.
            let _unexpected_handle = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        }
        eyre::bail!(
            "private directory creation was not confirmed; inspect before retrying (NTSTATUS {:#x})",
            u32::from_ne_bytes(status.0.to_ne_bytes())
        );
    }
    ensure!(
        !raw.0.is_null() && raw.0 as isize != -1,
        "directory creation returned an invalid handle; inspect before retrying"
    );
    // SAFETY: successful NtCreateFile returns a uniquely owned handle.
    let child = unsafe { File::from_raw_handle(raw.0) };
    let result = (|| {
        let identity = directory_identity(&child)?;
        ensure!(
            identity.volume_serial == expected_parent.volume_serial,
            "child volume mismatch"
        );
        ensure!(
            directory_identity(parent)? == expected_parent,
            "parent identity changed"
        );
        verify_directory_acl(&child, &user, true)?;
        Ok(())
    })();
    if let Err(error) = result {
        return Err(
            error.wrap_err("directory created but validation failed; preserve it for inspection")
        );
    }
    Ok(CreatedDirectory(child))
}

/// Construct only synthetic test fixtures. This path-based helper does not
/// qualify ancestry and is never compiled into the operational library.
#[cfg(test)]
pub(crate) fn create_synthetic_private_directory(path: &std::path::Path) -> Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CreateDirectoryW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let security = private_directory_security()?;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())?,
        lpSecurityDescriptor: security.0.0.0,
        bInheritHandle: windows::core::BOOL(0),
    };
    // SAFETY: test path is NUL terminated and the descriptor remains live.
    unsafe { CreateDirectoryW(windows::core::PCWSTR(wide.as_ptr()), Some(&raw const attrs))? };
    let directory = std::fs::OpenOptions::new()
        .access_mode(
            (READ_CONTROL
                | SYNCHRONIZE
                | FILE_LIST_DIRECTORY
                | FILE_ADD_SUBDIRECTORY
                | FILE_ADD_FILE
                | FILE_READ_ATTRIBUTES)
                .0,
        )
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    verify_directory_acl(&directory, &process_user_sid()?, true)?;
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::journal::{JournalApproval, ObjectIdentity};
    use crate::transfer::transaction_journal::TransactionJournal;
    use sha2::{Digest, Sha256};
    use std::io::Write as _;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CreateDirectoryW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    use windows::core::PCWSTR;

    fn descriptor(sddl: &str) -> LocalDescriptor {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut result = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the input is NUL-terminated and result is a valid output;
        // Windows allocates the returned descriptor with LocalAlloc.
        let conversion = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                1,
                &raw mut result,
                None,
            )
        };
        conversion.unwrap();
        LocalDescriptor(result)
    }

    fn journal_created_file(
        parent: &File,
        parent_id: FileIdentity,
        stage: &File,
        stage_id: FileIdentity,
        file: &mut ExclusiveFile,
    ) {
        let journal_file = create_private_file(parent, parent_id, "journal.bin").unwrap();
        let journal_id = journal_file.identity();
        let identity = |id: FileIdentity| ObjectIdentity {
            volume_serial: id.volume_serial,
            file_index: id.file_index,
        };
        let transaction = "0123456789abcdef0123456789abcdef";
        let pin = "1111111111111111111111111111111111111111111111111111111111111111";
        let hash = format!("{:x}", Sha256::digest(b"synthetic"));
        let manifest = format!(
            r#"{{"aggregate_bytes":9,"expires_unix":100,"file_count":1,"files":[{{"id":"one","name":"one.bin","sha256":"{hash}","size":9}}],"transaction_id":"{transaction}","version":1}}"#
        );
        let digest = format!("{:x}", Sha256::digest(manifest.as_bytes()));
        let approval = JournalApproval {
            manifest_bytes: manifest.as_bytes(),
            manifest_sha256: &digest,
            transaction_id: transaction,
            client_pin: pin,
            server_pin: pin,
            destination_parent: identity(parent_id),
            stage_directory: identity(stage_id),
            journal_file: identity(journal_id),
            final_name: "published",
            now_unix: 1,
        };
        let mut journal = TransactionJournal::initialize(journal_file, &approval).unwrap();
        journal.claim_empty_file("one", file, 1).unwrap();
        file.file_mut().write_all(b"synthetic").unwrap();
        journal.verify_file("one", file.file_mut(), 1).unwrap();
        journal.record_commit_intent(2).unwrap();
        assert!(journal.intent_matches_directory(stage).unwrap());
        let _expired = journal.check_publication_time().unwrap_err();
        assert!(journal.commit().is_err());
    }

    #[test]
    fn rejects_untrusted_write_null_dacl_untrusted_owner_and_unprotected_acl() {
        // S-1-5-18 is LocalSystem. This is synthetic descriptor data only.
        let system_sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let mut words = sid_storage(&system_sid).unwrap();
        let user = PSID(words.as_mut_ptr().cast());
        let safe = descriptor("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)");
        verify_descriptor(safe.0, user, true).unwrap();
        let writable = descriptor("O:SYG:SYD:P(A;;FA;;;SY)(A;;FW;;;WD)");
        assert!(verify_descriptor(writable.0, user, true).is_err());
        // The strict filter never applies the diagnostic root exception.
        let sibling_create = descriptor("O:SYG:SYD:P(A;;FA;;;SY)(A;;0x4;;;WD)");
        assert!(verify_descriptor(sibling_create.0, user, true).is_err());
        let delete_child = descriptor("O:SYG:SYD:P(A;;FA;;;SY)(A;;0x40;;;WD)");
        assert!(verify_descriptor(delete_child.0, user, true).is_err());
        let write_dacl = descriptor("O:SYG:SYD:P(A;;FA;;;SY)(A;;WD;;;WD)");
        assert!(verify_descriptor(write_dacl.0, user, true).is_err());
        let write_owner = descriptor("O:SYG:SYD:P(A;;FA;;;SY)(A;;WO;;;WD)");
        assert!(verify_descriptor(write_owner.0, user, true).is_err());
        let deleted = descriptor("O:SYG:SYD:P(A;;FA;;;SY)(A;;SD;;;WD)");
        assert!(verify_descriptor(deleted.0, user, true).is_err());
        let owner = descriptor("O:WDG:SYD:P(A;;FA;;;SY)");
        assert!(verify_descriptor(owner.0, user, true).is_err());
        let missing = descriptor("O:SYG:SY");
        assert!(verify_descriptor(missing.0, user, true).is_err());
        let inherited = descriptor("O:SYG:SYD:(A;;FA;;;SY)");
        assert!(verify_descriptor(inherited.0, user, true).is_err());
        verify_descriptor(inherited.0, user, false).unwrap();
        let mut invalid = system_sid;
        invalid[1] = 15;
        let _invalid_sid = sid_storage(&invalid).unwrap_err();
    }

    #[test]
    fn strict_filter_rejects_modify_even_without_delete_child() {
        // Synthetic descriptor: the common Windows Modify mask includes DELETE
        // on this directory, but does not include FILE_DELETE_CHILD (0x40).
        let modify_mask = std::hint::black_box(0x0013_01bf_u32);
        assert_eq!(modify_mask & 0x40, 0);
        assert_ne!(modify_mask & 0x1_0000, 0);
        let system_sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let mut words = sid_storage(&system_sid).unwrap();
        let user = PSID(words.as_mut_ptr().cast());
        let modify = descriptor("O:SYG:SYD:P(A;;FA;;;SY)(A;OICI;0x001301bf;;;WD)");
        assert!(verify_descriptor(modify.0, user, true).is_err());
    }

    #[test]
    fn checked_child_no_delete_share_conflicts_with_delete_and_blocks_rename() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("private-parent");
        let parent = create_synthetic_private_directory(&path).unwrap();
        let parent_id = directory_identity(&parent).unwrap();
        let child = create_private_child(&parent, parent_id, "child").unwrap();
        let child_id = directory_identity(&child).unwrap();
        drop(child);

        let delete_handle = std::fs::OpenOptions::new()
            .access_mode((DELETE | FILE_READ_ATTRIBUTES).0)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path.join("child"))
            .unwrap();
        let _conflict = open_checked_child_without_delete_share(&parent, parent_id, "child", false)
            .unwrap_err();
        drop(delete_handle);

        let guarded =
            open_checked_child_without_delete_share(&parent, parent_id, "child", false).unwrap();
        assert_eq!(directory_identity(&guarded).unwrap(), child_id);
        assert!(std::fs::rename(path.join("child"), path.join("moved")).is_err());
        drop(guarded);
        std::fs::rename(path.join("child"), path.join("moved")).unwrap();
        assert!(path.join("moved").is_dir());
    }

    #[test]
    fn private_file_reopen_is_relative_identity_bound_and_exclusive() {
        use std::io::Read as _;

        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("private-stage");
        let stage = create_synthetic_private_directory(&path).unwrap();
        let stage_id = directory_identity(&stage).unwrap();
        let mut file = create_private_file(&stage, stage_id, "one.bin").unwrap();
        file.file_mut().write_all(b"synthetic").unwrap();
        let expected = file.identity();
        drop(file);

        let mut held = reopen_private_file_no_share(&stage, stage_id, "one.bin", expected).unwrap();
        let _conflicting =
            reopen_private_file_no_share(&stage, stage_id, "one.bin", expected).unwrap_err();
        let mut contents = Vec::new();
        held.file_mut().read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"synthetic");
        drop(held);

        let mut wrong = expected;
        wrong.file_index ^= 1 << 63;
        let _wrong = reopen_private_file_no_share(&stage, stage_id, "one.bin", wrong).unwrap_err();
        let _traversal =
            reopen_private_file_no_share(&stage, stage_id, "../one.bin", expected).unwrap_err();
        assert_eq!(std::fs::read(path.join("one.bin")).unwrap(), b"synthetic");
    }

    #[test]
    fn root_acl_candidate_allows_only_noninheritable_sibling_creation() {
        let system_sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let mut words = sid_storage(&system_sid).unwrap();
        let user = PSID(words.as_mut_ptr().cast());
        let candidate = |sddl: &str| {
            let descriptor = descriptor(sddl);
            verify_descriptor_inner(descriptor.0, user, true, true, true)
        };
        candidate("O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;WD)(A;;0x4;;;WD)").unwrap();
        candidate("O:SYG:SYD:P(A;;FA;;;SY)(A;OICIIO;0xe0010000;;;AU)").unwrap();
        for unsafe_ace in [
            "(A;CI;0x4;;;WD)",
            "(A;OI;0x4;;;WD)",
            "(A;OICI;0xe0010000;;;AU)",
            "(A;;0x6;;;WD)",
            "(A;;0x44;;;WD)",
            "(A;;GW;;;WD)",
            "(A;;WD;;;WD)",
            "(A;;WO;;;WD)",
            "(A;;SD;;;WD)",
        ] {
            let sddl = format!("O:SYG:SYD:P(A;;FA;;;SY){unsafe_ace}");
            assert!(candidate(&sddl).is_err(), "accepted {unsafe_ace}");
        }
        assert!(candidate("O:WDG:SYD:P(A;;FA;;;SY)(A;;0x4;;;WD)").is_err());
        let strict = descriptor("O:SYG:SYD:P(A;;FA;;;SY)(A;;0x4;;;WD)");
        assert!(verify_descriptor(strict.0, user, true).is_err());
    }

    #[test]
    fn servicing_owner_is_exact_and_limited_to_root_diagnostic() {
        const SERVICE_SID: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        let system_sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let mut words = sid_storage(&system_sid).unwrap();
        let user = PSID(words.as_mut_ptr().cast());
        let exact = descriptor(&format!("O:{SERVICE_SID}G:SYD:P(A;;FA;;;SY)"));
        verify_descriptor_inner(exact.0, user, true, true, true).unwrap();
        assert!(verify_descriptor(exact.0, user, true).is_err());
        let altered = descriptor(
            "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478465G:SYD:P(A;;FA;;;SY)",
        );
        assert!(verify_descriptor_inner(altered.0, user, true, true, true).is_err());
        let other_service = descriptor("O:S-1-5-80-1-2-3-4-5G:SYD:P(A;;FA;;;SY)");
        assert!(verify_descriptor_inner(other_service.0, user, true, true, true).is_err());
        let grant = descriptor(&format!("O:{SERVICE_SID}G:SYD:P(A;;FA;;;{SERVICE_SID})"));
        assert!(verify_descriptor_inner(grant.0, user, true, true, true).is_err());
    }

    #[test]
    fn inherit_only_root_grant_can_be_effective_on_a_child() {
        let sid = process_user_sid().unwrap();
        let mut words = sid_storage(&sid).unwrap();
        let mut string = windows::core::PWSTR::null();
        // SAFETY: the SID is validated and string is a writable out pointer.
        unsafe {
            ConvertSidToStringSidW(PSID(words.as_mut_ptr().cast()), &raw mut string).unwrap();
        };
        // SAFETY: Windows returned a valid NUL-terminated SID string.
        let user_sid = unsafe { string.to_string().unwrap() };
        // SAFETY: the string is a Windows LocalAlloc allocation owned here.
        let _freed = unsafe { LocalFree(Some(HLOCAL(string.0.cast()))) };
        let security = descriptor(&format!("D:P(A;;FA;;;{user_sid})(A;OICIIO;FA;;;WD)"));
        let fixture = tempfile::tempdir().unwrap();
        let root_path = fixture.path().join("candidate");
        let wide: Vec<u16> = root_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
            lpSecurityDescriptor: security.0.0,
            bInheritHandle: windows::core::BOOL(0),
        };
        // SAFETY: the synthetic path and security descriptor remain live.
        unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&raw const attributes)).unwrap() };
        std::fs::create_dir(root_path.join("child")).unwrap();
        let open = |path: &std::path::Path| {
            std::fs::OpenOptions::new()
                .access_mode((READ_CONTROL | FILE_READ_ATTRIBUTES).0)
                .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
                .open(path)
                .unwrap()
        };
        let root = open(&root_path);
        let child = open(&root_path.join("child"));
        inspect_root_acl_candidate(&root, &sid).unwrap();
        assert!(verify_directory_acl(&root, &sid, true).is_err());
        assert!(verify_directory_acl(&child, &sid, false).is_err());
    }

    #[test]
    fn protected_descriptor_is_applied_when_temporary_directory_is_created() {
        let sid = process_user_sid().unwrap();
        let security = private_directory_security().unwrap();
        security.verify_for_process().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("private-stage");
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
            lpSecurityDescriptor: security.0.0.0,
            bInheritHandle: windows::core::BOOL(0),
        };
        // SAFETY: path is NUL-terminated and attributes and its descriptor
        // remain valid during the creation of this synthetic temporary folder.
        unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&raw const attributes)).unwrap() };
        let directory = std::fs::OpenOptions::new()
            .access_mode(
                (READ_CONTROL
                    | SYNCHRONIZE
                    | FILE_LIST_DIRECTORY
                    | FILE_ADD_FILE
                    | FILE_ADD_SUBDIRECTORY
                    | FILE_READ_ATTRIBUTES)
                    .0,
            )
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(&path)
            .unwrap();
        verify_directory_acl(&directory, &sid, true).unwrap();
        let parent_id = directory_identity(&directory).unwrap();
        let child = create_private_child(&directory, parent_id, "child").unwrap();
        verify_directory_acl(&child, &sid, true).unwrap();
        let child_id = directory_identity(&child).unwrap();
        assert_eq!(child_id.volume_serial, parent_id.volume_serial);
        let mut created = create_private_file(&child, child_id, "one.bin").unwrap();
        created.verify().unwrap();
        journal_created_file(&directory, parent_id, &child, child_id, &mut created);
        let _competing = std::fs::OpenOptions::new()
            .write(true)
            .open(path.join("child/one.bin"))
            .unwrap_err();
        let _collision = create_private_file(&child, child_id, "one.bin").unwrap_err();
        let _traversal = create_private_file(&child, child_id, "../other").unwrap_err();
        let mut wrong_child = child_id;
        wrong_child.file_index ^= 1 << 63;
        let _wrong_child = create_private_file(&child, wrong_child, "other.bin").unwrap_err();
        drop(created);
        assert_eq!(
            std::fs::read(path.join("child/one.bin")).unwrap(),
            b"synthetic"
        );
        let reopened = open_checked_child(&directory, parent_id, "child", false).unwrap();
        assert_eq!(directory_identity(&reopened).unwrap(), child_id);
        let mut wrong_parent = parent_id;
        wrong_parent.file_index ^= 1 << 63;
        let _wrong_parent =
            open_checked_child(&directory, wrong_parent, "child", false).unwrap_err();
        let _invalid_name = open_checked_child(&directory, parent_id, "..", false).unwrap_err();
        let _collision = create_private_child(&directory, parent_id, "child").unwrap_err();
        assert_eq!(directory_identity(&child).unwrap(), child_id);
        let chain =
            CheckedDirectoryChain::from_approved_root(directory, parent_id, &["child"], true)
                .unwrap();
        chain.revalidate().unwrap();
        assert_eq!(chain.leaf_identity(), Some(child_id));
        std::fs::rename(path.join("child"), path.join("moved")).unwrap();
        assert!(chain.revalidate().is_err());
    }
}
