//! Linux process address-space ceiling for a dedicated transfer command.
//!
//! This is a startup primitive, not an operational permit. It has no effect
//! until called, cannot qualify a destination, and is not wired to a command.

use eyre::{Result, ensure};
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use std::io::Read;

/// Maximum virtual address space for one transfer process.
pub const MAX_ADDRESS_SPACE_BYTES: u64 = 256 * 1024 * 1024;

/// Irreversibly lower this process's soft and hard `RLIMIT_AS` ceilings.
///
/// Call only at the beginning of a dedicated transfer process, before starting
/// asynchronous workers or handling credentials. A stricter inherited limit
/// is preserved. This does not constrain child processes, kernel allocations,
/// or the aggregate of multiple processes; the command must not spawn workers
/// and still needs measured flood tests. An existing address space larger than
/// the limit is not reclaimed, so it is checked before and after setting it.
///
/// # Errors
/// Returns an error if the limit cannot be set or verified exactly.
pub fn apply_linux_address_space_limit() -> Result<()> {
    let previous = getrlimit(Resource::As);
    let ceiling = previous
        .current
        .unwrap_or(MAX_ADDRESS_SPACE_BYTES)
        .min(previous.maximum.unwrap_or(MAX_ADDRESS_SPACE_BYTES))
        .min(MAX_ADDRESS_SPACE_BYTES);
    ensure!(ceiling > 0, "inherited address-space limit is zero");
    ensure!(
        current_address_space()? <= ceiling,
        "existing address space exceeds ceiling"
    );
    let desired = Rlimit {
        current: Some(ceiling),
        maximum: Some(ceiling),
    };
    setrlimit(Resource::As, desired)?;
    ensure!(
        getrlimit(Resource::As) == desired,
        "address-space limit verification failed"
    );
    ensure!(
        current_address_space()? <= ceiling,
        "address space exceeds ceiling after limit"
    );
    Ok(())
}

fn current_address_space() -> Result<u64> {
    let mut bytes = String::new();
    std::fs::File::open("/proc/self/statm")?
        .take(256)
        .read_to_string(&mut bytes)?;
    let pages: u64 = bytes
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| eyre::eyre!("missing process address-space size"))?
        .parse()?;
    let page_size = u64::try_from(rustix::param::page_size())?;
    ensure!(page_size > 0, "invalid system page size");
    pages
        .checked_mul(page_size)
        .ok_or_else(|| eyre::eyre!("address-space size overflow"))
}
