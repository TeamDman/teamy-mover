//! Building blocks for bounded, explicitly approved file transfer.

#[cfg(windows)]
pub mod blocking_io;
pub mod journal;
pub mod journal_file;
pub mod manifest;
#[cfg(target_os = "linux")]
pub mod process_limit;
pub mod proxy;
#[cfg(windows)]
pub mod receiver;
#[cfg(test)]
mod receiver_model;
pub mod recovery;
#[cfg(any(windows, target_os = "linux"))]
pub mod sender;
pub mod session;
#[cfg(any(windows, target_os = "linux"))]
pub(crate) mod source;
pub mod tls;
#[cfg(windows)]
pub mod transaction_journal;
pub mod verified_stream;
pub mod vox_transport;
#[cfg(windows)]
pub mod windows_acl;
#[cfg(windows)]
pub mod windows_lock;
#[cfg(windows)]
pub(crate) mod windows_prepare;
#[cfg(windows)]
pub mod windows_process_limit;
#[cfg(windows)]
pub mod windows_publish;
#[cfg(windows)]
pub mod windows_stage;
#[cfg(windows)]
pub mod windows_streams;
pub mod wire;
