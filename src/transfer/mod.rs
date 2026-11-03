//! Building blocks for the reviewed transfer design.
//!
//! No network listener, sender, receiver, or file execution is provided yet.

pub mod journal;
pub mod journal_file;
pub mod manifest;
pub mod proxy;
#[cfg(test)]
mod receiver_model;
pub mod recovery;
#[cfg(any(windows, target_os = "linux"))]
pub mod sender;
pub mod session;
#[cfg(any(windows, target_os = "linux"))]
mod source;
pub mod tls;
#[cfg(windows)]
pub mod transaction_journal;
pub mod verified_stream;
pub mod vox_transport;
#[cfg(windows)]
pub mod windows_lock;
pub mod wire;
