//! Version-one Vox transfer contract for one approved transaction.
//!
//! An implementation must authenticate and bind every request to its locally
//! approved transaction and manifest; use protected staging and durable
//! journaling before publication. This trait by itself does none of those things.

use facet::Facet;
use vox::Rx;

/// Small, non-sensitive failure codes for a transfer request.
#[derive(Clone, Copy, Debug, Facet, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferError {
    Rejected,
    Expired,
    NotReady,
    Failed,
    /// Publication may have happened; local reconciliation is required.
    PublicationUncertain,
}

/// Status of the transfer transaction, not a durability guarantee.
#[derive(Clone, Copy, Debug, Facet, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferState {
    AwaitingBegin,
    Receiving,
    BodiesChecked,
    PublishedDurabilityUnconfirmed,
    Durable,
    Failed,
}

/// Remote operations for one previously approved version-one manifest.
/// The receiver binds these requests to locally approved identities and pins.
#[vox::service]
pub trait TransferWire {
    async fn begin(
        &self,
        version: u32,
        transaction_id: String,
        manifest_sha256: String,
    ) -> Result<(), TransferError>;

    async fn upload(
        &self,
        transaction_id: String,
        manifest_sha256: String,
        file_id: String,
        chunks: Rx<Vec<u8>>,
    ) -> Result<(), TransferError>;

    async fn status(
        &self,
        transaction_id: String,
        manifest_sha256: String,
    ) -> Result<TransferState, TransferError>;

    /// Retrieve a previously persisted receipt only in an explicitly approved,
    /// authenticated reconciliation window. Implementations must fail closed
    /// without a qualified local replay permit.
    async fn receipt(
        &self,
        transaction_id: String,
        manifest_sha256: String,
    ) -> Result<Vec<u8>, TransferError>;

    async fn commit(
        &self,
        transaction_id: String,
        manifest_sha256: String,
    ) -> Result<(), TransferError>;
}
