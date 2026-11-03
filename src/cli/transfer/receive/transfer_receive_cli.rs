use arbitrary::Arbitrary;
use facet::Facet;

/// Placeholder; receiving is disabled.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
pub struct TransferReceiveArgs;
