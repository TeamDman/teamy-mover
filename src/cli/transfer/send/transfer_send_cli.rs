use arbitrary::Arbitrary;
use facet::Facet;

/// Placeholder; sending is disabled.
#[derive(Facet, Arbitrary, Debug, PartialEq)]
pub struct TransferSendArgs;
