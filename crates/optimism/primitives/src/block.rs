use alloy_consensus::Header;
use alloy_eips::eip4895::Withdrawals;
use alloy_rlp::{RlpDecodable, RlpEncodable};
use reth_primitives_traits::InMemorySize;
use serde::{Deserialize, Serialize};

use crate::transaction::TransactionSigned;
/// OVM block, same as EVM block but with different transaction signature handling
/// Pre-bedrock system transactions on Optimism were sent from the zero address
/// with an empty signature,
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpDecodable, RlpEncodable,
)]
pub struct Block {
    /// Block header
    pub header: Header,
    /// Block body
    pub body: BlockBody,
}

//impl Block {
//    /// Decodes a `Block` from the given byte slice.
//    pub fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
//        let header = Header::decode(buf)?;
//        let body = BlockBody::decode(buf)?;
//        Ok(Self { header, body })
//    }
//}

impl InMemorySize for Block {
    /// Calculates a heuristic for the in-memory size of the [`Block`].
    #[inline]
    fn size(&self) -> usize {
        self.header.size() + self.body.size()
    }
}

impl reth_node_types::Block for Block {
    type Header = Header;
    type Body = BlockBody;

    fn header(&self) -> &Self::Header {
        &self.header
    }

    fn body(&self) -> &Self::Body {
        &self.body
    }
}

/// The body of a block for OVM
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, RlpDecodable, RlpEncodable,
)]
#[rlp(trailing)]
pub struct BlockBody {
    /// Transactions in the block
    pub transactions: Vec<TransactionSigned>,
    /// Uncle headers for the given block
    pub ommers: Vec<Header>,
    /// Withdrawals in the block.
    pub withdrawals: Option<Withdrawals>,
}

impl InMemorySize for BlockBody {
    /// Calculates a heuristic for the in-memory size of the [`BlockBody`].
    #[inline]
    fn size(&self) -> usize {
        self.transactions.iter().map(TransactionSigned::size).sum::<usize>() +
            self.transactions.capacity() * core::mem::size_of::<TransactionSigned>() +
            self.ommers.iter().map(Header::size).sum::<usize>() +
            self.ommers.capacity() * core::mem::size_of::<Header>() +
            self.withdrawals
                .as_ref()
                .map_or(core::mem::size_of::<Option<Withdrawals>>(), Withdrawals::total_size)
    }
}

impl reth_node_types::BlockBody for BlockBody {
    type Transaction = TransactionSigned;
    type Ommers = Header;
    type Withdrawals = Withdrawals;

    fn transactions(&self) -> &[Self::Transaction] {
        &self.transactions
    }

    fn ommers(&self) -> &[Header] {
        &self.ommers
    }

    fn withdrawals(&self) -> Option<Self::Withdrawals> {
        self.withdrawals.clone()
    }
}
