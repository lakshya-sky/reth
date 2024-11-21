use crate::DBProvider;
use alloy_consensus::Header;
use alloy_eips::eip4895::Withdrawals;
use alloy_primitives::BlockNumber;
use reth_db::{
    cursor::DbCursorRW,
    models::{StoredBlockOmmers, StoredBlockWithdrawals},
    tables,
    transaction::DbTxMut,
};
use reth_primitives_traits::{Block, BlockBody, FullNodePrimitives};
use reth_storage_errors::provider::ProviderResult;

/// Trait that implements how block bodies are written to the storage.
///
/// Note: Within the current abstraction, this should only write to tables unrelated to
/// transactions. Writing of transactions is handled separately.
#[auto_impl::auto_impl(&, Arc)]
pub trait BlockBodyWriter<Provider, Body: BlockBody> {
    /// Writes a set of block bodies to the storage.
    fn write_block_bodies(
        &self,
        provider: &Provider,
        bodies: Vec<(BlockNumber, Option<Body>)>,
    ) -> ProviderResult<()>;
}

/// Trait that implements how chain-specific types are written to the storage.
pub trait ChainStorageWriter<Provider, Primitives: FullNodePrimitives>:
    BlockBodyWriter<Provider, <Primitives::Block as Block>::Body>
{
}
impl<T, Provider, Primitives: FullNodePrimitives> ChainStorageWriter<Provider, Primitives> for T where
    T: BlockBodyWriter<Provider, <Primitives::Block as Block>::Body>
{
}

/// Ethereum storage implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct EthStorage;

impl<Provider, Body> BlockBodyWriter<Provider, Body> for EthStorage
where
    Provider: DBProvider<Tx: DbTxMut>,
    Body: BlockBody<Ommers = Header, Withdrawals = Withdrawals>,
{
    fn write_block_bodies(
        &self,
        provider: &Provider,
        bodies: Vec<(u64, Option<Body>)>,
    ) -> ProviderResult<()> {
        let mut ommers_cursor = provider.tx_ref().cursor_write::<tables::BlockOmmers>()?;
        let mut withdrawals_cursor =
            provider.tx_ref().cursor_write::<tables::BlockWithdrawals>()?;

        for (block_number, body) in bodies {
            let Some(body) = body else { continue };

            // Write ommers if any
            if !body.ommers().is_empty() {
                ommers_cursor
                    .append(block_number, StoredBlockOmmers { ommers: body.ommers().into() })?;
            }

            // Write withdrawals if any
            if let Some(withdrawals) = body.withdrawals() {
                if !withdrawals.is_empty() {
                    withdrawals_cursor
                        .append(block_number, StoredBlockWithdrawals { withdrawals })?;
                }
            }
        }

        Ok(())
    }
}
