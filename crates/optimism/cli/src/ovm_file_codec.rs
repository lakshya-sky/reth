use alloy_primitives::bytes::{Buf, BytesMut};
use alloy_rlp::Decodable;
use derive_more::AsRef;
use reth_downloaders::file_client::FileClientError;
use reth_optimism_primitives::Block;
use tokio_util::codec::Decoder;

/// Specific codec for reading raw block bodies from a file
/// with optimism-specific signature handling
pub(crate) struct OvmBlockFileCodec;

impl Decoder for OvmBlockFileCodec {
    type Item = Block;
    type Error = FileClientError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        let buf_slice = &mut src.as_ref();
        let body =
            Block::decode(buf_slice).map_err(|err| FileClientError::Rlp(err, src.to_vec()))?;
        src.advance(src.len() - buf_slice.len());

        Ok(Some(body))
    }
}
