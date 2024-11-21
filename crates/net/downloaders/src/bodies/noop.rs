use alloy_primitives::BlockNumber;
use futures::Stream;
use reth_network_p2p::{
    bodies::{downloader::BodyDownloader, response::BlockResponse},
    error::{DownloadError, DownloadResult},
};
use reth_primitives_traits::BlockBody;
use std::ops::RangeInclusive;

/// A [`BodyDownloader`] implementation that does nothing.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct NoopBodiesDownloader<Body> {
    _phantom: std::marker::PhantomData<Body>,
}

impl<B> BodyDownloader for NoopBodiesDownloader<B>
where
    B: BlockBody + Send + Sync + 'static,
{
    type Body = B;

    fn set_download_range(&mut self, _: RangeInclusive<BlockNumber>) -> DownloadResult<()> {
        Ok(())
    }
}

impl<B> Stream for NoopBodiesDownloader<B>
where
    B: BlockBody + Send + Sync + 'static,
{
    type Item = Result<Vec<BlockResponse<B>>, DownloadError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        panic!("NoopBodiesDownloader shouldn't be polled.")
    }
}
