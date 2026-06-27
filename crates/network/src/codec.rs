//! The libp2p request-response [`Codec`] for the `ubi2/sync/1` protocol (spec §4.2).
//!
//! It frames a `GetBlocks` request / `Blocks` response as a single length-prefixed binary message
//! (the same canonical [`crate::wire`] encodings used everywhere else). A `u32` big-endian length
//! prefix bounds the read so a malicious peer cannot make us allocate unboundedly
//! (`SYNC_MAX_BATCH`-bounded response on top, §4.2/AC-F8).

use std::io;

use futures::prelude::*;
use libp2p::request_response::Codec;

use crate::consts::{MAX_BLOCK_BYTES, SYNC_MAX_BATCH};
use crate::wire::{SyncRequest, SyncResponse};

/// The protocol id wrapper (request-response negotiates over the `AsRef<str>` protocol name).
#[derive(Debug, Clone)]
pub struct SyncProtocol(pub &'static str);

impl AsRef<str> for SyncProtocol {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// Hard ceiling on a single sync frame: a full `Blocks` batch of max-size blocks, plus framing slack.
/// Bounds the request-response read regardless of the claimed length prefix (anti-DoS).
const MAX_SYNC_FRAME: u64 = SYNC_MAX_BATCH * (MAX_BLOCK_BYTES as u64) + (1 << 20);

#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

async fn read_frame<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as u64;
    if len > MAX_SYNC_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sync frame exceeds MAX_SYNC_FRAME",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame<T>(io: &mut T, bytes: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    let len = bytes.len() as u32;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(bytes).await?;
    io.flush().await?;
    Ok(())
}

#[async_trait::async_trait]
impl Codec for SyncCodec {
    type Protocol = SyncProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_frame(io).await?;
        SyncRequest::decode(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_frame(io).await?;
        SyncResponse::decode(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &req.encode()).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &res.encode()).await
    }
}
