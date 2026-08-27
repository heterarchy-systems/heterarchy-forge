//! Bounded JSON-RPC frame ingress for the rmcp line transport.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};

/// Maximum JSON-RPC frame payload bytes between newline delimiters.
pub const MAX_MCP_FRAME_BYTES: usize = 64 * 1024;
const SCRATCH_BYTES: usize = 8 * 1024;

/// Safe-Rust reader wrapper enforcing a bounded line/frame before rmcp's
/// `AsyncRwTransport` copies bytes into its internal line buffer.
///
/// The counter records payload bytes since the last `\n`; delimiters reset it.
/// At exactly the limit, one further byte is inspected: a newline is accepted
/// and resets the counter, while any other byte returns `InvalidData` without
/// copying that byte to the caller.  A fixed scratch buffer prevents this
/// boundary from allocating based on remote input size.
pub struct BoundedMcpFrameReader<R> {
    inner: R,
    frame_bytes: usize,
}

impl<R> fmt::Debug for BoundedMcpFrameReader<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedMcpFrameReader")
            .field("frame_bytes", &self.frame_bytes)
            .finish_non_exhaustive()
    }
}

impl<R> BoundedMcpFrameReader<R> {
    pub const fn new(inner: R) -> Self {
        Self {
            inner,
            frame_bytes: 0,
        }
    }

    pub const fn frame_bytes(&self) -> usize {
        self.frame_bytes
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R> AsyncRead for BoundedMcpFrameReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if destination.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let available = if self.frame_bytes >= MAX_MCP_FRAME_BYTES {
            1
        } else {
            (MAX_MCP_FRAME_BYTES - self.frame_bytes)
                .min(SCRATCH_BYTES)
                .min(destination.remaining())
        };
        let mut scratch = [0_u8; SCRATCH_BYTES];
        let mut scratch_read = ReadBuf::new(&mut scratch[..available]);
        match Pin::new(&mut self.inner).poll_read(context, &mut scratch_read) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let filled = scratch_read.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(()));
                }

                let mut next_frame_bytes = self.frame_bytes;
                for byte in filled {
                    if *byte == b'\n' {
                        next_frame_bytes = 0;
                    } else {
                        if next_frame_bytes >= MAX_MCP_FRAME_BYTES {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "MCP JSON-RPC frame exceeds the bounded ingress limit",
                            )));
                        }
                        next_frame_bytes += 1;
                    }
                }
                destination.put_slice(filled);
                self.frame_bytes = next_frame_bytes;
                Poll::Ready(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::error::Error;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

    use super::{BoundedMcpFrameReader, MAX_MCP_FRAME_BYTES};

    #[derive(Debug)]
    struct ChunkReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl ChunkReader {
        fn new(chunks: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into_iter().collect(),
            }
        }
    }

    impl AsyncRead for ChunkReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            destination: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let Some(mut chunk) = self.chunks.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            let amount = chunk.len().min(destination.remaining());
            destination.put_slice(&chunk[..amount]);
            if amount < chunk.len() {
                chunk.drain(..amount);
                self.chunks.push_front(chunk);
            }
            Poll::Ready(Ok(()))
        }
    }

    async fn read_all<R>(reader: R) -> Result<Vec<u8>, Box<dyn Error>>
    where
        R: AsyncRead + Unpin,
    {
        let mut reader = BoundedMcpFrameReader::new(reader);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await?;
        Ok(output)
    }

    #[tokio::test]
    async fn partial_chunks_preserve_frame_count_and_reset_after_newline()
    -> Result<(), Box<dyn Error>> {
        let output = read_all(ChunkReader::new([
            b"ab".to_vec(),
            b"c\n".to_vec(),
            b"de\n".to_vec(),
        ]))
        .await?;
        assert_eq!(output, b"abc\nde\n");
        Ok(())
    }

    #[tokio::test]
    async fn exactly_max_payload_is_accepted() -> Result<(), Box<dyn Error>> {
        let mut input = vec![b'a'; MAX_MCP_FRAME_BYTES];
        input.push(b'\n');
        let output = read_all(ChunkReader::new([input])).await?;
        assert_eq!(output.len(), MAX_MCP_FRAME_BYTES + 1);
        Ok(())
    }

    #[tokio::test]
    async fn max_plus_one_payload_is_rejected_before_extra_copy() -> Result<(), Box<dyn Error>> {
        let input = vec![b'a'; MAX_MCP_FRAME_BYTES + 1];
        let mut reader = BoundedMcpFrameReader::new(ChunkReader::new([input]));
        let mut output = Vec::new();
        let Err(error) = reader.read_to_end(&mut output).await else {
            return Err(io::Error::other("oversized frame was accepted").into());
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(output.len(), MAX_MCP_FRAME_BYTES);
        assert_eq!(reader.frame_bytes(), MAX_MCP_FRAME_BYTES);
        Ok(())
    }

    #[tokio::test]
    async fn multiple_lines_keep_retained_counter_bounded() -> Result<(), Box<dyn Error>> {
        let input = (0..32)
            .map(|_| vec![b'x'; 2_048])
            .flat_map(|mut line| {
                line.push(b'\n');
                line
            })
            .collect::<Vec<_>>();
        let mut reader = BoundedMcpFrameReader::new(ChunkReader::new([input]));
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await?;
        assert_eq!(reader.frame_bytes(), 0);
        assert!(output.len() <= (2_049 * 32));
        Ok(())
    }
}
