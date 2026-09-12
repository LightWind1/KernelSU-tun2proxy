//! Android root-TUN adapter.
//!
//! Android's /dev/tun character device can be opened and used by a root
//! process, but on some kernels it cannot be registered with epoll(2).
//! tun's normal AsyncDevice uses tokio::io::unix::AsyncFd, which fails with
//! EINVAL in that situation.  Keep the file descriptor on blocking worker
//! threads and expose the same AsyncRead/AsyncWrite interface to tun2proxy.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

type ReadResult = io::Result<Vec<u8>>;
type WriteResult = io::Result<usize>;

pub struct AndroidTun {
    reader: Arc<Mutex<File>>,
    writer: Arc<Mutex<File>>,
    pending_read: Option<JoinHandle<ReadResult>>,
    pending_write: Option<JoinHandle<WriteResult>>,
}

impl AndroidTun {
    /// Take ownership of the inherited TUN fd and duplicate it for full
    /// duplex blocking I/O. The process owns the descriptors until exit.
    pub fn new(fd: i32) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid TUN fd"));
        }

        // SAFETY: fd is supplied by the launcher and is valid at this point.
        let base = unsafe { File::from_raw_fd(fd) };
        let reader = base.try_clone()?;
        let writer = base;
        Ok(Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            pending_read: None,
            pending_write: None,
        })
    }

    fn join_error(err: tokio::task::JoinError) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("TUN worker failed: {err}"))
    }
}

impl AsyncRead for AndroidTun {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(handle) = self.pending_read.as_mut() {
                match Pin::new(handle).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        self.pending_read = None;
                        let packet = match result {
                            Ok(result) => result?,
                            Err(err) => return Poll::Ready(Err(Self::join_error(err))),
                        };
                        if packet.len() > buf.remaining() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "TUN packet exceeds read buffer",
                            )));
                        }
                        buf.put_slice(&packet);
                        return Poll::Ready(Ok(()));
                    }
                }
            }

            let reader = Arc::clone(&self.reader);
            self.pending_read = Some(tokio::task::spawn_blocking(move || {
                let mut packet = vec![0u8; 65536];
                let mut file = reader
                    .lock()
                    .map_err(|_| io::Error::other("TUN reader lock poisoned"))?;
                let len = file.read(&mut packet)?;
                packet.truncate(len);
                Ok(packet)
            }));
        }
    }
}

impl AsyncWrite for AndroidTun {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(handle) = self.pending_write.as_mut() {
            return match Pin::new(handle).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => {
                    self.pending_write = None;
                    match result {
                        Ok(result) => Poll::Ready(result),
                        Err(err) => Poll::Ready(Err(Self::join_error(err))),
                    }
                }
            };
        }

        let writer = Arc::clone(&self.writer);
        let packet = data.to_vec();
        self.pending_write = Some(tokio::task::spawn_blocking(move || {
            let mut file = writer
                .lock()
                .map_err(|_| io::Error::other("TUN writer lock poisoned"))?;
            file.write(&packet)
        }));
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
