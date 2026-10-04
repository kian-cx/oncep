use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub enum Observation {
    Connected { rtt: Duration },
    Refused { rtt: Duration },
    Timeout,
    Unreachable,
}

#[derive(Debug)]
pub enum LocalError {
    /// EMFILE, ENFILE, EAGAIN: the attempt goes back on the queue and does not spend budget.
    Resource,
}

pub trait Probe: Send + Sync {
    fn attempt<'a>(
        &'a self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Observation, LocalError>> + Send + 'a>>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TcpProbe;

impl Probe for TcpProbe {
    fn attempt<'a>(
        &'a self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Observation, LocalError>> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                Err(_) => Ok(Observation::Timeout),
                Ok(Ok(stream)) => {
                    drop(stream);
                    Ok(Observation::Connected {
                        rtt: start.elapsed(),
                    })
                }
                Ok(Err(err)) => map_io(err, start.elapsed()),
            }
        })
    }
}

fn map_io(err: std::io::Error, rtt: Duration) -> Result<Observation, LocalError> {
    match err.kind() {
        ErrorKind::ConnectionRefused => Ok(Observation::Refused { rtt }),
        ErrorKind::TimedOut => Ok(Observation::Timeout),
        ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::AddrNotAvailable => Ok(Observation::Unreachable),
        ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::OutOfMemory => {
            Err(LocalError::Resource)
        }
        _ => match err.raw_os_error() {
            // EMFILE, ENFILE, ENOBUFS, EAGAIN/EWOULDBLOCK (Linux and macOS).
            Some(24) | Some(23) | Some(55) | Some(11) | Some(35) => Err(LocalError::Resource),
            // EHOSTDOWN, EHOSTUNREACH, ENETUNREACH, EADDRNOTAVAIL, and the Linux equivalents.
            Some(64) | Some(65) | Some(51) | Some(49) | Some(101) | Some(113) | Some(112) => {
                Ok(Observation::Unreachable)
            }
            // ECONNREFUSED, in case the kind did not classify it.
            Some(61) | Some(111) => Ok(Observation::Refused { rtt }),
            _ => Err(LocalError::Resource),
        },
    }
}

/// Test probe: each address has a queue of observations.
#[derive(Clone, Default)]
pub struct ScriptedProbe {
    scripts: Arc<Mutex<HashMap<SocketAddr, VecDeque<Observation>>>>,
}

impl ScriptedProbe {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, addr: SocketAddr, obs: Observation) {
        self.scripts
            .lock()
            .expect("guion")
            .entry(addr)
            .or_default()
            .push_back(obs);
    }
}

impl Probe for ScriptedProbe {
    fn attempt<'a>(
        &'a self,
        addr: SocketAddr,
        _timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Observation, LocalError>> + Send + 'a>> {
        Box::pin(async move {
            let next = self
                .scripts
                .lock()
                .expect("guion")
                .get_mut(&addr)
                .and_then(|q| q.pop_front());
            Ok(next.unwrap_or(Observation::Timeout))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn localhost_open_is_connected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((sock, _)) = listener.accept().await {
                    drop(sock);
                }
            }
        });
        let obs = TcpProbe.attempt(addr, Duration::from_secs(1)).await.unwrap();
        assert!(matches!(obs, Observation::Connected { .. }));
    }

    #[tokio::test]
    async fn localhost_closed_is_refused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let obs = TcpProbe.attempt(addr, Duration::from_secs(1)).await.unwrap();
        assert!(matches!(obs, Observation::Refused { .. }));
    }
}
