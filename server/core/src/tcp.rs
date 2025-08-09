use crate::config::TcpAddressInfo;
use haproxy_protocol::{ProxyHdrV1, ProxyHdrV2, RemoteAddress};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::fmt;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub(crate) enum ConnectionAddress {
    Unix,
    Tcp(SocketAddr)
}

impl fmt::Display for ConnectionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionAddress::Unix => write!(f, "unix://"),
            ConnectionAddress::Tcp(socket_address) => write!(f, "tcp://{socket_address}"),
        }
    }
}

pub(crate) async fn process_client_addr<S>(
    stream: S,
    connection_addr: ConnectionAddress,
    time_limit: Duration,
    trusted_tcp_info_ips: Arc<TcpAddressInfo>,
) -> Result<(S, SocketAddr), std::io::Error>
where
    S: tokio::io::AsyncReadExt + std::marker::Unpin,
{
    let ConnectionAddress::Tcp(connection_addr) = connection_addr else {
        // NOTE: To simply codepaths, we simply use IPv6 Localhost as the client ip
        //       for unix connections here.
        return Ok((stream, SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)));
    };

    let canonical_conn_addr = connection_addr.ip().to_canonical();

    let hdr_result = match trusted_tcp_info_ips.as_ref() {
        TcpAddressInfo::ProxyV2(trusted)
            if trusted
                .iter()
                .any(|ip_cidr| ip_cidr.contains(&canonical_conn_addr)) =>
        {
            debug!("processing proxy-v2 header");
            timeout(time_limit, ProxyHdrV2::parse_from_read(stream))
                .await
                .map(|ok_result| ok_result.map(|(stream, hdr)| (stream, hdr.to_remote_addr())))
        }
        TcpAddressInfo::ProxyV1(trusted)
            if trusted
                .iter()
                .any(|ip_cidr| ip_cidr.contains(&canonical_conn_addr)) =>
        {
            debug!("processing proxy-v1 header");
            timeout(time_limit, ProxyHdrV1::parse_from_read(stream))
                .await
                .map(|ok_result| ok_result.map(|(stream, hdr)| (stream, hdr.to_remote_addr())))
        }
        TcpAddressInfo::ProxyV2(_) | TcpAddressInfo::ProxyV1(_) => {
            debug!("Ignoring proxy headers from untrusted connection");
            return Ok((stream, connection_addr));
        }
        TcpAddressInfo::None => {
            // Not configured, ignore
            return Ok((stream, connection_addr));
        }
    };

    match hdr_result {
        Ok(Ok((stream, remote_addr))) => {
            let remote_socket_addr = match remote_addr {
                RemoteAddress::Local => {
                    debug!("PROXY protocol liveness check - will not contain client data");
                    // This is a check from the proxy, so just use the connection address.
                    connection_addr
                }
                RemoteAddress::TcpV4 { src, dst: _ } => SocketAddr::from(src),
                RemoteAddress::TcpV6 { src, dst: _ } => SocketAddr::from(src),
                remote_addr => {
                    error!(?remote_addr, "remote address in proxy header is invalid");
                    return Err(std::io::Error::from(ErrorKind::ConnectionAborted));
                }
            };

            Ok((stream, remote_socket_addr))
        }
        Ok(Err(err)) => {
            error!(?connection_addr, ?err, "Unable to process proxy header");
            Err(std::io::Error::from(ErrorKind::ConnectionAborted))
        }
        Err(_) => {
            error!(?connection_addr, "Timeout receiving proxy header");
            Err(std::io::Error::from(ErrorKind::TimedOut))
        }
    }
}
