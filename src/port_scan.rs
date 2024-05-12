use tokio::net::TcpStream;
use std::net::SocketAddr;
use std::time::Duration;


#[derive(Debug)]
pub enum PortStatus {
    OPEN,
    CLOSED
}

pub struct PortInformation {
    pub id: u16,
    pub status: PortStatus
}

pub async fn scan_port_tcp_connection(addr: SocketAddr, timeout: Duration) -> PortInformation {
    let stream = tokio::time::timeout(timeout, async move {
        TcpStream::connect(addr).await
    }).await;

    let status = {
        if stream.is_err() {
            PortStatus::CLOSED
        }
        else {
            PortStatus::OPEN
        }
    };

    let result = PortInformation {
        id: addr.port(),
        status
    };
    return result;
}
