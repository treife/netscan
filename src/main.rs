mod port_scan;
mod def;

use std::error::Error;
use std::time::Instant;
use clap::Parser;
use tokio;
use futures::stream::{self, StreamExt};
use std::net::{SocketAddr, IpAddr};

use crate::port_scan::{PortStatus, scan_port_tcp_connection};

#[derive(Clone, Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// host to scan
    host: String,
    /// all / top / comma-separated numbers
    #[arg(short, long, default_value_t=("top").to_string())]
    ports: String,
    /// batch size (bigger - faster scanning)
    #[arg(short, long, default_value_t=1024)]
    batch_size: usize,
    /// how long to wait if the host does not respond
    #[arg(short, long, default_value_t=("2s").to_string())]
    timeout: String
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let args = Args::parse();

    let scan_timeout = parse_duration::parse(&args.timeout).unwrap();
    let ports = match args.ports.as_str() {
      "all" => (1..65535).collect::<Vec<u16>>(),
      "top" => Vec::from(def::TOP_1K_PORTS),
      arg => {
          if arg.is_empty() {
              Vec::from(def::TOP_1K_PORTS)
          }
          else {
              arg.split(',').collect::<Vec<&str>>().into_iter().
                  map(|s_port| s_port.parse::<u16>().unwrap()).collect()
          }
      },
    };

    println!("Performing scan of {}", args.host);
    println!("Ports included in the scan: {}", args.ports);
    println!("Batch size: {}", args.batch_size);

    let now = Instant::now();

    let mut result = vec![];
    for batch in ports.chunks(args.batch_size) {
        let args_clone = args.clone();
        let ports = batch.to_vec();
        let task = tokio::spawn(async move {
            let mut streams = stream::iter(ports.into_iter().map(|port| {
                let ip = args_clone.host.parse::<IpAddr>().unwrap();
                let addr = SocketAddr::new(ip, port);
                async move {
                    let result = scan_port_tcp_connection(addr, scan_timeout).await;
                    result
                }
            })).buffer_unordered(args.batch_size);

            let mut results = Vec::new();
            while let Some(result) = streams.next().await {
                results.push(result)
            }
            results
        });

        result.push(task);
    }

    let mut all_results = Vec::new();
    for task in result {
        if let Ok(result) = task.await {
            all_results.extend(result);
        }
    }

    for port in all_results {
        if matches!(port.status, PortStatus::CLOSED) {
            continue;
        }

        println!("{}: {:?}", port.id, port.status);
    }

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);

    Ok(())
}
