use std::net::SocketAddr;

use clap::Parser;
use pulsar_proto::DEFAULT_RELAY_PORT;
use pulsar_relay::Relay;
use tracing_subscriber::EnvFilter;

/// Pulsar relay / rendezvous server.
#[derive(Parser, Debug)]
#[command(name = "pulsar-relay", version, about)]
struct Args {
	/// Full bind address `host:port` (overrides --host/--port).
	#[arg(long, env = "PULSAR_RELAY_BIND")]
	bind: Option<SocketAddr>,

	/// Host/interface to bind.
	#[arg(long, env = "PULSAR_RELAY_HOST", default_value = "0.0.0.0")]
	host: String,

	/// UDP port to listen on.
	#[arg(long, short, env = "PULSAR_RELAY_PORT", default_value_t = DEFAULT_RELAY_PORT)]
	port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(
			EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
		)
		.init();

	let args = Args::parse();
	let addr: SocketAddr = match args.bind {
		Some(a) => a,
		None => format!("{}:{}", args.host, args.port).parse()?,
	};

	let relay = Relay::bind(addr).await?;
	tracing::info!(%addr, "pulsar-relay listening (UDP)");
	relay.run().await?;
	Ok(())
}
