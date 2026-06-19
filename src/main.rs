use std::net::SocketAddr;

use clap::Parser;
use pulsar_proto::DEFAULT_RELAY_PORT;
use pulsar_relay::{parse_rate, parse_size, Limits, Relay};
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

	/// Per-device forward-rate cap, e.g. `10mbit` / `2mb`. Default: unlimited.
	#[arg(long, env = "PULSAR_RELAY_USER_RATE")]
	user_rate: Option<String>,

	/// Per-device cumulative data cap, e.g. `5gb`. Default: unlimited.
	#[arg(long, env = "PULSAR_RELAY_USER_DATA")]
	user_data: Option<String>,

	/// Per-source-IP forward-rate cap, e.g. `50mbit`. Default: unlimited.
	#[arg(long, env = "PULSAR_RELAY_IP_RATE")]
	ip_rate: Option<String>,

	/// Per-source-IP cumulative data cap, e.g. `20gb`. Default: unlimited.
	#[arg(long, env = "PULSAR_RELAY_IP_DATA")]
	ip_data: Option<String>,

	/// Per-SESSION forward-rate cap, e.g. `10mbit`. Unlike `--user-rate`, this caps each
	/// relay session independently (two panes from one device each get the full budget), and
	/// is advertised to the client so its encoder starts within the cap. Default: unlimited.
	#[arg(long, env = "PULSAR_RELAY_SESSION_RATE")]
	session_rate: Option<String>,

	/// Per-session cumulative data cap, e.g. `2gb`. Default: unlimited.
	#[arg(long, env = "PULSAR_RELAY_SESSION_DATA")]
	session_data: Option<String>,
}

fn opt_rate(v: &Option<String>, what: &str) -> anyhow::Result<Option<u64>> {
	match v {
		Some(s) => {
			Ok(Some(parse_rate(s).ok_or_else(|| {
				anyhow::anyhow!("invalid {what} rate: {s:?}")
			})?))
		}
		None => Ok(None),
	}
}

fn opt_size(v: &Option<String>, what: &str) -> anyhow::Result<Option<u64>> {
	match v {
		Some(s) => {
			Ok(Some(parse_size(s).ok_or_else(|| {
				anyhow::anyhow!("invalid {what} size: {s:?}")
			})?))
		}
		None => Ok(None),
	}
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

	let limits = Limits {
		per_user_bps: opt_rate(&args.user_rate, "--user-rate")?,
		per_user_total: opt_size(&args.user_data, "--user-data")?,
		per_ip_bps: opt_rate(&args.ip_rate, "--ip-rate")?,
		per_ip_total: opt_size(&args.ip_data, "--ip-data")?,
		per_session_bps: opt_rate(&args.session_rate, "--session-rate")?,
		per_session_total: opt_size(&args.session_data, "--session-data")?,
	};
	let relay = Relay::bind(addr).await?.with_limits(limits);
	tracing::info!(%addr, ?limits, "pulsar-relay listening (UDP)");
	relay.run().await?;
	Ok(())
}
