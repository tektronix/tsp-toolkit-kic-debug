use anyhow::Error;
use clap::{arg, command, Args, Command, FromArgMatches, Parser, Subcommand};
use kic_debug::debugger::Debugger;
use kic_debug::error::DebugError;
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::Arc;
use tsp_toolkit_kic_lib::instrument::{self, Instrument, State};
use tsp_toolkit_kic_lib::interface::async_stream::AsyncStream;
use tsp_toolkit_kic_lib::Interface;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    conn: SubCli,
}

#[derive(Debug, Subcommand)]
enum SubCli {
    /// Perform the given action over a LAN connection.
    Lan(LanConnectArgs),
}

#[derive(Debug, Args)]
struct LanConnectArgs {
    ///The port on which to connect to the instrument.
    #[arg(long, short = 'p', name = "lan_port")]
    port: Option<u16>,

    /// The IP address of the instrument to connect to.
    ip_addr: OsString,
}

fn main() -> anyhow::Result<()> {
    let cmd = command!()
        .propagate_version(true)
        .subcommand_required(true)
        .allow_external_subcommands(true);

    let cmd = SubCli::augment_subcommands(cmd);
    let cmd = cmd.subcommand(Command::new("print-description").hide(true));
    let matches = cmd.clone().get_matches();

    if let Some(("print-description", _)) = matches.subcommand() {
        println!("{}", cmd.get_about().unwrap_or_default());
        return Ok(());
    }

    let sub = SubCli::from_arg_matches(&matches)
        .map_err(|err| err.exit())
        .unwrap();

    let mut debugger = match sub {
        SubCli::Lan(args) => {
            let addr: Ipv4Addr = args.ip_addr.to_str().unwrap().parse().unwrap();
            let port = args.port.unwrap_or(5025);
            let socket_addr = SocketAddr::V4(SocketAddrV4::new(addr, port));
            let lan: Arc<dyn Interface + Send + Sync> = Arc::new(TcpStream::connect(socket_addr)?);
            let lan: Box<dyn Interface> = Box::new(AsyncStream::try_from(lan)?);
            let mut instrument: Box<dyn Instrument> = lan.try_into()?;
            //FIXME: This code will automatically exit if the instrument requires a login.
            //       If/when the debugger extension supports login, this should be removed.
            let inst_login_state = instrument.check_login()?;
            match inst_login_state {
                State::Needed | State::LogoutNeeded => {
                    return Err(Error::from(DebugError::InstrumentPasswordProtected));
                }
                State::NotNeeded => {}
            }
            //FIXME: This code will automatically exit if the instrument is using the
            //       wrong language mode. If/when the debugger extension supports user
            //       prompts, this should be removed. (See the implementation in
            //       tsp-toolkit-kic-cli for reference.)
            match instrument.as_mut().get_language()? {
                instrument::CmdLanguage::Scpi => {
                    return Err(DebugError::InstrumentLanguageError.into())
                }
                instrument::CmdLanguage::Tsp => {}
            }

            Debugger::new(instrument)
        }
    };

    Ok(debugger.start()?)
}
