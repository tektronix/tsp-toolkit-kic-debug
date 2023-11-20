use clap::{arg, command, Args, Command, FromArgMatches, Parser, Subcommand};
use kic_debug::debugger::Debugger;
use std::ffi::OsString;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::Arc;
use tsp_instrument::instrument::{Instrument, State};
use tsp_instrument::interface::async_stream::AsyncStream;
use tsp_instrument::Interface;

use chrono::{DateTime, NaiveDateTime, Utc};
use directories::UserDirs;
use machineid_rs::HWIDComponent;
use machineid_rs::{Encryption, IdBuilder};
pub type GenericError = Box<dyn std::error::Error + Send + Sync>;
use ring::hmac;
use std::io::BufReader;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, Write},
    path::Path,
};

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

    /// Perform the given action over a USBTMC connection.
    Usb(UsbConnectArgs),
}

#[derive(Debug, Args)]
struct LanConnectArgs {
    ///The port on which to connect to the instrument.
    #[arg(long, short = 'p', name = "lan_port")]
    port: Option<u16>,

    /// The IP address of the instrument to connect to.
    ip_addr: OsString,
}

#[derive(Debug, Args)]
struct UsbConnectArgs {
    /// The instrument address in the form of, for example, `05e6:2461:3`, where the
    /// first part is the vendor id, the second part is the product id, and the third
    /// part is the USB address on the bus.
    addr: OsString,
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

    eprintln!("Keithley Instruments Script Debugger");

    let mut lm = LicenseManager::new();
    lm.init_license();
    lm.register();
    let is_trial_available = lm.is_trial_active();
    if !is_trial_available {
        println!("Debugger cannot be started.");
        return Ok(());
    }

    let mut debugger = match sub {
        SubCli::Lan(args) => {
            let addr: Ipv4Addr = args.ip_addr.to_str().unwrap().parse().unwrap();
            let port = args.port.unwrap_or(5025);
            println!("Connecting to {:?}:{:?}...", addr, port);
            let socket_addr = SocketAddr::V4(SocketAddrV4::new(addr, port));
            let lan: Arc<dyn Interface + Send + Sync> = Arc::new(TcpStream::connect(socket_addr)?);
            let lan: Box<dyn Interface> = Box::new(AsyncStream::try_from(lan)?);
            let mut instrument: Box<dyn Instrument> = lan.try_into()?;
            let check_log = instrument.check_login()?;
            if check_log == State::Needed {
                eprintln!("Enter the instrument password to unlock:");
                let password = rpassword::prompt_password("")?;
                instrument.login(password.as_bytes())?;
                let check_log_again = instrument.check_login()?;
                if check_log_again == State::Needed {
                    eprintln!("Password is incorrect");
                }
            } else if check_log == State::LogoutNeeded {
                println!("Another interface has control, LOGOUT on that interface.");
            }
            Debugger::new(instrument)
        }
        SubCli::Usb(_args) => todo!(),
    };

    Ok(debugger.start()?)
}

enum TrialStatus {
    Expired,
    Tampered,
    Available,
    Unknown,
}
struct License {
    trial_start_date: DateTime<Utc>,
    trial_status: TrialStatus,
}

impl License {
    fn new() -> Self {
        Self {
            trial_start_date: DateTime::<Utc>::MIN_UTC,
            trial_status: TrialStatus::Unknown,
        }
    }
}

struct KeyGen {
    hw_key: ring::hmac::Key,
}
impl KeyGen {
    fn new() -> Self {
        let mut builder = IdBuilder::new(Encryption::SHA256);
        builder.add_component(HWIDComponent::SystemID);
        let hwid = builder.build("ktt").unwrap();

        Self {
            hw_key: hmac::Key::new(hmac::HMAC_SHA256, hwid.as_bytes()),
        }
    }

    pub fn verify(&mut self, signature: &str, message: &str) -> bool {
        let decoded = hex::decode(signature).unwrap();
        let decoding_result = hmac::verify(&self.hw_key, message.as_bytes(), &decoded);
        matches!(decoding_result, core::result::Result::Ok(()))
    }

    pub fn get_new_key(&mut self, msg: String) -> String {
        let sign = hmac::sign(&self.hw_key, msg.as_bytes());
        hex::encode(sign)
    }
}
struct LicenseManager {
    trial_license: License,
    //trial_file: String,
}

impl LicenseManager {
    const TRIAL_DAYS: i64 = 90;
    const DATE_FORMAT: &'static str = "%d/%m/%Y %T";
    const KEY_FILE: &'static str = "key.txt";

    pub fn new() -> Self {
        Self {
            trial_license: License::new(),
        }
    }

    fn get_trial_key(&mut self) -> String {
        let dir = UserDirs::new().expect("directory not found");
        let path = dir.public_dir().unwrap();
        let buf = path.join(Path::new("Keithley\\TSPToolkit"));
        let _ = fs::create_dir_all(&buf);
        let p = buf.join(LicenseManager::KEY_FILE);
        let output: String = p.into_os_string().into_string().unwrap();
        output
    }

    pub fn init_license(&mut self) {
        let key_file = self.get_trial_key();
        let path = Path::new(&key_file);
        if !path.exists() {
            self.register();
        }
        let file_line = self.read_file_line(key_file);
        if !file_line.is_empty() {
            let clumps: Vec<&str> = file_line.split(',').collect();
            if clumps.len() != 3 {
                self.trial_license = License {
                    trial_start_date: Utc::now(),
                    trial_status: TrialStatus::Tampered, //File tampered
                };
                println!("Trial tampered! : File issue");
                return;
            }

            let mut kg = KeyGen::new();
            let msg = format!("{},{}", clumps[1], clumps[2]);
            let is_decoded = kg.verify(clumps[0], msg.as_str());

            if is_decoded {
                let trial_start = self.get_date(clumps[1]);
                let trial_since = Utc::now().signed_duration_since(trial_start);
                let mut status = TrialStatus::Available;
                if LicenseManager::TRIAL_DAYS - trial_since.num_days() < 1 {
                    status = TrialStatus::Expired;
                }

                let prev_start_date = self.get_date(clumps[2]);
                let login_since = Utc::now().signed_duration_since(prev_start_date);

                if login_since.num_days() < 0 {
                    status = TrialStatus::Tampered; //Date tampered
                                                    //println!("Trial tampered! : {}", login_since.num_days());
                }

                self.trial_license = License {
                    trial_start_date: trial_start,
                    trial_status: status,
                };

                if matches!(self.trial_license.trial_status, TrialStatus::Tampered) {
                    self.update_key();
                }
            } else {
                self.trial_license = License {
                    trial_start_date: Utc::now(),
                    trial_status: TrialStatus::Tampered, //File tampered
                };
                println!("Trial tampered! : File issue.",);
            }
        }
    }

    fn get_date(&self, literal: &str) -> DateTime<Utc> {
        let naive_time = NaiveDateTime::parse_from_str(literal, "%d/%m/%Y %H:%M:%S");
        naive_time.unwrap().and_utc()
    }

    fn read_file_line(&mut self, filename: String) -> String {
        let file = File::open(filename);
        match file {
            std::result::Result::Ok(the_file) => {
                let mut reader = BufReader::new(the_file);
                let mut first_line = String::new();
                let _ = reader.read_line(&mut first_line);
                if first_line.is_empty() {
                    first_line = "\n".to_string();
                }
                first_line
            }
            Err(_) => String::new(),
        }
    }

    pub fn is_trial_active(&mut self) -> bool {
        let mut is_active = false;
        match self.trial_license.trial_status {
            TrialStatus::Expired => println!("Trial has expired!"),
            TrialStatus::Tampered => println!("Trial is tampered with!"),
            TrialStatus::Available => {
                println!("Trial is available!");
                is_active = true
            }
            TrialStatus::Unknown => println!("Trial is not registered!"),
        }
        is_active
    }

    pub fn register(&mut self) {
        match self.trial_license.trial_status {
            TrialStatus::Unknown => {
                //Register new trial
                let current_time = Utc::now();
                self.trial_license = License {
                    trial_start_date: current_time,
                    trial_status: TrialStatus::Available,
                };
                self.update_key();
            }
            TrialStatus::Expired => (),
            TrialStatus::Tampered => (),
            TrialStatus::Available => (),
        }
    }

    fn update_key(&mut self) {
        let mut kg = KeyGen::new();
        let current_time = Utc::now();
        let current_time_string = current_time.format(LicenseManager::DATE_FORMAT);
        let register_time = self
            .trial_license
            .trial_start_date
            .format(LicenseManager::DATE_FORMAT);
        let msg = format!("{},{}", register_time, current_time_string);
        let msg_copy = msg.clone();
        let key = kg.get_new_key(msg);
        self.write_key_to_file(format!("{},{}", key, msg_copy).to_string());
    }

    fn write_key_to_file(&mut self, input: String) {
        let key_file = self.get_trial_key();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(key_file)
            .unwrap();
        if let Err(e) = write!(file, "{}", input) {
            eprintln!("Could not write to file: {}.", e);
        }
    }
}
