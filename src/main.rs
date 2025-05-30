use anyhow::Error;
use clap::{arg, command, Args, Command, FromArgMatches, Parser, Subcommand};
use kic_debug::debugger::Debugger;
use kic_debug::error::DebugError;
use std::ffi::OsString;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::Arc;
use tsp_toolkit_kic_lib::instrument::{self, Instrument, State};
use tsp_toolkit_kic_lib::interface::async_stream::AsyncStream;
use tsp_toolkit_kic_lib::Interface;

use chrono::{DateTime, NaiveDateTime, Utc};
use directories::{BaseDirs, UserDirs};
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

use steganography::decoder::*;
use steganography::encoder::*;
use steganography::util::*;

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

    let mut lm = LicenseManager::new();
    lm.init_license();
    lm.register();
    let is_trial_available = lm.is_trial_active();
    if !is_trial_available {
        return Err(Error::from(DebugError::DebugLicenseRejection {
            reason: "trail license is not active.".to_string(),
        }));
    }

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

#[derive(PartialEq)]
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

    fn get_cross_verification_key_file(&mut self) -> String {
        let dir = BaseDirs::new().expect("directory not found");
        let path = dir.cache_dir();
        let mut kg = KeyGen::new();
        let key = kg.get_new_key("crossKey".to_string());
        let full_key = path.join(Path::new(&key[..8]));
        let output: String = full_key.into_os_string().into_string().unwrap();
        output
    }

    pub fn init_license(&mut self) {
        let key_file = self.get_trial_key();
        let path = Path::new(&key_file);
        let does_key_file_exist = path.exists();
        let is_cross_verified = self.is_cross_verification_successful(does_key_file_exist);

        if !is_cross_verified {
            self.trial_license = License {
                trial_start_date: Utc::now(),
                trial_status: TrialStatus::Tampered, //File tampered
            };
            println!("Trial tampered : Verification failed");
            return;
        }
        if !does_key_file_exist {
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
                println!("Trial tampered : File issue");
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

                if self.trial_license.trial_status != TrialStatus::Tampered {
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
        let msg = format!("{register_time},{current_time_string}");
        let msg_copy = msg.clone();
        let key = kg.get_new_key(msg);
        self.write_key_to_file(format!("{key},{msg_copy}").to_string());
    }

    fn is_cross_verification_successful(&mut self, is_trial_key_found: bool) -> bool {
        let mut kg = KeyGen::new();
        let cross_verification_key_file = self.get_cross_verification_key_file();
        let filename = format!("{cross_verification_key_file}.png").to_string();
        let cross_verification_path = Path::new(&filename);
        let does_cross_verification_key_exist = cross_verification_path.exists();

        let message = kg.get_new_key("trial".to_string());
        if !does_cross_verification_key_exist && !is_trial_key_found {
            //This is probably the first time trial verification is happening

            let payload = str_to_bytes(&message);

            let img_to_embed = include_bytes!("resources/keyI.png");

            let destination_image = image::load_from_memory(img_to_embed).unwrap();

            //Encode info into image
            let enc = Encoder::new(payload, destination_image);
            let result = enc.encode_alpha();
            save_image_buffer(result, filename);

            return true;
        }

        if is_trial_key_found {
            if !does_cross_verification_key_exist {
                return false; //Image to decode is not found
            }
            let encoded_image = file_as_image_buffer(filename);
            //Create a decoder
            let dec = Decoder::new(encoded_image);
            //Decode the image by reading the alpha channel
            let out_buffer = dec.decode_alpha();
            //If there is no alpha, it's set to 255 by default so we filter those out
            let clean_buffer: Vec<u8> = out_buffer.into_iter().filter(|b| *b != 0xff_u8).collect();
            //Convert those bytes into a string we can read
            let found_key = bytes_to_str(clean_buffer.as_slice());

            return found_key == message;
        }
        false
    }

    fn write_key_to_file(&mut self, input: String) {
        let key_file = self.get_trial_key();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(key_file)
            .unwrap();
        if let Err(e) = write!(file, "{input}") {
            eprintln!("Could not write to file: {e}.");
        }
    }
}
