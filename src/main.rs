//! Command-line front end. All Bitcoin logic lives in the library crate; this
//! file only parses arguments, reads and writes files, and reports errors.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::Network;
use clap::{Parser, Subcommand};

use btc_offline_signer::builder::build_unsigned;
use btc_offline_signer::key::SigningKey;
use btc_offline_signer::params::{parse_network, SpendRequest};
use btc_offline_signer::review::Review;
use btc_offline_signer::signer::sign;
use btc_offline_signer::InputKind;

/// Environment variable that may hold the WIF private key.
const KEY_ENV: &str = "BTC_SIGNER_WIF";

/// Any error, as long as it can be printed. Good enough for a CLI's top level.
type CliResult<T> = Result<T, Box<dyn Error>>;

/// Build and sign Bitcoin transactions offline.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The three things the tool can do. Each field becomes a command-line
/// option, and each `///` comment becomes its `--help` text.
#[derive(Subcommand)]
enum Command {
    /// Create a new private key file and print its native SegWit address
    Keygen {
        /// mainnet, testnet, testnet4, signet or regtest
        #[arg(long, value_parser = parse_network)]
        network: Network,
        /// Where to write the new key (WIF). Must not exist yet
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Print an address of a private key
    Address {
        /// mainnet, testnet, testnet4, signet or regtest
        #[arg(long, value_parser = parse_network)]
        network: Network,
        /// Which of the key's addresses: p2pkh, p2sh, p2wpkh or p2tr
        #[arg(long = "type", short = 't', default_value_t)]
        kind: InputKind,
        /// File containing the WIF private key [default: $BTC_SIGNER_WIF]
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Build and sign the transaction described by a params file
    Sign {
        /// JSON file describing the UTXOs to spend and whom to pay
        params: PathBuf,
        /// File containing the WIF private key [default: $BTC_SIGNER_WIF]
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Write the transaction hex to this file instead of stdout
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

/// Entry point. Runs the chosen command and turns its result into an exit
/// code: 0 for success, 1 for failure with the reason on stderr.
fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Sends each subcommand to the function that carries it out.
fn run(cli: Cli) -> CliResult<()> {
    match cli.command {
        Command::Keygen { network, key_file } => keygen(network, &key_file),
        Command::Address {
            network,
            kind,
            key_file,
        } => {
            let key = load_key(key_file.as_deref(), network)?;
            println!("{}", key.owner().address(kind));
            Ok(())
        }
        Command::Sign {
            params,
            key_file,
            output,
        } => sign_command(&params, key_file.as_deref(), output.as_deref()),
    }
}

/// `keygen`: makes a new random key, saves it, and prints where to send coins.
fn keygen(network: Network, key_file: &Path) -> CliResult<()> {
    let key = SigningKey::generate(network);
    write_secret(key_file, &key.to_wif())?;

    // The note goes to stderr so that stdout holds only the address.
    eprintln!("private key written to {}", key_file.display());
    println!("{}", key.owner().address(InputKind::default()));
    Ok(())
}

/// `sign`: the whole pipeline, in order. Any step that fails stops the rest
/// (that is what each `?` does), so nothing is printed to stdout on error.
fn sign_command(params: &Path, key_file: Option<&Path>, output: Option<&Path>) -> CliResult<()> {
    // 1. Read and validate the params file.
    let request = SpendRequest::from_json(&read_file(params)?)?;
    // 2. Load the key, checking it is for the same network as the params.
    let key = load_key(key_file, request.network())?;

    // 3. Decide outputs, fee and change. Only the public half is passed in.
    let unsigned = build_unsigned(&request, key.owner())?;

    // 4. Show where the money goes. Everything except the hex goes to
    // stderr, so stdout can be piped. The review is what the user should
    // read before broadcasting.
    eprint!("{}", Review::new(&unsigned, request.network()));

    // 5. Sign, and encode the result as the hex string a node accepts.
    let tx = sign(unsigned, &key)?;
    let hex = serialize_hex(&tx);
    eprintln!("size:     {:>10} vB", tx.vsize());
    eprintln!("txid:     {}", tx.compute_txid());

    // 6. Deliver the hex: to a file if one was asked for, otherwise stdout.
    match output {
        Some(path) => fs::write(path, format!("{hex}\n"))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?,
        None => println!("{hex}"),
    }
    Ok(())
}

/// Reads the WIF from `key_file`, or from the environment when no file is given.
fn load_key(key_file: Option<&Path>, network: Network) -> CliResult<SigningKey> {
    let wif = match key_file {
        Some(path) => read_file(path)?,
        None => std::env::var(KEY_ENV)
            .map_err(|_| format!("no private key: pass --key-file or set {KEY_ENV}"))?,
    };
    Ok(SigningKey::from_wif(&wif, network)?)
}

/// Reads a whole text file, naming the file in the error if it cannot be read.
fn read_file(path: &Path) -> CliResult<String> {
    fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()).into())
}

/// Creates `path` (failing if it already exists, so a key is never overwritten)
/// readable by the current user only, and writes `secret` to it.
fn write_secret(path: &Path, secret: &str) -> CliResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    writeln!(file, "{secret}")?;
    Ok(())
}
