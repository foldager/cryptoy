use clap::Clap;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use anyhow::{Context, Result};

#[derive(Clap, Debug)]
#[clap(version = "0.0.0", author = "Jesper Foldager")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap, Debug)]
enum SubCommand {
    Encrypt(EncryptOpts),
    Decrypt(DecryptOpts),
    GenerateKey(GenerateKeyOpts),
}

#[derive(Clap, Debug)]
struct EncryptOpts {
    #[clap(short, long, parse(from_os_str))]
    key: PathBuf,

    #[clap(short, long, parse(from_os_str))]
    input: PathBuf,

    #[clap(short, long, parse(from_os_str))]
    output: PathBuf,
}
#[derive(Clap, Debug)]
struct DecryptOpts {
    #[clap(short, long, parse(from_os_str))]
    key: PathBuf,

    #[clap(short, long, parse(from_os_str))]
    input: PathBuf,

    #[clap(short, long, parse(from_os_str))]
    output: PathBuf,
}

#[derive(Clap, Debug)]
struct GenerateKeyOpts {
    #[clap(short, long, parse(from_os_str))]
    key: PathBuf,
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Encrypt(opts) => encrypt(opts)?,
        SubCommand::Decrypt(opts) => {
            decrypt(opts)?;
        }
        SubCommand::GenerateKey(opts) => {
            generate_key(opts)?;
        }
    }
    Ok(())
}

fn read<P>(path: P) -> Result<Vec<u8>>
where
    P: AsRef<Path>,
{
    let p: &Path = path.as_ref();
    fs::read(p).context(format!("Error reading {}", p.to_string_lossy()))
}

fn encrypt(opts: EncryptOpts) -> Result<()> {
    println!("Encrypting ...");
    let plaintext = read(&opts.input)?;
    let key = read(opts.key)?;
    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
    let mut rng = StdRng::from_entropy();
    let nonce: [u8; 12] = rng.gen();
    let nonce = GenericArray::from(nonce);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .context("Error encrypting")?;

    let mut f = File::create(&opts.output).context(format!(
        "unable to open output file {}",
        opts.output.to_string_lossy()
    ))?;
    f.write_all(&nonce).expect("write err");
    f.write_all(&ciphertext).expect("write err");
    Ok(())
}

fn decrypt(opts: DecryptOpts) -> Result<()> {
    println!("Decrypting ...!");
    let ciphermsg =
        fs::read(&opts.input).context(format!("Error reading {}", opts.input.to_string_lossy()))?;
    let nonce = GenericArray::from_slice(&ciphermsg[0..12]);
    let ciphertext = &ciphermsg[12..];
    let key =
        fs::read(opts.key).context(format!("Error reading {}", opts.input.to_string_lossy()))?;
    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
    let msg = cipher
        .decrypt(nonce, ciphertext)
        .context("Authenticated decryption failed. Message or key is incorrect")?;

    println!("secret: {}", std::str::from_utf8(&msg)?);
    fs::write(&opts.output, msg)
        .context(format!("Error writing {}", opts.output.to_string_lossy()))?;
    Ok(())
}

fn generate_key(opts: GenerateKeyOpts) -> Result<()> {
    let mut key = [0u8; 32];
    let mut rng = StdRng::from_entropy();
    rng.fill(&mut key);
    fs::write(&opts.key, &key).context(format!(
        "error saving key to {}",
        opts.key.to_string_lossy()
    ))?;
    Ok(())
}
