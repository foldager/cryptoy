use std::fs::{self, File};
use std::io::{Write};
use std::path::PathBuf;
use rand::{rngs::StdRng, Rng, SeedableRng};
use clap::Clap;

use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::aead::{Aead, NewAead, generic_array::GenericArray};

#[derive(Clap, Debug)]
#[clap(version = "0.0.0", author = "Jesper Foldager")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand
}

#[derive(Clap, Debug)]
enum SubCommand {
    Encrypt(EncryptOpts),
    Decrypt(DecryptOpts),
    GenerateKey(GenerateKeyOpts)
}

#[derive(Clap, Debug)]
struct EncryptOpts{
    #[clap(short, long, parse(from_os_str))]
    key: PathBuf,

    #[clap(short, long, parse(from_os_str))]
    input: PathBuf,

    #[clap(short, long, parse(from_os_str))]
    output: PathBuf
}
#[derive(Clap, Debug)]
struct DecryptOpts{
    #[clap(short, long, parse(from_os_str))]
    key: PathBuf,

    #[clap(short, long, parse(from_os_str))]
    input: PathBuf,

    #[clap(short, long, parse(from_os_str))]
    output: PathBuf
}

#[derive(Clap, Debug)]
struct GenerateKeyOpts{
    #[clap(short, long, parse(from_os_str))]
    key: PathBuf
}


fn main() {
    let opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Encrypt(opts) => {
            println!("Encrypting ...");
            let plaintext = fs::read(opts.input).expect("failed reading plain text");
            let key = fs::read(opts.key).expect("failed reading key");
            let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
            let mut rng = StdRng::from_entropy();
            let nonce: [u8; 12] = rng.gen();
            let nonce = GenericArray::from(nonce);
            let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).expect("Error encrypting");

            
            let mut f = File::create(opts.output).expect("unable to open output file");
            f.write_all(&nonce).expect("write err");
            f.write_all(&ciphertext).expect("write err");

        },
        SubCommand::Decrypt(opts) => {
            println!("Decrypting ...!");
            let ciphermsg = fs::read(opts.input).expect("error reading");
            let nonce = GenericArray::from_slice(&ciphermsg[0..12]);
            let ciphertext = &ciphermsg[12..];
            let key = fs::read(opts.key).expect("failed reading key");
            let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
            let msg = cipher.decrypt(nonce, ciphertext).expect("error decrypting");
            
            println!("secret: {}", std::str::from_utf8(&msg).expect("error converting secret to utf8"));
            fs::write(opts.output, msg).expect("Error writing");
        }
        SubCommand::GenerateKey(opts) => {
            let mut key= [0u8; 32];
            let mut rng = StdRng::from_entropy();
            rng.fill(&mut key);
            fs::write(&opts.key, &key).expect("error saving key");
        }
    }


}

