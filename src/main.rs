mod backend;
mod url;

pub use backend::*;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "hax", about = "CUDA-based Entrust 2FA cracker")]
struct Args {
    /// An igmobileotp:// url to decode
    url: String,
}

pub const MAX_CODE: u32 = 99_999_999;

fn main() {
    let args = Args::from_args();

    println!("{}", style("\nFrom the url,").bold());

    let caps = url::RE.captures(&args.url).expect("couldn't parse url");

    url::visualise_url(&caps);

    let salt = url::get_salt(&caps);
    let mac = url::get_mac(&caps);
    let payload = caps["payload"].as_ref();

    println!("{}", style("\nwe know:").bold());
    println!(
        "    {} = \"{}\" (in ascii)",
        style("payload").cyan(),
        style("?action=secactivate&enc=...&v=1").cyan()
    );
    println!(
        "       {} = {} (in hex)",
        style("salt").cyan().bold(),
        style(hex::encode(salt)).cyan().bold()
    );
    println!(
        "        {} = {} (in hex)",
        style("mac").magenta(),
        style(hex::encode(mac)).magenta()
    );

    println!(
        "{}{}{}",
        style("\nTrying to find ").bold(),
        style("code").green(),
        style(", such that:").bold()
    );
    println!(
        "    HMAC(PBKDF2({}, {}), {}) = {}",
        style("salt").cyan().bold(),
        style("code").green(),
        style("payload").cyan(),
        style("mac").magenta()
    );
    println!("");

    let progress = ProgressBar::new(MAX_CODE.into())
        .with_style(ProgressStyle::default_bar()
                    .template("{spinner} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos:>8}/{len:>8} (eta: {eta})")
                    .progress_chars("█▉▊▋▌▍▎▏  ")
                    .tick_strings(&["🧡", "💛", "💚", "💙", "💜", "🌈"])
        );

    let res = CudaBackend::hack(salt, mac, payload, progress);

    println!(
        "🎉 Finished! Your code is {}",
        style(res.expect("search completed without errors but no result was found")).bold()
    );
}
