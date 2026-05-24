use camino::Utf8PathBuf;
use std::env;
use std::process;
use uniffi_bindgen::bindings::KotlinBindingGenerator;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err:?}");
        process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let udl = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: legado-uniffi-bindgen <udl> <out-dir> [cdylib]"))?;
    let out_dir = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: legado-uniffi-bindgen <udl> <out-dir> [cdylib]"))?;
    let cdylib = args.next();

    let udl = Utf8PathBuf::from_path_buf(udl.into())
        .map_err(|_| anyhow::anyhow!("UDL path is not valid UTF-8"))?;
    let out_dir = Utf8PathBuf::from_path_buf(out_dir.into())
        .map_err(|_| anyhow::anyhow!("output path is not valid UTF-8"))?;
    let cdylib = cdylib
        .map(|path| {
            Utf8PathBuf::from_path_buf(path.into())
                .map_err(|_| anyhow::anyhow!("cdylib path is not valid UTF-8"))
        })
        .transpose()?;

    uniffi_bindgen::generate_bindings(
        &udl,
        None,
        KotlinBindingGenerator,
        Some(&out_dir),
        cdylib.as_deref(),
        None,
        false,
    )
}
