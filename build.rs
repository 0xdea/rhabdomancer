//! build.rs - See <https://github.com/binarly-io/idalib/blob/master/README.md>

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let (_, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);
    if !ida_path.exists() || !idalib_path.exists() {
        println!("cargo::warning=IDA installation not found, check your IDADIR env var");
        idalib_build::configure_idasdk_linkage();
    } else {
        idalib_build::configure_linkage()?;
    }
    Ok(())
}
