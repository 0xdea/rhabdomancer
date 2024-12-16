use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let (_, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);
    if !ida_path.exists() || !idalib_path.exists() {
        idalib_build::configure_idasdk_linkage();
        println!("cargo::warning=Cannot find an IDA Pro installation, check your IDADIR environment variable");
    } else {
        idalib_build::configure_linkage()?;
    }
    Ok(())
}
