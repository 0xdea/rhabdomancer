use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let (_, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);

    if ida_path.exists() && idalib_path.exists() {
        idalib_build::configure_linkage()?;
    } else {
        idalib_build::configure_idasdk_linkage();

        // FIXME: see `configure_linkage()` in idalib-build
        if cfg!(target_os = "windows") {
            println!("cargo::rustc-link-arg=/FORCE:UNRESOLVED");
        }
    }

    Ok(())
}
