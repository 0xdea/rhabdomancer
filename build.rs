use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    idalib_build::configure_linkage()?;
    Ok(())
}
