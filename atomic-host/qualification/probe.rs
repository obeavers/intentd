//! Build and offline-runtime qualification only; this is not the Atomic host.

use std::{error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(std::env::args_os().nth(1).ok_or("missing fixture path")?);
    let repo = atomic_repository::Repository::init(&root)?;
    let view = repo.current_view().to_owned();
    drop(repo);
    let reopened = atomic_repository::Repository::open_existing(&root)?;
    if reopened.current_view() != view || !root.join(".atomic").is_dir() {
        return Err("repository initialization did not survive reopening".into());
    }
    println!("initialized and reopened disposable Atomic repository; view={view}");
    Ok(())
}
