//! Stages the UI assets that `rust-embed` (in `src/api.rs`) will embed.
//!
//! The embed target is `$OUT_DIR/ui/`, written here rather than read from the
//! source tree so that:
//!
//!   * `cargo publish` verification doesn't reject the package for source
//!     modification (build scripts may only touch `OUT_DIR`),
//!   * fresh clones / CI can compile without running `pnpm --dir ui build`
//!     first (placeholders are used), and
//!   * production artifacts still embed the real assets whenever `ui/dist/`
//!     contains a proper build.
//!
//! Runs only when the inputs change:
//!   * `ui/dist/` contents
//!   * this build script itself

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=ui/dist");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    let target = out_dir.join("ui");

    // Start from a clean slate so stale files don't linger across rebuilds.
    let _ = fs::remove_dir_all(&target);
    fs::create_dir_all(&target).expect("failed to create OUT_DIR/ui");

    let src = Path::new("ui/dist");
    if src.join("index.html").exists() {
        copy_dir_recursive(src, &target).expect("failed to copy ui/dist into OUT_DIR");
    } else {
        // No real UI build. Write minimal SPA entrypoints so rust-embed can
        // expand and the server can still start up (returning placeholder
        // HTML at /admin and /ui).
        let name = "index.html";
        let body = format!(
            "<!doctype html><title>{name}</title>\
             <p>Placeholder. Run <code>pnpm --dir ui build</code> to generate the real UI.</p>"
        );
        fs::write(target.join(name), body).expect("failed to write UI placeholder");
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else {
            fs::copy(entry.path(), dst_path)?;
        }
    }
    Ok(())
}
