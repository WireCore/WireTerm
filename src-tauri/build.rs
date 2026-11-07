fn main() {
    embed_manifest();
    // Without Tauri's own manifest: [`embed_manifest`] supplies one for every
    // target, and Tauri's would be a second resource of the same type next to
    // it — which the linker fails on.
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest()),
    )
    .expect("failed to run tauri-build");
}

/// Attaches [`app.manifest`] to everything that is linked — the tests included.
///
/// Tauri embeds the same manifest itself, but as a resource attached to the
/// app binary only. A test binary gets none, and on Windows that is not a
/// cosmetic difference: `cargo test` then fails before a single test runs,
/// with `STATUS_ENTRYPOINT_NOT_FOUND` and nothing else to go on.
///
/// The reason is three levels down. A test binary links Tauri, Tauri's window
/// layer imports `TaskDialogIndirect` from `comctl32.dll`, and that function
/// exists only in version 6 of it. A process reaches version 6 through an
/// application manifest; without one the loader binds version 5 from
/// `system32`, finds no such export, and gives up. One reference anywhere in
/// the linked set is enough to pull that import in, so it is not something a
/// test can avoid by being careful.
///
/// The linker applies this to every target it links — there is no way to say
/// "tests only" for a library's own unit tests — which is why `tauri-build` is
/// told above not to add its own. One manifest, in the repository, for the app
/// and the tests alike. If the app ever needs something else in it (a DPI
/// setting, a requested execution level), this file is where it goes.
fn embed_manifest() {
    if !cfg!(windows) {
        return;
    }
    println!("cargo:rerun-if-changed=app.manifest");

    let Ok(manifest) = std::path::Path::new("app.manifest").canonicalize() else {
        return;
    };
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
}
