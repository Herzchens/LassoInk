use std::{
    env,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn command_text(
    program: &str,
    arguments: &[&str],
    working_directory: Option<&str>,
) -> Option<String> {
    let mut command = Command::new(program);
    command.args(arguments);
    if let Some(directory) = working_directory {
        command.current_dir(directory);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    let manifest_directory = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    if let Some(head_path) = command_text(
        "git",
        &["rev-parse", "--git-path", "HEAD"],
        Some(&manifest_directory),
    ) {
        println!("cargo:rerun-if-changed={head_path}");
    }
    if let Some(reference) = command_text(
        "git",
        &["symbolic-ref", "-q", "HEAD"],
        Some(&manifest_directory),
    ) {
        println!("cargo:rerun-if-changed=.git/{reference}");
    }
    let git_sha = command_text("git", &["rev-parse", "HEAD"], Some(&manifest_directory))
        .unwrap_or_else(|| "unknown".to_owned());
    let tree_dirty = command_text(
        "git",
        &["status", "--porcelain", "--untracked-files=normal"],
        Some(&manifest_directory),
    )
    .is_some_and(|status| !status.is_empty());
    let rustc = env::var("RUSTC")
        .ok()
        .and_then(|path| command_text(&path, &["--version"], None))
        .unwrap_or_else(|| "unknown".to_owned());
    let build_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string();

    println!("cargo:rustc-env=LASSOINK_BUILD_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=LASSOINK_BUILD_TREE_DIRTY={tree_dirty}");
    println!("cargo:rustc-env=LASSOINK_BUILD_ID={build_id}");
    println!(
        "cargo:rustc-env=LASSOINK_BUILD_TARGET={}",
        env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned())
    );
    println!(
        "cargo:rustc-env=LASSOINK_BUILD_PROFILE={}",
        env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned())
    );
    println!("cargo:rustc-env=LASSOINK_BUILD_RUSTC={rustc}");
}
