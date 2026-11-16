//! Compiled only by the ignored CI integration test in provider_protocol.rs.
//! This source is not a Cargo binary target or a production provider.

use std::{
    env,
    io::{self, Read, Write},
    process,
    thread,
    time::Duration,
};

fn hosted_ci_guarded() -> bool {
    let env_is = |key: &str, expected: &str| {
        env::var(key).is_ok_and(|actual| actual == expected)
    };
    (env_is("GITHUB_EVENT_NAME", "push") || env_is("GITHUB_EVENT_NAME", "pull_request"))
        && env_is("LASSOINK_RUN_PROVIDER_MOCK_TESTS", "1")
        && env_is("CI", "true")
        && env_is("GITHUB_ACTIONS", "true")
        && env_is("RUNNER_ENVIRONMENT", "github-hosted")
        && env_is("RUNNER_OS", "Windows")
        && env_is("GITHUB_REPOSITORY", "Herzchens/LassoInk")
}

fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut prefix = [0u8; 4];
    match reader.read(&mut prefix[..1])? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!(),
    }
    reader.read_exact(&mut prefix[1..])?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > 8 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "test worker received an invalid frame length",
        ));
    }
    let mut bytes = vec![0u8; length];
    reader.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response too large"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

fn main() {
    if !hosted_ci_guarded() {
        process::exit(36);
    }
    let mut args = env::args().skip(1);
    let behavior = args.next().unwrap_or_else(|| "crash".to_owned());
    let handshake = args.next().unwrap_or_default();
    let response = args.next().unwrap_or_default();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    if read_frame(&mut input).ok().flatten().is_none() {
        process::exit(31);
    }
    if write_frame(&mut output, handshake.as_bytes()).is_err() {
        process::exit(32);
    }
    if read_frame(&mut input).ok().flatten().is_none() {
        process::exit(33);
    }
    match behavior.as_str() {
        "crash" => process::exit(23),
        "hang" => thread::sleep(Duration::from_secs(60)),
        "ok" | "stale" => {
            if write_frame(&mut output, response.as_bytes()).is_err() {
                process::exit(34);
            }
            process::exit(0);
        }
        "extra" => {
            if write_frame(&mut output, response.as_bytes()).is_err()
                || write_frame(&mut output, b"{}").is_err()
            {
                process::exit(37);
            }
            process::exit(0);
        }
        _ => process::exit(35),
    }
}
