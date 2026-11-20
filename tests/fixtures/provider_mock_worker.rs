//! Compiled only by the ignored CI integration test in provider_protocol.rs.
//! This source is not a Cargo binary target or a production provider.

use std::{
    env,
    io::{self, Read, Write},
    process::{self, Command, Stdio},
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

fn json_string_field(input: &[u8], field: &str) -> Option<String> {
    let marker = format!("\"{field}\":\"");
    let start = input
        .windows(marker.len())
        .position(|window| window == marker.as_bytes())?
        + marker.len();
    let remaining = &input[start..];
    let end = remaining.iter().position(|byte| *byte == b'"')?;
    String::from_utf8(remaining[..end].to_vec()).ok()
}

fn response_bound_to_request(template: &str, request_frame: &[u8]) -> Option<String> {
    let template_request_id = json_string_field(template.as_bytes(), "request_id")?;
    let request_id = json_string_field(request_frame, "request_id")?;
    Some(template.replace(&template_request_id, &request_id))
}

fn spawn_pipe_holder() -> io::Result<()> {
    let executable = env::current_exe()?;
    Command::new(executable)
        .arg("hold-stdio")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map(|_child| ())
}

fn spawn_silent_holder(ready_marker: &str) -> io::Result<()> {
    let executable = env::current_exe()?;
    Command::new(executable)
        .arg("silent-holder")
        .arg(ready_marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_child| ())
}

fn main() {
    if !hosted_ci_guarded() {
        process::exit(36);
    }
    let mut args = env::args().skip(1);
    let behavior = args.next().unwrap_or_else(|| "crash".to_owned());
    if behavior == "hold-stdio" {
        thread::sleep(Duration::from_secs(60));
        return;
    }
    if behavior == "silent-holder" {
        let Some(ready_marker) = args.next() else {
            process::exit(45);
        };
        if std::fs::write(ready_marker, process::id().to_string()).is_err() {
            process::exit(46);
        }
        thread::sleep(Duration::from_secs(60));
        return;
    }
    let handshake = args.next().unwrap_or_default();
    let response = args.next().unwrap_or_default();
    let ready_marker = args.next();
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
    let Some(recognition_request) = read_frame(&mut input).ok().flatten() else {
        process::exit(33);
    };
    let is_primary_repeat = recognition_request
        .windows(b"-r0".len())
        .any(|window| window == b"-r0");
    match behavior.as_str() {
        "crash" => process::exit(23),
        "crash-holder" => {
            if spawn_pipe_holder().is_err() {
                process::exit(38);
            }
            process::exit(23);
        }
        "hang" => thread::sleep(Duration::from_secs(60)),
        "hang-holder" | "cancel-holder" => {
            if spawn_pipe_holder().is_err() {
                process::exit(39);
            }
            if let Some(path) = ready_marker {
                if std::fs::write(path, b"ready").is_err() {
                    process::exit(42);
                }
            } else if behavior == "cancel-holder" {
                process::exit(41);
            }
            thread::sleep(Duration::from_secs(60));
        }
        "ok" | "stale" => {
            if write_frame(&mut output, response.as_bytes()).is_err() {
                process::exit(34);
            }
            if behavior == "stale" && spawn_pipe_holder().is_err() {
                process::exit(44);
            }
            process::exit(0);
        }
        "vary-repeat" => {
            let Some(response_for_request) =
                response_bound_to_request(&response, &recognition_request)
            else {
                process::exit(50);
            };
            let recognized = if is_primary_repeat {
                "fixture text primary"
            } else {
                "fixture text later"
            };
            let varied_response = response_for_request.replace("fixture text", recognized);
            if write_frame(&mut output, varied_response.as_bytes()).is_err() {
                process::exit(34);
            }
            process::exit(0);
        }
        "fail-primary-then-success" => {
            if is_primary_repeat {
                process::exit(23);
            }
            let Some(response_for_request) =
                response_bound_to_request(&response, &recognition_request)
            else {
                process::exit(50);
            };
            let later_response = response_for_request.replace("fixture text", "fixture text later");
            if write_frame(&mut output, later_response.as_bytes()).is_err() {
                process::exit(34);
            }
            process::exit(0);
        }
        "ok-holder" => {
            if write_frame(&mut output, response.as_bytes()).is_err()
                || spawn_pipe_holder().is_err()
            {
                process::exit(40);
            }
            process::exit(0);
        }
        "ok-silent-holder" => {
            let Some(ready_marker) = ready_marker.as_deref() else {
                process::exit(47);
            };
            if write_frame(&mut output, response.as_bytes()).is_err()
                || spawn_silent_holder(ready_marker).is_err()
            {
                process::exit(48);
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !std::path::Path::new(ready_marker).exists() {
                if std::time::Instant::now() >= deadline {
                    process::exit(49);
                }
                thread::sleep(Duration::from_millis(5));
            }
            process::exit(0);
        }
        "extra" | "extra-holder" => {
            if write_frame(&mut output, response.as_bytes()).is_err()
                || write_frame(&mut output, b"{}").is_err()
            {
                process::exit(37);
            }
            if behavior == "extra-holder" && spawn_pipe_holder().is_err() {
                process::exit(43);
            }
            process::exit(0);
        }
        _ => process::exit(35),
    }
}
