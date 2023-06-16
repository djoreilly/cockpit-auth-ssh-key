use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose as b64engine, Engine as _};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{os::unix::process::CommandExt, process};

const COCKPIT_SSH_COMMAND: &str = "/usr/libexec/cockpit-ssh";
const ASKPASS_PATH: &str = "/run/askpass";

#[derive(Debug, Serialize, Deserialize)]
struct AuthCommand {
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookie: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProblemInit {
    command: String,
    problem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_methods: Option<String>,
}

fn send_frame(content: String) {
    let frame = format!("{}\n\n{}", content.len() + 1, content);
    debug!("Sending frame: {:?}", frame);
    print!("{frame}"); // send frame on stdout
    io::stdout().flush().expect("stdout should flush");
}

fn send_auth_command(challenge: Option<String>, response: Option<String>) {
    let cookie = match challenge {
        None => None,
        Some(_) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("current time should be after unix epoch");
            Some(format!("{}{:?}", process::id(), now))
        }
    };
    let auth_cmd = AuthCommand {
        command: "authorize".to_owned(),
        cookie,
        challenge,
        response,
    };
    let jsn = serde_json::to_string(&auth_cmd).expect("auth_cmd should serialize");
    send_frame(jsn);
}

fn send_problem_init(problem: String, message: Option<String>, auth_methods: Option<String>) {
    let cmd = ProblemInit {
        command: "init".to_owned(),
        problem,
        message,
        auth_methods,
    };
    let jsn = serde_json::to_string(&cmd).expect("ProblemInit should serialize");
    send_frame(jsn);
}

fn read_size<R: BufRead>(mut reader: R) -> Result<usize> {
    let mut v: Vec<u8> = Vec::new();
    let bytes_read = reader.read_until(b'\n', &mut v)?;
    v.pop(); // discard '\n'
    if bytes_read > 7 {
        bail!("Invalid frame: size too long");
    }
    let sz: usize = str::from_utf8(&v)?.parse()?;
    Ok(sz)
}

fn read_frame<R: BufRead>(mut reader: R) -> Result<String> {
    let sz = read_size(&mut reader)?;
    debug!("Frame size to read: {sz}");
    let mut buf = vec![0u8; sz];
    reader.read_exact(&mut buf)?;
    let s = String::from_utf8(buf)?;
    debug!("Received frame: {:?}", s);
    Ok(s)
}

fn read_auth_reply<R: BufRead>(reader: R) -> Result<String> {
    let data = read_frame(reader)?;
    let cmd: AuthCommand = serde_json::from_str(&data)?;
    debug!("auth_resp: {:?}", cmd);
    if cmd.response.is_none() || cmd.cookie.is_none() {
        bail!("Did not receive a valid authorize command")
    }
    Ok(cmd.response.expect("already checked not None"))
}

fn decode_basic_header(response: &str) -> Result<(String, String)> {
    let response = response
        .strip_prefix("Basic ")
        .context("Header should start with \"Basic \"")?;
    let decoded = b64engine::STANDARD.decode(response)?;
    let s = String::from_utf8(decoded)?;
    let (u, p) = s
        .split_once(':')
        .context("Unable to split username:password")?;
    Ok((u.to_string(), p.to_string()))
}

fn create_askpass_script(password: &str) -> Result<()> {
    // ssh-add re-asks without any limit if the password is wrong.
    // To mitigate, self-destruct to only allow one iteration.
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o700)
        .open(ASKPASS_PATH)?;

    let script = format!(
        r#"#!/bin/sh
echo {password}
rm $0
"#
    );

    file.write_all(script.as_bytes())?;
    Ok(())
}

fn load_key(fname: &str, password: &str) -> Result<()> {
    create_askpass_script(password)?;

    let output = process::Command::new("ssh-add")
        .arg("-t")
        .arg("30")
        .arg(fname)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("SSH_ASKPASS", ASKPASS_PATH)
        .output()?;

    let stderr = str::from_utf8(&output.stderr)?;
    debug!("ssh-add stderr: {:?}", &stderr,);

    if !output.status.success() {
        bail!("{:?}", &stderr);
    }

    send_auth_command(None, Some("ssh-agent".to_string()));
    Ok(())
}

fn main() -> ExitCode {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: {} [user@]host[:port]", args[0]);
        return ExitCode::from(64);
    }
    debug!("{} running with args: {}", args[0], args[1]);
    let mut host = args[1].clone();
    let key_name: String = env::var("COCKPIT_SSH_KEY_PATH").unwrap_or_default();
    debug!("COCKPIT_SSH_KEY_PATH is: {key_name}");

    if !key_name.is_empty() {
        send_auth_command(Some("*".to_string()), None);

        let resp = match read_auth_reply(io::stdin().lock()) {
            Ok(s) => s,
            Err(e) => {
                send_problem_init("internal-error".to_string(), Some(e.to_string()), None);
                error!("auth reply: {}", e.to_string());
                return ExitCode::FAILURE;
            }
        };

        let (user, password) = match decode_basic_header(&resp) {
            Ok((u, p)) => (u, p),
            Err(e) => {
                error!("decode header: {}", e.to_string());
                return ExitCode::FAILURE;
            }
        };
        debug!("user: {user}, password: {password}");

        match load_key(&key_name, &password) {
            Ok(()) => {}
            Err(e) => {
                send_problem_init(
                    "authentication-failed".to_string(),
                    Some("Couldn't open private key".to_string()),
                    Some("{\"password\": \"denied\"}".to_string()),
                );
                error!("load key: {}", e.to_string());
                return ExitCode::FAILURE;
            }
        };

        host = format!("{user}@{host}");
    }

    debug!("Execing {COCKPIT_SSH_COMMAND} {host}");
    let err = process::Command::new(COCKPIT_SSH_COMMAND).arg(host).exec();
    error!("failed to exec: {} {}", COCKPIT_SSH_COMMAND, err);
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_basic_header() {
        let header = "Basic cm9vdDpwYXNzd29yZDE=";
        let (u, p) = decode_basic_header(header).unwrap();
        assert_eq!(u, "root");
        assert_eq!(p, "password1");
    }

    #[test]
    #[should_panic(expected = "Header should start with \"Basic \"")]
    fn test_decode_basic_header_bad_start() {
        let header = "this does not start with: Basic ";
        decode_basic_header(header).unwrap();
    }

    #[test]
    fn test_read_size() {
        let input = b"7\n";
        assert_eq!(read_size(&input[..]).unwrap(), 7usize);

        let input = b"42\n";
        assert_eq!(read_size(&input[..]).unwrap(), 42usize);
    }

    #[test]
    #[should_panic(expected = "Invalid frame: size too long")]
    fn test_read_size_fails_too_long() {
        let input = b"1234567\n";
        read_size(&input[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid digit found in string")]
    fn test_read_size_parse_error() {
        let input = b"NaN\n";
        read_size(&input[..]).unwrap();
    }

    #[test]
    fn test_read_auth_reply() {
        let frame = b"104\n\n{\"command\":\"authorize\",\"cookie\":\"3201686918587.307038207s\",\"response\":\"Basic dXNlcjE6cGFzc3BocmFzZTE=\"}";

        let resp = read_auth_reply(&frame[..]).unwrap();
        let (u, p) = decode_basic_header(&resp).unwrap();
        assert_eq!(u, "user1");
        assert_eq!(p, "passphrase1");
    }
}

