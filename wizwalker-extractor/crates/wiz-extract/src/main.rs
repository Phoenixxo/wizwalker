use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::Path,
    process::ExitCode,
};

use wiz_analysis::{
    pe::{Image, MAX_IMAGE},
    wizard101,
};

mod output;
mod python;
mod user32;

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "Find hook candidates in WizardGraphicalClient.exe.

Usage:
  wiz-extract --exe <path> [--user32 <path>] [--report <path>] [--python]
    Use --report to save the JSON report.
    Use --python to write generated/wiz_hooks.py in the current directory.
    Pass both options if you'd like both files.
    The cursor hook looks for user32.dll in System32 or the executable's Wine prefix.

  wiz-extract compare --before <path> --after <path>
    Print a diff between two reports.

  wiz-extract decode --hex '48 8b 45 a0' [--ip 0x1000]
    Decode hex bytes as x86-64 instructions and print them as JSON.";

fn run() -> CliResult {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{USAGE}");
        return Ok(());
    }

    match args[0].as_str() {
        "decode" => {
            let options = parse_options(&args[1..], &["--hex", "--ip"])?;
            decode(required(&options, "--hex")?, options.get("--ip").copied())
        }
        "compare" => {
            let options = parse_options(&args[1..], &["--before", "--after"])?;
            compare(
                required(&options, "--before")?,
                required(&options, "--after")?,
            )
        }
        _ => {
            let options = parse_options(&args, &["--exe", "--report", "--user32", "--python"])?;
            extract(
                Path::new(required(&options, "--exe")?),
                options.get("--report").copied(),
                options.get("--user32").copied(),
                options.contains_key("--python"),
            )
        }
    }
}

fn read_image(path: &Path, kind: &str) -> CliResult<(Image, String)> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("Can't open {kind} {path:?} ({error})."))?;
    if metadata.len() > MAX_IMAGE as u64 {
        let limit_mib = MAX_IMAGE / (1024 * 1024);
        return Err(format!("File {path:?} exceeds the {limit_mib} MiB limit.").into());
    }

    let binary =
        fs::read(path).map_err(|error| format!("Can't read {kind} {path:?} ({error})."))?;
    let image = Image::from_file(&binary)
        .map_err(|error| format!("Can't parse {kind} {path:?} ({error})."))?;
    Ok((image, format!("{:x}", Sha256::digest(&binary))))
}

fn extract(
    executable: &Path,
    report_path: Option<&str>,
    user32_path: Option<&str>,
    generate_python: bool,
) -> CliResult {
    let python_path = generate_python.then(|| Path::new("generated/wiz_hooks.py"));
    if let (Some(report), Some(module)) = (report_path, python_path) {
        if output::same_path(Path::new(report), module) {
            return Err("Choose a --report path other than generated/wiz_hooks.py.".into());
        }
    }
    let (image, sha256) = read_image(executable, "executable")?;
    let user32 = match user32_path {
        Some(path) => Some(read_image(Path::new(path), "user32.dll")?),
        None => user32::local_path(executable).and_then(|path| {
            read_image(&path, "user32.dll")
                .map_err(|error| eprintln!("wiz-extract: {error}"))
                .ok()
        }),
    };
    let report = wizard101::analyze_with_user32(&image, user32.as_ref().map(|(dll, _)| dll));
    if report_path.is_some() || python_path.is_none() {
        let mut json_report = serde_json::to_value(&report)?;
        json_report["file_sha256"] = json!(&sha256);
        if let Some((_, hash)) = user32 {
            json_report["module_sha256"] = json!({"user32.dll": hash});
        }
        let output = serde_json::to_string_pretty(&json_report)? + "\n";
        match report_path {
            Some(path) => fs::write(path, output)
                .map_err(|error| format!("Can't write report to {path:?} ({error})."))?,
            None => print!("{output}"),
        }
    }
    if let Some(path) = python_path {
        let output = python::generate(
            &report,
            &sha256,
            wizard101::locators::cursor_game_sites(&image),
        )?;
        output::replace_text(path, &output)
            .map_err(|error| format!("Can't write Python definitions to {path:?} ({error})."))?;
    }
    Ok(())
}

fn decode(hex_bytes: &str, instruction_pointer: Option<&str>) -> CliResult {
    let bytes = hex_bytes
        .split_whitespace()
        .map(|byte| {
            u8::from_str_radix(byte, 16).map_err(|_| {
                format!("Invalid hex byte {byte:?}. Use space-separated bytes like '48 8b 45 a0'.")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let address = match instruction_pointer {
        Some(text) => u64::from_str_radix(text.trim_start_matches("0x"), 16).map_err(|_| {
            format!("Invalid --ip address {text:?}. Use a hex address like 0x1000.")
        })?,
        None => 0,
    };

    let instructions = wiz_analysis::x64::decode_all(&bytes, address)?;
    println!("{}", serde_json::to_string_pretty(&instructions)?);
    Ok(())
}

fn compare(before_path: &str, after_path: &str) -> CliResult {
    let (before_version, before_hooks) = read_report(before_path)?;
    let (after_version, after_hooks) = read_report(after_path)?;
    let hook_names: BTreeSet<_> = before_hooks.keys().chain(after_hooks.keys()).collect();
    let mut changes = Map::new();

    for name in hook_names {
        let before = before_hooks.get(name).unwrap_or(&Value::Null);
        let after = after_hooks.get(name).unwrap_or(&Value::Null);
        if before != after {
            changes.insert(
                name.clone(),
                json!({
                    "kind": change_kind(before, after),
                    "before": before,
                    "after": after,
                }),
            );
        }
    }

    let comparison = json!({
        "schema_version": 1,
        "resolver_changed": before_version != after_version,
        "changes": changes,
    });
    println!("{}", serde_json::to_string_pretty(&comparison)?);
    Ok(())
}

fn read_report(path: &str) -> CliResult<(u64, Map<String, Value>)> {
    let incompatible = || {
        format!("Unsupported extraction report format in {path:?}. Generate a report with --exe.")
    };
    let bytes = fs::read(path).map_err(|error| format!("Can't read report {path:?} ({error})."))?;
    let value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Invalid JSON in report {path:?} ({error})."))?;
    let Value::Object(mut report) = value else {
        return Err(incompatible().into());
    };
    if report.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(incompatible().into());
    }
    let version = report
        .get("resolver_version")
        .and_then(Value::as_u64)
        .ok_or_else(incompatible)?;
    let Some(Value::Object(hooks)) = report.remove("hooks") else {
        return Err(incompatible().into());
    };

    Ok((version, hooks))
}

fn parse_options<'a>(
    args: &'a [String],
    allowed: &[&str],
) -> CliResult<BTreeMap<&'a str, &'a str>> {
    let mut options = BTreeMap::new();
    let mut args = args.iter().map(String::as_str);
    while let Some(flag) = args.next() {
        if !allowed.contains(&flag) {
            return Err(format!("Unknown option {flag:?}. See --help.").into());
        }
        let value = if flag == "--python" {
            ""
        } else {
            args.next()
                .filter(|value| !allowed.contains(value))
                .ok_or_else(|| format!("Missing value for {flag}. See --help."))?
        };
        if options.insert(flag, value).is_some() {
            return Err(format!("Use {flag} only once.").into());
        }
    }
    Ok(options)
}

fn required<'a>(options: &BTreeMap<&str, &'a str>, flag: &str) -> CliResult<&'a str> {
    options
        .get(flag)
        .copied()
        .ok_or_else(|| format!("Missing required option {flag}. See --help.").into())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wiz-extract: {e}");
            ExitCode::FAILURE
        }
    }
}

fn change_kind(before: &Value, after: &Value) -> &'static str {
    if before["finding"].is_null() != after["finding"].is_null() {
        return "availability_changed";
    }
    if before["finding"].is_null() {
        return "diagnostic_changed";
    }
    if before["finding"]["locations"] != after["finding"]["locations"]
        || before["finding"]["overwrite_size"] != after["finding"]["overwrite_size"]
    {
        return "layout_changed";
    }
    if before["finding"]["target_rva"] != after["finding"]["target_rva"]
        || before["finding"]["module"] != after["finding"]["module"]
        || before["finding"]["dependencies"] != after["finding"]["dependencies"]
        || before["finding"]["dependency_modules"] != after["finding"]["dependency_modules"]
    {
        return "addresses_and_evidence_changed";
    }
    "code_evidence_changed"
}
