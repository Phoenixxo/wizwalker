# WizExtract

`wiz-extract` finds hook candidates within `WizardGraphicalClient.exe` and generates the matching hook patterns.
Recommended to be run on Windows (user32.dll requirements) with at least `Rust 1.100`.
The extractor reads local files offline, with the game closed or running.

## Extract a report

From the workspace root, run the following:

```powershell
cargo run --release --locked -p wiz-extract -- --exe "C:\path\to\WizardGraphicalClient.exe" --report report.json
```

>[!important]
> The cursor locator uses `user32.dll` from Windows System32. On macOS or Linux,
it will attempt to look in the Wine prefix containing the executable, but may fail otherwise. You may pass 
`--user32 <path>` to use a local DLL, but it may not be accurate. Running without the DLL will still pass with all extracted 
hooks except the cursor hook.

## Generate Python hook definitions

```powershell
cargo run --release --locked -p wiz-extract -- --exe "C:\path\to\WizardGraphicalClient.exe" --python --report report.json
```

`--python` will generate `generated/wiz_hooks.py` under the current directory. `HOOKS` contains image-relative
addresses, overwrite lengths, field offsets, dependencies, and expected bytes. The cursor definition names the exports 
WizWalker needs to resolve from its loaded `user32.dll`, so Python generation works with the game executable alone.

If a core hook or the AutoBot region is unresolved, generation exits with an
error and preserves any existing Python module. Unresolved optional hooks appear
in `UNAVAILABLE`.
Omit `--report` to generate just the Python module.

## To use

In WizWalker, run from the workspace root: 

```bash
  cd wizwalker/memory && cargo run --release --locked -p wiz-extract -- --exe "C:\path\to\WizardGraphicalClient.exe" --python
```

Add `--report` if you'd like to save extracted hooks to a JSON file.

## Compare reports or decode bytes

```sh
cargo run --release --locked -p wiz-extract -- compare --before previous.json --after report.json
cargo run --release --locked -p wiz-extract -- decode --hex '48 8b 45 a0' --ip 0x1000
```

Both commands write JSON to stdout. To print an extraction report to stdout,
omit `--report`.

## Using the Rust lib

Pass the executable bytes to `wiz_analysis::pe::Image::from_file`, then pass
the parsed image to `wiz_analysis::wizard101::analyze`. Use `analyze_with_user32`
when you also have the DLL image.
See [decoder coverage and limits](crates/wiz-analysis/README.md).

Run the workspace tests with `cargo test --workspace --locked`.

## License
[GPL-3.0-only](LICENSE).
