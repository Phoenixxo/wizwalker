# WizAnalysis

`wiz-analysis` reads x86-64 PE32+ files and finds Wizard101 hook candidates.
For CLI commands and the JSON report format, see the [WizExtract README](../../README.md).

## To use

Pass the bytes of `WizardGraphicalClient.exe` to `Image::from_file` to get an
image, then call `analyze` to get the report.

```rust
use wiz_analysis::{pe::Image, wizard101::analyze};

let image = Image::from_file(&exe_bytes)?;
let report = analyze(&image);
```

If you also have the matching `user32.dll`, parse it the same way and call
`wiz_analysis::wizard101::analyze_with_user32(&image, Some(&user32))`.

## Decoder support

The decoder handles common integer operations, register pushes and pops,
relative and selected indirect branches and calls, `CMOV`, `SETcc`, selected SSE
instructions, and multi-byte NOPs. It reads REX, operand-size and selected
mandatory and segment prefixes, ModR/M, SIB, signed displacements, and
RIP-relative addresses.

Each decoded instruction gives you its bytes, opcode, prefixes, operands, and
encoding offsets. Hook locators use those details to check the instruction
forms and data flow they expect, including encodings in the `Vector` and
`Unary` families.

> [!important]
> Decoding stops on unsupported encodings such as VEX, EVEX, and address-size
> overrides. Whole-function scans are limited to 128 KiB per function and PE
> images to 256 MiB. Hook discovery rejects saved instructions that need
> RIP-relative or direct-branch relocation.
