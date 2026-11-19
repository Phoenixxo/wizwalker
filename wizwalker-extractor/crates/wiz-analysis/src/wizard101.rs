//! Find hook candidates in WizardGraphicalClient.exe.
use crate::{
    pe::{Function, Image},
    x64::{self, Instruction, Memory, Op, Operand},
    Error, Result,
};
use serde::Serialize;
use std::collections::BTreeMap;
#[path = "locators.rs"]
pub mod locators;
pub const RESOLVER_VERSION: u32 = 2;
const MAX_FUNCTION: usize = 128 * 1024;
#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<&'static str>,
    pub rva: u32,
    pub bytes: Vec<u8>,
    pub role: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<&'static str>,
    pub target_rva: u32,
    pub overwrite_size: usize,
    pub locations: BTreeMap<String, i64>,
    pub dependencies: BTreeMap<String, u32>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub dependency_modules: BTreeMap<String, &'static str>,
    pub evidence: Vec<Evidence>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Availability {
    pub finding: Option<Finding>,
    pub error: Option<Error>,
}
impl From<Result<Finding>> for Availability {
    fn from(r: Result<Finding>) -> Self {
        match r {
            Ok(f) => Self {
                finding: Some(f),
                error: None,
            },
            Err(e) => Self {
                finding: None,
                error: Some(e),
            },
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub resolver_version: u32,
    pub image_size: usize,
    pub timestamp: u32,
    pub hooks: BTreeMap<String, Availability>,
}
fn fail(s: &str) -> Error {
    Error::new("Wiz Extract", s)
}
fn unique<T>(mut v: Vec<T>, what: &str) -> Result<T> {
    if v.len() != 1 {
        return Err(fail(&format!(
            "{what}: expected one validated candidate, found {}",
            v.len()
        )));
    }
    Ok(v.remove(0))
}
fn decoded(image: &Image, f: Function) -> Result<Vec<Instruction>> {
    if f.end as usize - f.start as usize > MAX_FUNCTION {
        return Err(fail("function exceeds analysis budget"));
    }
    x64::decode_all(
        image.read(f.start, (f.end - f.start) as usize)?,
        image.address(f.start)?,
    )
}
fn vector_move(i: &Instruction) -> bool {
    i.op == Op::Vector
        && matches!(
            i.opcode,
            0x0f10 | 0x0f11 | 0x0f28 | 0x0f29 | 0x0f6f | 0x0f7f
        )
}
fn register(o: Option<&Operand>) -> Option<u8> {
    match o {
        Some(Operand::Register(r)) if !r.vector && !r.high_byte => Some(r.index),
        _ => None,
    }
}
fn memory(o: Option<&Operand>) -> Option<Memory> {
    match o {
        Some(Operand::Memory(m)) => Some(*m),
        _ => None,
    }
}
fn immediate(o: Option<&Operand>) -> Option<i64> {
    match o {
        Some(Operand::Immediate(i)) => Some(*i),
        _ => None,
    }
}
fn target(i: &Instruction, image: &Image) -> Option<u32> {
    match i.operands.first() {
        Some(Operand::Address(a)) => image.rva(*a).ok(),
        _ => None,
    }
}
fn evidence(image: &Image, rva: u32, size: usize, role: &str) -> Result<Evidence> {
    Ok(Evidence {
        module: None,
        rva,
        bytes: image.read(rva, size)?.to_vec(),
        role: role.into(),
    })
}
fn finding(image: &Image, rva: u32, overwrite: usize) -> Result<Finding> {
    Ok(Finding {
        module: None,
        target_rva: rva,
        overwrite_size: overwrite,
        locations: BTreeMap::new(),
        dependencies: BTreeMap::new(),
        dependency_modules: BTreeMap::new(),
        evidence: vec![evidence(image, rva, overwrite, "hook instructions")?],
    })
}

/// Find instructions that reference the string. Decode from the PE function
/// start to confirm each instruction boundary.
fn references(image: &Image, text: &str) -> Result<Vec<(Function, Instruction)>> {
    references_to_string(image, text, false)
}

/// Find decoded LEAs that point anywhere within a stable string. MSVC pools
/// string suffixes, so a reference may start after the beginning of the literal.
fn references_within(image: &Image, text: &str) -> Result<Vec<(Function, Instruction)>> {
    references_to_string(image, text, true)
}

fn references_to_string(
    image: &Image,
    text: &str,
    allow_interior: bool,
) -> Result<Vec<(Function, Instruction)>> {
    let strings = image.strings(text);
    if strings.len() > 1024 {
        return Err(fail("string anchor budget exceeded"));
    }
    if strings.is_empty() {
        return Err(fail(&format!("anchor {text:?} is absent")));
    }
    let mut candidates = BTreeMap::<u32, Vec<u32>>::new();
    // Use the seven-byte LEA form to find candidates before checking instruction boundaries.
    for s in &image.headers.sections {
        if !s.executable {
            continue;
        }
        let data = image.read(s.rva, s.size as usize)?;
        for (n, b) in data.iter().enumerate() {
            if *b != 0x8d
                || n == 0
                || n + 6 > data.len()
                || !matches!(data[n - 1], 0x48 | 0x4c)
                || data[n + 1] & 0xc7 != 5
            {
                continue;
            }
            let rva = s.rva + n as u32 - 1;
            let d = i32::from_le_bytes(data[n + 2..n + 6].try_into().unwrap());
            let dest = i64::from(rva) + 7 + i64::from(d);
            if strings.iter().any(|r| {
                let start = i64::from(*r);
                dest == start
                    || (allow_interior && dest > start && dest < start + text.len() as i64)
            }) {
                if let Some(f) = image.function(rva) {
                    candidates.entry(f.start).or_default().push(rva);
                }
            }
        }
    }
    let mut out = Vec::new();
    for (start, refs) in candidates {
        let f = image.function(start).unwrap();
        let instructions = decoded(image, f)?;
        for i in instructions {
            let r = image.rva(i.ip)?;
            if refs.contains(&r) {
                out.push((f, i));
            }
        }
    }
    Ok(out)
}

/// Locate the large AutobotManager setup function used as WizWalker's AutoBot region.
/// Stable method-name references identify its role, while its unwind boundary and
/// early ownership transfer validate that the candidate has the expected structure.
fn autobot(image: &Image) -> Result<Finding> {
    const ANCHORS: [&str; 3] = [
        "AutobotManager::Initialize",
        "AutobotManager::OnQuestComplete",
        "AutobotManager::ToggleAutobotMode",
    ];

    let mut candidates = BTreeMap::<u32, BTreeMap<&str, Instruction>>::new();
    for anchor in ANCHORS {
        for (function, instruction) in references_within(image, anchor)? {
            if function.end - function.start >= locators::AUTOBOT_MIN_SIZE as u32 {
                candidates
                    .entry(function.start)
                    .or_default()
                    .entry(anchor)
                    .or_insert(instruction);
            }
        }
    }

    let mut validated = Vec::new();
    for (target, references) in candidates {
        if references.len() != ANCHORS.len() {
            continue;
        }
        let entry = image.read(target, 256)?;
        let entry_address = image.address(target)?;
        let mut instructions = Vec::new();
        let mut offset = 0;
        while instructions.len() < 32 {
            let instruction = x64::decode(&entry[offset..], entry_address + offset as u64)?;
            offset += instruction.len();
            instructions.push(instruction);
        }
        let saves_owner = instructions.iter().any(|instruction| {
            instruction.op == Op::Mov
                && register(instruction.operands.get(1)) == Some(1)
                && register(instruction.operands.first())
                    .is_some_and(|register| matches!(register, 3 | 5 | 6 | 7 | 12..=15))
        });
        if saves_owner {
            validated.push((target, references));
        }
    }
    let (target, references) = unique(validated, "AutobotManager region")?;

    let mut proof = vec![evidence(
        image,
        target,
        16,
        "AutobotManager function entry",
    )?];
    for (anchor, instruction) in references {
        proof.push(evidence(
            image,
            image.rva(instruction.ip)?,
            instruction.len(),
            &format!("reference within {anchor}"),
        )?);
    }
    Ok(Finding {
        module: None,
        target_rva: target,
        overwrite_size: 0,
        locations: BTreeMap::new(),
        dependencies: BTreeMap::new(),
        dependency_modules: BTreeMap::new(),
        evidence: proof,
    })
}
fn registration(image: &Image, name: &str, qualified: &str) -> Result<(u32, Vec<Evidence>)> {
    let first = references(image, name)?;
    let second = references(image, qualified)?;
    let mut matches = Vec::new();
    for (f, a) in first {
        let instructions = decoded(image, f)?;
        let at = instructions.iter().position(|i| i.ip == a.ip).unwrap();
        if at < 3 {
            continue;
        }
        let prefix = &instructions[at - 3..at];
        // The handler and adjustment form a member-function descriptor saved on the stack.
        let (load, store, adjust) = (&prefix[0], &prefix[1], &prefix[2]);
        if load.op != Op::Lea
            || register(load.operands.first()) != Some(0)
            || store.op != Op::Mov
            || register(store.operands.get(1)) != Some(0)
            || adjust.op != Op::Mov
        {
            continue;
        }
        let Some(slot) = memory(store.operands.first()) else {
            continue;
        };
        let Some(adj) = memory(adjust.operands.first()) else {
            continue;
        };
        if slot.base != Some(4)
            || slot.index.is_some()
            || adj.base != Some(4)
            || adj.index.is_some()
            || adj.displacement != slot.displacement + 8
        {
            continue;
        }
        let Some(handler) = load.memory_address()?.and_then(|a| image.rva(a).ok()) else {
            continue;
        };
        if image.function(handler).map(|f| f.start) != Some(handler) {
            continue;
        }
        let paired = second
            .iter()
            .filter(|(g, b)| g.start == f.start && b.ip > a.ip && b.ip - a.ip < 96)
            .collect::<Vec<_>>();
        if paired.len() != 1 {
            continue;
        }
        let end = paired[0].1.next_ip()?;
        let start = image.rva(load.ip)?;
        // R9 must point to the copied descriptor when the registration call runs.
        let tail = &instructions[at + 1..];
        let call = tail
            .iter()
            .position(|i| i.op == Op::Call && i.ip > paired[0].1.ip);
        let Some(call) = call else { continue };
        if call > 24 {
            continue;
        }
        let copies = tail[..call]
            .windows(2)
            .filter(|w| {
                vector_move(&w[0])
                    && memory(w[0].operands.get(1))
                        .is_some_and(|m| m.base == slot.base && m.displacement == slot.displacement)
                    && vector_move(&w[1])
                    && w[0].operands.first() == w[1].operands.get(1)
            })
            .filter_map(|w| memory(w[1].operands.first()))
            .collect::<Vec<_>>();
        let r9 = tail[..call].iter().any(|i| {
            i.op == Op::Lea
                && register(i.operands.first()) == Some(9)
                && memory(i.operands.get(1)).is_some_and(|m| {
                    copies.iter().any(|c| {
                        c.base == m.base && c.index == m.index && c.displacement == m.displacement
                    })
                })
        });
        if !r9 {
            continue;
        }
        matches.push((
            handler,
            vec![evidence(
                image,
                start,
                (end - load.ip) as usize,
                "paired handler registration",
            )?],
        ));
    }
    unique(matches, &format!("registration for {name}"))
}
fn field_calls(image: &Image, ins: &[Instruction], name: &str) -> Vec<usize> {
    let strings = image.strings(name);
    ins.iter()
        .enumerate()
        .filter_map(|(n, i)| {
            if i.op != Op::Lea || register(i.operands.first()) != Some(2) {
                return None;
            }
            let a = i
                .memory_address()
                .ok()
                .flatten()
                .and_then(|a| image.rva(a).ok())?;
            if !strings.contains(&a) {
                return None;
            }
            let call = ins[n + 1..].iter().take(4).position(|i| i.op == Op::Call)?;
            Some(n + 1 + call)
        })
        .collect()
}
fn chat_receive(image: &Image) -> Result<Finding> {
    let (handler, proof) = registration(image, "MSG_DirectedChat", "GameClient::MSG_DirectedChat")?;
    let ins = decoded(image, image.function(handler).unwrap())?;
    let source = unique(field_calls(image, &ins, "SourceID"), "SourceID lookup")?;
    let message = unique(field_calls(image, &ins, "Message"), "Message lookup")?;
    // Field -> typed getter -> load through getter result -> persistent stack local.
    let s = ins
        .get(source + 1..source + 6)
        .ok_or_else(|| fail("SourceID getter is incomplete"))?;
    if s[0].op != Op::Mov
        || register(s[0].operands.first()) != Some(1)
        || register(s[0].operands.get(1)) != Some(0)
        || s[1].op != Op::Lea
        || s[2].op != Op::Call
        || s[3].op != Op::Mov
        || s[4].op != Op::Mov
    {
        return Err(fail("unsupported SourceID getter data flow"));
    }
    let loaded = memory(s[3].operands.get(1))
        .ok_or_else(|| fail("SourceID is not loaded from getter result"))?;
    let stored = memory(s[4].operands.first())
        .ok_or_else(|| fail("SourceID is not stored in a stack local"))?;
    if loaded.base != Some(0)
        || loaded.displacement != 0
        || loaded.index.is_some()
        || register(s[3].operands.first()) != register(s[4].operands.get(1))
        || stored.base != Some(5)
        || stored.index.is_some()
        || stored.bits != 64
    {
        return Err(fail("unsupported SourceID storage"));
    }
    let m = ins
        .get(message + 1..message + 5)
        .ok_or_else(|| fail("Message getter is incomplete"))?;
    if m[0].op != Op::Mov
        || register(m[0].operands.first()) != Some(1)
        || register(m[0].operands.get(1)) != Some(0)
        || m[1].op != Op::Call
        || m[2].op != Op::Lea
        || register(m[2].operands.first()) != Some(1)
        || m[3].op != Op::Cmp
        || register(m[3].operands.first()) != Some(1)
        || register(m[3].operands.get(1)) != Some(0)
    {
        return Err(fail("unsupported Message getter/capture data flow"));
    }
    let local = memory(m[2].operands.get(1)).ok_or_else(|| fail("Message local missing"))?;
    if local.base != Some(5) || local.index.is_some() {
        return Err(fail("unsupported Message local"));
    }
    // Check that RSI keeps the owner and RBP keeps the same frame until capture.
    let owner = ins
        .iter()
        .position(|i| {
            i.op == Op::Mov
                && register(i.operands.first()) == Some(6)
                && register(i.operands.get(1)) == Some(1)
        })
        .ok_or_else(|| fail("owner register is not RSI"))?;
    if owner >= source || source >= message {
        return Err(fail("unsupported field order"));
    }
    for i in &ins[owner + 1..message + 3] {
        if register(i.operands.first()).is_some_and(|r| matches!(r, 5 | 6))
            && !matches!(i.op, Op::Cmp | Op::Test | Op::Push)
        {
            return Err(fail("owner/frame register changed before capture"));
        }
    }
    let at = image.rva(m[2].ip)?;
    let mut f = finding(image, at, m[2].len() + m[3].len())?;
    f.locations
        .insert("source_id_frame_offset".into(), stored.displacement);
    f.locations.insert("owner_register".into(), 6);
    f.locations.insert("message_register".into(), 0);
    f.locations
        .insert("message_frame_offset".into(), local.displacement);
    f.dependencies.insert("handler".into(), handler);
    f.evidence.extend(proof);
    f.evidence.push(evidence(
        image,
        handler,
        (m[3].next_ip()? - u64::from(handler) - image.base) as usize,
        "receive field data flow",
    )?);
    Ok(f)
}

pub fn analyze(image: &Image) -> Report {
    analyze_with_user32(image, None)
}

/// Scan the game executable. Pass its matching user32.dll to resolve the cursor hook.
pub fn analyze_with_user32(image: &Image, user32: Option<&Image>) -> Report {
    let mut hooks = BTreeMap::new();
    for spec in locators::CORE
        .into_iter()
        .chain([locators::DANCE])
        .chain(locators::LEGACY)
    {
        hooks.insert(spec.name.into(), locators::locate(image, spec).into());
    }
    hooks.insert(locators::AUTOBOT_NAME.into(), autobot(image).into());
    hooks.insert(
        "mouseless_cursor".into(),
        user32
            .ok_or_else(|| fail("requires a matching user32.dll. Supply it with --user32."))
            .and_then(|dll| locators::cursor(image, dll))
            .into(),
    );
    hooks.insert(
        "combat.duel_manager".into(),
        locators::duel_manager(image).into(),
    );
    hooks.insert("chat".into(), chat_receive(image).into());
    hooks.insert("movement_teleport".into(), movement(image).into());
    hooks.insert("chat_send".into(), chat_send(image).into());
    hooks.insert("resize.video_manager".into(), video_manager(image).into());
    Report {
        schema_version: 1,
        resolver_version: RESOLVER_VERSION,
        image_size: image.bytes.len(),
        timestamp: image.headers.timestamp,
        hooks,
    }
}

fn video_manager(image: &Image) -> Result<Finding> {
    match video_manager_from_restart(image) {
        Ok(found) => Ok(found),
        Err(semantic_error) => match locators::locate(image, locators::LEGACY_VIDEO_MANAGER) {
            Ok(found) => Ok(found),
            Err(pattern_error) => Err(Error::new(
                "resize.video_manager",
                format!(
                    "{semantic_error}. Legacy signature check failed ({})",
                    pattern_error.message
                ),
            )),
        },
    }
}

fn video_manager_from_restart(image: &Image) -> Result<Finding> {
    let restart_functions: BTreeMap<_, _> = references(image, "GamebryoClient::VidRestart")?
        .into_iter()
        .map(|(function, _)| (function.start, function))
        .collect();
    let mut candidates = BTreeMap::new();
    for (function, anchor) in references(image, "GamebryoClient::PreRender")? {
        for w in decoded(image, function)?.windows(3) {
            let Some(field) = memory(w[0].operands.first()) else {
                continue;
            };
            if w[0].op != Op::Cmp
                || field.base != Some(1)
                || field.index.is_some()
                || field.bits != 8
                || field.displacement <= 0
                || immediate(w[0].operands.get(1)) != Some(0)
                || w[1].op != Op::Conditional(4)
                || w[2].op != Op::Call
            {
                continue;
            }
            let Some(restart) = target(&w[2], image).and_then(|rva| restart_functions.get(&rva))
            else {
                continue;
            };
            let restart_code = decoded(image, *restart)?;
            // VidRestart saves the incoming manager in RBX and clears the same byte on success.
            let Some(save_manager) = restart_code.iter().position(|i| {
                i.op == Op::Mov
                    && register(i.operands.first()) == Some(3)
                    && register(i.operands.get(1)) == Some(1)
            }) else {
                continue;
            };
            let Some(clear) = restart_code[save_manager + 1..].iter().find(|i| {
                i.op == Op::Mov
                    && immediate(i.operands.get(1)) == Some(0)
                    && memory(i.operands.first()).is_some_and(|m| {
                        m.base == Some(3)
                            && m.index.is_none()
                            && m.bits == 8
                            && m.displacement == field.displacement
                    })
            }) else {
                continue;
            };

            let overwrite =
                locators::overwrite_span(image, "resize.video_manager", function.start, 5)?;
            let mut found = finding(image, function.start, overwrite)?;
            found
                .locations
                .insert("pending_change_offset".into(), field.displacement);
            found
                .dependencies
                .insert("video_restart".into(), restart.start);
            for (i, size, role) in [
                (&anchor, anchor.len(), "PreRender string reference"),
                (
                    &w[0],
                    w.iter().map(Instruction::len).sum(),
                    "pending flag check and restart call",
                ),
                (clear, clear.len(), "restart clears pending flag"),
            ] {
                found
                    .evidence
                    .push(evidence(image, image.rva(i.ip)?, size, role)?);
            }
            candidates.insert((function.start, w[0].ip), found);
        }
    }
    unique(
        candidates.into_values().collect(),
        "video manager pending restart check",
    )
}

fn raw_candidates(image: &Image, needle: &[u8]) -> Result<Vec<Function>> {
    let mut fs = BTreeMap::new();
    for s in &image.headers.sections {
        if !s.executable {
            continue;
        }
        if let Ok(b) = image.read(s.rva, s.size as usize) {
            for off in memchr::memmem::find_iter(b, needle) {
                if let Some(f) = image.function(s.rva + off as u32) {
                    fs.insert(f.start, f);
                    if fs.len() > 512 {
                        return Err(fail("structural candidate budget exceeded"));
                    }
                }
            }
        }
    }
    Ok(fs.into_values().collect())
}
fn movement(image: &Image) -> Result<Finding> {
    let mut setters = Vec::new();
    for fun in raw_candidates(image, &[0xf2, 0x0f, 0x10, 0x02])? {
        let Ok(ins) = decoded(image, fun) else {
            continue;
        };
        for w in ins.windows(10) {
            if !vector_move(&w[0])
                || !vector_move(&w[1])
                || w[2].op != Op::Mov
                || w[3].op != Op::Mov
                || w[4].op != Op::Mov
            {
                continue;
            }
            let Some(input) = memory(w[0].operands.get(1)) else {
                continue;
            };
            let Some(dest) = memory(w[1].operands.first()) else {
                continue;
            };
            let Some(z) = memory(w[2].operands.get(1)) else {
                continue;
            };
            let Some(dz) = memory(w[3].operands.first()) else {
                continue;
            };
            let Some(flag) = memory(w[4].operands.first()) else {
                continue;
            };
            if input.base != Some(2)
                || input.index.is_some()
                || input.displacement != 0
                || dest.base != Some(8)
                || dest.displacement != 0x58
                || z.base != Some(2)
                || z.displacement != 8
                || dz.base != Some(8)
                || dz.displacement != 0x60
                || flag.base != Some(8)
                || flag.displacement != 0x88
                || immediate(w[4].operands.get(1)) != Some(1)
            {
                continue;
            }
            // A position setter updates the owner position and marks it dirty.
            let tail = &ins[ins.iter().position(|i| i.ip == w[0].ip).unwrap() + 5..];
            let owner_xy = tail.iter().any(|i| {
                vector_move(i)
                    && memory(i.operands.first())
                        .is_some_and(|m| m.base == Some(1) && m.displacement == 0xa8)
            });
            let owner_z = tail.iter().any(|i| {
                i.op == Op::Mov
                    && memory(i.operands.first())
                        .is_some_and(|m| m.base == Some(1) && m.displacement == 0xb0)
            });
            let dirty = tail.iter().any(|i| {
                i.op == Op::Or
                    && memory(i.operands.first())
                        .is_some_and(|m| m.base == Some(1) && m.displacement == 0x160)
                    && immediate(i.operands.get(1)) == Some(1)
            });
            if owner_xy && owner_z && dirty {
                setters.push(fun);
            }
        }
    }
    let setter = unique(setters, "position setter")?;
    let setter_ins = decoded(image, setter)?;
    let overwrite = setter_ins
        .iter()
        .scan(0, |n, i| {
            *n += i.len();
            Some(*n)
        })
        .find(|n| *n >= 6)
        .ok_or_else(|| fail("position setter is too short"))?;
    let mut states = Vec::new();
    for fun in raw_candidates(image, &[0x8b, 0x5f, 0x70])? {
        let Ok(ins) = decoded(image, fun) else {
            continue;
        };
        for (n, i) in ins.iter().enumerate() {
            if i.op != Op::Mov
                || register(i.operands.first()) != Some(3)
                || !memory(i.operands.get(1))
                    .is_some_and(|m| m.base == Some(7) && m.displacement == 0x70)
            {
                continue;
            }
            let tail = &ins[n + 1..];
            let Some(a) = tail.iter().take(5).position(|j| {
                j.op == Op::And
                    && register(j.operands.first()) == Some(3)
                    && immediate(j.operands.get(1)) == Some(3)
            }) else {
                continue;
            };
            let Some(first) = tail.get(a + 1) else {
                continue;
            };
            let Some(cmp) = tail.get(a + 2) else { continue };
            let Some(second) = tail.get(a + 3) else {
                continue;
            };
            if first.op == Op::Conditional(4)
                && cmp.op == Op::Cmp
                && register(cmp.operands.first()) == Some(3)
                && immediate(cmp.operands.get(1)) == Some(3)
                && second.op == Op::Conditional(4)
                && first.len() == 6
                && second.len() == 6
                && target(first, image).is_some_and(|t| t >= fun.start && t < fun.end)
                && target(second, image).is_some_and(|t| t >= fun.start && t < fun.end)
            {
                states.push((
                    fun,
                    ins.clone(),
                    image.rva(first.ip)?,
                    image.rva(second.ip)?,
                ));
            }
        }
    }
    let (state, ins, first, second) = unique(states, "movement-state branches")?;
    let mut collisions = Vec::new();
    for w in ins.windows(8) {
        if w[0].op != Op::Conditional(4)
            || w[0].len() != 2
            || !vector_move(&w[1])
            || !vector_move(&w[2])
            || w[3].op != Op::Mov
            || w[7].op != Op::Mov
        {
            continue;
        }
        let Some(src) = memory(w[1].operands.get(1)) else {
            continue;
        };
        let Some(dst) = memory(w[2].operands.first()) else {
            continue;
        };
        if src.base != Some(4) || dst.base != Some(4) || src.index.is_some() || dst.index.is_some()
        {
            continue;
        }
        if register(w[3].operands.first()) != Some(0)
            || !memory(w[3].operands.get(1))
                .is_some_and(|m| m.base == Some(6) && m.displacement == 0)
        {
            continue;
        }
        if w[6].op != Op::Call
            || !memory(w[6].operands.first())
                .is_some_and(|m| m.base == Some(0) && m.displacement == 0x140)
        {
            continue;
        }
        if !memory(w[7].operands.first())
            .is_some_and(|m| m.base == Some(7) && m.displacement == 0xac)
            || immediate(w[7].operands.get(1)) != Some(1)
        {
            continue;
        }
        if target(&w[0], image) != Some(image.rva(w[7].next_ip()?)?) {
            continue;
        }
        collisions.push(image.rva(w[0].ip)?);
    }
    let collision = unique(collisions, "collision branch")?;
    let mut f = finding(image, setter.start, overwrite)?;
    f.dependencies.extend([
        ("movement_state".into(), state.start),
        ("first_action".into(), first),
        ("second_action".into(), second),
        ("collision".into(), collision),
    ]);
    f.evidence.push(evidence(
        image,
        setter.start,
        (setter.end - setter.start) as usize,
        "position setter data flow",
    )?);
    f.evidence.push(evidence(
        image,
        state.start,
        (state.end - state.start) as usize,
        "movement control flow",
    )?);
    Ok(f)
}
fn buddy(image: &Image) -> Result<(u32, Vec<Evidence>)> {
    let mut found = Vec::new();
    for (fun, _) in references(image, "MSG_BUDDYREQUESTADD")? {
        let ins = decoded(image, fun)?;
        let calls = field_calls(image, &ins, "EntryGID");
        if calls.len() != 1 {
            continue;
        }
        let save = ins.iter().take(16).find(|i| {
            i.op == Op::Mov
                && memory(i.operands.first()).is_some_and(|m| m.base == Some(4) && m.bits == 64)
                && register(i.operands.get(1)) == Some(2)
        });
        let Some(save) = save else { continue };
        let slot = memory(save.operands.first()).unwrap();
        let at = calls[0];
        let flow = ins.get(at + 1..at + 4);
        if !flow.is_some_and(|w| {
            w[0].op == Op::Lea
                && register(w[0].operands.first()) == Some(2)
                && memory(w[0].operands.get(1))
                    .is_some_and(|m| m.base == slot.base && m.displacement == slot.displacement)
                && w[1].op == Op::Mov
                && register(w[1].operands.first()) == Some(1)
                && register(w[1].operands.get(1)) == Some(0)
                && w[2].op == Op::Call
        }) {
            continue;
        }
        found.push((
            fun.start,
            vec![evidence(
                image,
                fun.start,
                (fun.end - fun.start) as usize,
                "buddy argument and EntryGID data flow",
            )?],
        ));
    }
    unique(found, "buddy request constructor")
}
fn chat_send(image: &Image) -> Result<Finding> {
    let (send, mut proof) = registration(
        image,
        "SendDirectedChat",
        "GameClient::HandleSendDirectedChat",
    )?;
    let ins = decoded(image, image.function(send).unwrap())?;
    let target_id = unique(field_calls(image, &ins, "TargetID"), "send TargetID lookup")?;
    let message = unique(field_calls(image, &ins, "Message"), "send Message lookup")?;
    let t = ins
        .get(target_id + 1..target_id + 4)
        .ok_or_else(|| fail("TargetID argument missing"))?;
    if t[0].op != Op::Lea
        || register(t[0].operands.first()) != Some(2)
        || !memory(t[0].operands.get(1))
            .is_some_and(|m| m.base == Some(3) && m.displacement == 0x20 && m.index.is_none())
        || t[1].op != Op::Mov
        || register(t[1].operands.first()) != Some(1)
        || register(t[1].operands.get(1)) != Some(0)
        || t[2].op != Op::Call
    {
        return Err(fail("unsupported chat request TargetID layout"));
    }
    let m = ins
        .get(message + 1..message + 8)
        .ok_or_else(|| fail("Message assignment missing"))?;
    if m[0].op != Op::Mov
        || register(m[0].operands.first()) != Some(2)
        || register(m[0].operands.get(1)) != Some(3)
        || m[1].op != Op::Cmp
        || !memory(m[1].operands.first())
            .is_some_and(|v| v.base == Some(3) && v.displacement == 0x18)
        || immediate(m[1].operands.get(1)) != Some(8)
        || m[6].op != Op::Call
    {
        return Err(fail("unsupported chat request wide-string layout"));
    }
    if !ins.iter().take(16).any(|i| {
        i.op == Op::Mov
            && register(i.operands.first()) == Some(3)
            && register(i.operands.get(1)) == Some(2)
    }) {
        return Err(fail("chat request is not held in RBX"));
    }
    let assign =
        target(&m[6], image).ok_or_else(|| fail("Message assignment is not a direct call"))?;
    let assign_fn = image
        .function(assign)
        .filter(|f| f.start == assign)
        .ok_or_else(|| fail("Message assignment has no function boundary"))?;
    let assign_ins = decoded(image, assign_fn)?;
    // The string allocation path passes sizeof(std::wstring), checks RAX, and sets capacity to 7.
    let mut allocs = Vec::new();
    for w in assign_ins.windows(5) {
        if w[0].op == Op::Lea
            && register(w[0].operands.first()) == Some(1)
            && memory(w[0].operands.get(1))
                .is_some_and(|m| m.base == Some(0) && m.displacement == 0x20)
            && w[1].op == Op::Call
            && w[2].op == Op::Xor
            && w[3].op == Op::Test
        {
            if let Some(a) = target(&w[1], image) {
                allocs.push(a);
            }
        }
    }
    let allocator = unique(allocs, "wide-string allocation dependency")?;
    let alloc_fn = image
        .function(allocator)
        .filter(|f| f.start == allocator)
        .ok_or_else(|| fail("allocator is not a function entry"))?;
    let ai = decoded(image, alloc_fn)?;
    if !ai.iter().any(|i| i.op == Op::Call)
        || !ai
            .iter()
            .any(|i| i.op == Op::Test && register(i.operands.first()) == Some(0))
        || !ai.iter().any(|i| i.op == Op::Conditional(4))
    {
        return Err(fail("allocator result/retry flow is unsupported"));
    }
    let (buddy, buddy_proof) = buddy(image)?;
    proof.extend(buddy_proof);
    let refs = references(image, "GameClient::MainLoop")?;
    let mut schedulers = Vec::new();
    for (fun, _) in refs {
        let si = decoded(image, fun)?;
        for w in si.windows(5) {
            if w[0].op == Op::Cmp
                && memory(w[0].operands.first()).is_some_and(|m| m.base == Some(7) && m.bits == 8)
                && register(w[0].operands.get(1)) == Some(3)
                && w[1].op == Op::Conditional(4)
                && w[2].op == Op::Call
                && w[3].op == Op::Cmp
                && register(w[3].operands.first()) == Some(0)
                && immediate(w[3].operands.get(1)) == Some(100)
                && w[4].op == Op::Conditional(15)
            {
                schedulers.push((image.rva(w[0].ip)?, w[0].len(), fun));
            }
        }
    }
    schedulers.sort_by_key(|v| v.0);
    schedulers.dedup_by_key(|v| v.0);
    let (scheduler, overwrite, loop_fn) = unique(schedulers, "main-loop chat scheduler")?;
    let mut f = finding(image, scheduler, overwrite)?;
    f.dependencies.extend([
        ("send".into(), send),
        ("buddy".into(), buddy),
        ("allocator".into(), allocator),
    ]);
    f.locations.insert("request_target_offset".into(), 0x20);
    f.evidence.extend(proof);
    for (fun, role) in [
        (image.function(send).unwrap(), "send request layout"),
        (assign_fn, "Message allocation path"),
        (alloc_fn, "allocator result handling"),
        (loop_fn, "main-loop execution site"),
    ] {
        f.evidence.push(evidence(
            image,
            fun.start,
            (fun.end - fun.start) as usize,
            role,
        )?);
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{Headers, Section};
    fn image() -> Image {
        Image {
            base: 0x140000000,
            bytes: vec![0; 0x10000],
            functions: Vec::new(),
            headers: Headers {
                base: 0x140000000,
                size: 0x10000,
                headers_size: 0x1000,
                sections: vec![
                    Section {
                        name: ".text".into(),
                        rva: 0x1000,
                        size: 0x5000,
                        executable: true,
                        readable: true,
                        raw_offset: 0,
                        raw_size: 0,
                    },
                    Section {
                        name: ".rdata".into(),
                        rva: 0x8000,
                        size: 0x1000,
                        executable: false,
                        readable: true,
                        raw_offset: 0,
                        raw_size: 0,
                    },
                ],
                exception_rva: 0,
                exception_size: 0,
                timestamp: 0,
            },
        }
    }
    fn put(image: &mut Image, rva: u32, b: &[u8]) {
        image.bytes[rva as usize..rva as usize + b.len()].copy_from_slice(b);
    }
    fn lea(code: &mut Vec<u8>, start: u32, rex: u8, modrm: u8, dest: u32) {
        let next = start + code.len() as u32 + 7;
        code.extend_from_slice(&[rex, 0x8d, modrm]);
        code.extend_from_slice(&((i64::from(dest) - i64::from(next)) as i32).to_le_bytes());
    }
    fn call(code: &mut Vec<u8>, start: u32, dest: u32) {
        let next = start + code.len() as u32 + 5;
        code.push(0xe8);
        code.extend_from_slice(&((i64::from(dest) - i64::from(next)) as i32).to_le_bytes());
    }
    fn fixture(displacement: i8) -> Image {
        let mut image = image();
        for (a, s) in [
            (0x8000, "MSG_DirectedChat"),
            (0x8100, "GameClient::MSG_DirectedChat"),
            (0x8200, "SourceID"),
            (0x8300, "Message"),
        ] {
            put(&mut image, a, s.as_bytes());
        }
        let mut c = Vec::new();
        lea(&mut c, 0x1000, 0x48, 0x05, 0x2000);
        c.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x50, 0x89, 0x5c, 0x24, 0x58]);
        lea(&mut c, 0x1000, 0x48, 0x15, 0x8000);
        c.extend_from_slice(&[0x48, 0x8d, 0x4d, 0x20]);
        call(&mut c, 0x1000, 0x4000);
        c.extend_from_slice(&[0x0f, 0x28, 0x44, 0x24, 0x50, 0x66, 0x0f, 0x7f, 0x45, 0x30]);
        lea(&mut c, 0x1000, 0x48, 0x05, 0x8100);
        c.extend_from_slice(&[
            0x48, 0x89, 0x44, 0x24, 0x20, 0x4c, 0x8d, 0x4d, 0x30, 0x4d, 0x8b, 0xc6, 0x48, 0x8d,
            0x55, 0x20, 0x48, 0x8b, 0xcf,
        ]);
        call(&mut c, 0x1000, 0x4100);
        c.push(0xc3);
        put(&mut image, 0x1000, &c);
        image.functions.push(Function {
            start: 0x1000,
            end: 0x1000 + c.len() as u32,
        });
        let mut c = vec![0x48, 0x8b, 0xf1];
        lea(&mut c, 0x2000, 0x48, 0x15, 0x8200);
        call(&mut c, 0x2000, 0x4200);
        c.extend_from_slice(&[0x48, 0x8b, 0xc8, 0x48, 0x8d, 0x54, 0x24, 0x30]);
        call(&mut c, 0x2000, 0x4300);
        c.extend_from_slice(&[0x48, 0x8b, 0x08, 0x48, 0x89, 0x4d, displacement as u8]);
        lea(&mut c, 0x2000, 0x48, 0x15, 0x8300);
        call(&mut c, 0x2000, 0x4200);
        c.extend_from_slice(&[0x48, 0x8b, 0xc8]);
        call(&mut c, 0x2000, 0x4400);
        c.extend_from_slice(&[0x48, 0x8d, 0x4d, 0x18, 0x48, 0x3b, 0xc8, 0xc3]);
        put(&mut image, 0x2000, &c);
        image.functions.push(Function {
            start: 0x2000,
            end: 0x2000 + c.len() as u32,
        });
        image
    }
    #[test]
    fn registrations_and_storage_are_derived_under_aslr() {
        for base in [0x140000000, 0x7ff600000000] {
            for offset in [-128, -96, -64] {
                let mut image = fixture(offset);
                image.base = base;
                let f = chat_receive(&image).unwrap();
                assert_eq!(f.locations["source_id_frame_offset"], i64::from(offset));
                assert_eq!(f.dependencies["handler"], 0x2000);
                assert_eq!(f.overwrite_size, 7);
            }
        }
    }
    #[test]
    fn unrelated_or_missing_registration_is_not_a_match() {
        let mut image = fixture(-96);
        put(&mut image, 0x8100, b"Unrelated::Handler\0");
        assert!(chat_receive(&image).is_err());
        let mut image = fixture(-96);
        image.bytes[0x1010] = 0xcc;
        assert!(chat_receive(&image).is_err());
    }
    #[test]
    fn unsupported_instruction_blocks_reference_analysis() {
        let mut image = fixture(-96);
        put(&mut image, 0x1000, &[0xc5, 0xf8, 0x77]);
        let e = chat_receive(&image).unwrap_err();
        assert!(e.to_string().contains("unsupported opcode"));
    }
    #[test]
    fn optional_failures_are_independent() {
        let report = analyze(&fixture(-96));
        assert!(report.hooks["chat"].finding.is_some());
        assert!(report.hooks["chat_send"].error.is_some());
        assert!(report.hooks["movement_teleport"].error.is_some());
        assert!(report.hooks["mouseless_cursor"]
            .error
            .as_ref()
            .unwrap()
            .message
            .contains("--user32"));
        assert!(report.hooks["drops_toggle"].error.is_some());
    }

    #[test]
    fn autobot_resolves_a_unique_sized_function_without_an_overwrite_span() {
        let mut image = image();
        let target = 0x1000;
        image.bytes[target as usize..target as usize + locators::AUTOBOT_MIN_SIZE].fill(0x90);
        let initialize = 0x8000;
        let complete = 0x8040;
        let toggle = 0x8080;
        put(&mut image, initialize, b"AutobotManager::Initialize\0");
        put(&mut image, complete, b"AutobotManager::OnQuestComplete\0");
        put(&mut image, toggle, b"AutobotManager::ToggleAutobotMode\0");
        let mut entry = vec![0x4c, 0x8b, 0xf1];
        lea(&mut entry, target, 0x48, 0x15, initialize);
        lea(&mut entry, target, 0x48, 0x15, complete + 8);
        lea(&mut entry, target, 0x48, 0x15, toggle);
        entry.push(0xc3);
        put(&mut image, target, &entry);
        image.functions.push(Function {
            start: target,
            end: target + locators::AUTOBOT_MIN_SIZE as u32,
        });

        let found = autobot(&image).unwrap();
        assert_eq!(found.target_rva, target);
        assert_eq!(found.overwrite_size, 0);
        assert_eq!(found.evidence[0].rva, target);
        assert_eq!(found.evidence.len(), 4);

        image.functions[0].end -= 1;
        assert!(autobot(&image).is_err());
    }

    #[test]
    fn duel_manager_resolves_the_pointer_slot_and_rejects_duplicate_sites() {
        let mut image = image();
        let site = 0x1000;
        let slot = 0x8100;
        let mut code = vec![0x48, 0x8b, 0x0d];
        code.extend_from_slice(&(slot as i32 - (site as i32 + 7)).to_le_bytes());
        call(&mut code, site, 0x2000);
        code.extend_from_slice(&[
            0x90, 0x48, 0x8b, 0x8e, 0xa8, 0x07, 0, 0, 0x48, 0x85, 0xc9, 0x74, 0x32, 0x0f, 0x28,
            0x45, 0x10,
        ]);
        put(&mut image, site, &code);
        let report = analyze(&image);
        let found = report.hooks["combat.duel_manager"]
            .finding
            .as_ref()
            .unwrap();
        assert_eq!((found.target_rva, found.overwrite_size), (slot, 0));
        assert_eq!(found.evidence[0].rva, site);
        put(&mut image, 0x1100, &code);
        assert!(locators::duel_manager(&image).is_err());
    }

    #[test]
    fn video_manager_derives_the_pending_flag_only_when_the_restart_clears_it() {
        let mut image = image();
        put(&mut image, 0x8000, b"GamebryoClient::PreRender\0");
        put(&mut image, 0x8100, b"GamebryoClient::VidRestart\0");
        let prerender = 0x1000;
        let restart = 0x2000;
        let mut check = vec![0x48, 0x8b, 0xc4, 0x55, 0x57, 0x80, 0xb9];
        check.extend_from_slice(&0x222a3u32.to_le_bytes());
        check.extend_from_slice(&[0x00, 0x74, 0x05]);
        call(&mut check, prerender, restart);
        lea(&mut check, prerender, 0x48, 0x05, 0x8000);
        check.push(0xc3);
        let mut clear = vec![0x48, 0x8b, 0xd9, 0xc6, 0x83];
        clear.extend_from_slice(&0x222a3u32.to_le_bytes());
        clear.push(0x00);
        lea(&mut clear, restart, 0x48, 0x05, 0x8100);
        clear.push(0xc3);
        for (addr, bytes) in [(prerender, check.as_slice()), (restart, clear.as_slice())] {
            put(&mut image, addr, bytes);
            image.functions.push(Function {
                start: addr,
                end: addr + bytes.len() as u32,
            });
        }
        let found = video_manager(&image).unwrap();
        assert_eq!(found.target_rva, prerender);
        assert_eq!(found.overwrite_size, 5);
        assert_eq!(found.locations["pending_change_offset"], 0x222a3);
        assert_eq!(found.dependencies["video_restart"], restart);

        put(&mut image, restart + 5, &0x222a4u32.to_le_bytes());
        assert!(video_manager(&image).is_err());
    }
}
