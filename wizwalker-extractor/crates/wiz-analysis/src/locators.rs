//! Find hook sites using byte patterns and decoded instructions.
use super::{evidence, finding, Evidence, Finding};
use crate::{pe::Image, x64, Error, Result};
use std::collections::BTreeMap;

pub const GAME_MODULE: &str = "WizardGraphicalClient.exe";
pub const USER32_MODULE: &str = "user32.dll";
pub const CURSOR_NAME: &str = "mouseless_cursor";
pub const CURSOR_TARGET_EXPORT: &str = "GetCursorPos";
pub const CURSOR_SET_EXPORT: &str = "SetCursorPos";
pub const CURSOR_OVERWRITE_SIZE: usize = 5;
#[derive(Clone, Copy)]
pub struct Locator {
    pub name: &'static str,
    pub signature: &'static str,
    pub offset: u32,
    pub overwrite: usize,
}
pub const CLIENT: Locator = Locator {
    name: "core.client",
    signature: concat!(
        "18 48 ?? ?? ?? ?? ?? ?? 48 8B 7C 24 ?? 48 85 FF 74 29 8B C6 F0 0F ",
        "C1 47 08 83 F8 01 75 1D 48 8B 07 48 8B CF FF 50 08 F0 0F C1 77 0C",
    ),
    offset: 1,
    overwrite: 15,
};
pub const PLAYER: Locator = Locator {
    name: "core.player",
    signature: concat!(
        "F2 0F 10 40 58 F2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ",
        "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
    ),
    offset: 0,
    overwrite: 0,
};
pub const QUEST: Locator = Locator {
    name: "core.quest",
    signature: "F3 41 0F 10 ?? FC 0C 00 00 F3 0F 11 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
    offset: 0,
    overwrite: 0,
};
pub const PLAYER_STAT: Locator = Locator {
    name: "core.player_stat",
    signature: concat!(
        "0F 5B C0 F3 0F 59 81 3C 03 00 00 E8 ?? ?? ?? ?? ",
        "2B D8 B8 ?? ?? ?? ?? 0F 49 C3 48 83 C4 20 5B C3",
    ),
    offset: 3,
    overwrite: 0,
};
pub const ROOT_WINDOW: Locator = Locator {
    name: "core.root_window",
    signature: concat!(
        "?? 8B ?? ?? ?? ?? ?? 48 8B 01 ?? ?? ?? ?? ?? ?? ",
        "?? FF 50 70 84 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??",
    ),
    offset: 0,
    overwrite: 0,
};
pub const RENDER_CONTEXT: Locator = Locator {
    name: "core.render_context",
    signature: concat!(
        "F3 44 0F 10 8B 98 00 00 00 ?? ?? ?? ?? ?? ?? ?? ",
        "?? ?? F3 41 0F 10 28 F3 0F 10 56 04 48 63 C1 ??",
    ),
    offset: 0,
    overwrite: 0,
};
pub const CORE: [Locator; 6] = [
    CLIENT,
    PLAYER,
    QUEST,
    PLAYER_STAT,
    ROOT_WINDOW,
    RENDER_CONTEXT,
];
pub const DANCE: Locator = Locator {
    name: "dance_game_moves",
    signature: "48 8B F8 48 39 70 10",
    offset: 0,
    overwrite: 7,
};
// Match the patterns used by WizWalker's drops toggle and WizSprinter's resize hooks.
pub const LEGACY: [Locator; 3] = [
    Locator {
        name: "drops_toggle",
        signature:
            "4C 8B DC 48 83 EC 68 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 ?? 48 8D 05 ?? ?? ?? ??",
        offset: 0,
        overwrite: 7,
    },
    Locator {
        name: "resize.set_mode",
        signature: concat!(
            "48 89 5C 24 08 44 89 4C 24 20 44 89 44 24 18 89 54 24 10 ",
            "55 56 57 41 54 41 55 41 56 41 57 48 81 EC B0 00 00 00",
        ),
        offset: 0,
        overwrite: 5,
    },
    Locator {
        name: "resize.wndproc_hit_test",
        signature: concat!(
            "48 83 EC 38 4C 8B D1 48 8B 0D ?? ?? ?? ?? ",
            "48 85 C9 74 1C 48 8B 01 4C 89 4C ?? 20 4D 8B C8",
        ),
        offset: 0,
        overwrite: 7,
    },
];
pub(super) const LEGACY_VIDEO_MANAGER: Locator = Locator {
    name: "resize.video_manager",
    signature: concat!(
        "48 8B C4 48 89 58 10 48 89 70 18 55 57 41 56 48 8D 68 88 48 81 EC 60 01 00 00 ",
        "0F 29 70 D8 0F 29 78 C8 44 0F 29 40 B8 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 20 48 8B D9",
    ),
    offset: 0,
    overwrite: 7,
};

fn unique_signature(image: &Image, name: &str, signature: &str) -> Result<(u32, usize)> {
    let pattern = signature
        .split_whitespace()
        .map(|b| {
            if b == "??" {
                Ok(None)
            } else {
                u8::from_str_radix(b, 16).map(Some)
            }
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::new(name, "invalid built-in locator"))?;
    let (anchor, byte) = pattern
        .iter()
        .enumerate()
        .find_map(|(n, b)| b.map(|v| (n, v)))
        .ok_or_else(|| Error::new(name, "locator has no fixed bytes"))?;
    let mut found = None;
    let mut count = 0;
    for section in &image.headers.sections {
        if !section.executable {
            continue;
        }
        let data = image.read(section.rva, section.size as usize)?;
        for at in memchr::memchr_iter(byte, data) {
            let Some(start) = at.checked_sub(anchor) else {
                continue;
            };
            let Some(window) = data.get(start..start + pattern.len()) else {
                continue;
            };
            if pattern
                .iter()
                .zip(window)
                .all(|(p, b)| p.is_none_or(|p| p == *b))
            {
                let rva = section.rva + start as u32;
                found = Some(rva);
                count += 1;
            }
        }
    }
    match found {
        Some(rva) if count == 1 => Ok((rva, pattern.len())),
        _ => Err(Error::new(
            name,
            format!("expected a unique locator, found {count}"),
        )),
    }
}

pub fn locate(image: &Image, spec: Locator) -> Result<Finding> {
    let (site, signature_size) = unique_signature(image, spec.name, spec.signature)?;
    let target = site + spec.offset;
    let size = overwrite_span(image, spec.name, target, spec.overwrite.max(5))?;
    if spec.overwrite != 0 && size != spec.overwrite {
        return Err(Error::new(spec.name, "overwrite splits an instruction"));
    }
    let mut locations = BTreeMap::new();
    if spec.name == "core.root_window" {
        let i = x64::decode(image.read(target, size)?, image.address(target)?)?;
        match i.operands.as_slice() {
            [x64::Operand::Register(r), x64::Operand::Memory(m)]
                if i.op == x64::Op::Mov
                    && r.index == 1
                    && r.bits == 64
                    && m.index.is_none()
                    && m.base.is_some()
                    && !matches!(m.base, Some(0 | 4 | 12)) =>
            {
                locations.insert("pointer_base_register".into(), i64::from(m.base.unwrap()));
                locations.insert("pointer_displacement".into(), m.displacement);
            }
            _ => return Err(Error::new(spec.name, "unsupported root pointer load")),
        }
    }
    Ok(Finding {
        module: None,
        target_rva: target,
        overwrite_size: size,
        locations,
        dependencies: BTreeMap::new(),
        dependency_modules: BTreeMap::new(),
        evidence: vec![Evidence {
            module: None,
            rva: site,
            bytes: image.read(site, signature_size)?.to_vec(),
            role: "unique locator and decoded overwrite".into(),
        }],
    })
}

pub(super) fn overwrite_span(image: &Image, name: &str, target: u32, min: usize) -> Result<usize> {
    let window = image.read(target, 32)?;
    let mut size = 0;
    while size < min {
        let i = x64::decode(&window[size..], image.address(target)? + size as u64)?;
        if !i.relocatable() {
            return Err(Error::new(
                name,
                "hook span requires unsupported relocation",
            ));
        }
        size += i.len();
    }
    Ok(size)
}

pub(super) fn duel_manager(image: &Image) -> Result<Finding> {
    let name = "combat.duel_manager";
    let (site, _) = unique_signature(
        image,
        name,
        concat!(
            "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 ?? ?? ?? ?? ?? ?? ?? ",
            "48 85 C9 74 ?? 0F 28 45",
        ),
    )?;
    let load = x64::decode(image.read(site, 7)?, image.address(site)?)?;
    let pointer = load
        .memory_address()?
        .ok_or_else(|| Error::new(name, "missing RIP-relative pointer load"))?;
    let rva = image.rva(pointer)?;
    if !image.headers.sections.iter().any(|section| {
        section.readable
            && !section.executable
            && rva >= section.rva
            && u64::from(rva) + 8 <= u64::from(section.rva) + u64::from(section.size)
    }) {
        return Err(Error::new(
            name,
            "duel-manager pointer is outside readable data",
        ));
    }
    Ok(Finding {
        module: None,
        target_rva: rva,
        overwrite_size: 0,
        locations: BTreeMap::new(),
        dependencies: BTreeMap::new(),
        dependency_modules: BTreeMap::new(),
        evidence: vec![evidence(
            image,
            site,
            load.len(),
            "duel-manager pointer load",
        )?],
    })
}

pub(super) fn cursor(image: &Image, dll: &Image) -> Result<Finding> {
    let get = dll.export_rva(CURSOR_TARGET_EXPORT)?;
    let set = dll.export_rva(CURSOR_SET_EXPORT)?;
    let get_end = get + CURSOR_OVERWRITE_SIZE as u32;
    if (get..get_end).contains(&set)
        || (set..set + 6).contains(&get)
        || !dll.executable(get_end - 1)
        || !dll.executable(set + 5)
    {
        return Err(Error::new(
            CURSOR_NAME,
            "cursor exports lack separate executable spans",
        ));
    }

    // The hook replaces GetCursorPos and skips replaying its overwritten instructions.
    let mut found = finding(dll, get, CURSOR_OVERWRITE_SIZE)?;
    found.module = Some(USER32_MODULE);
    found.evidence[0].module = Some(USER32_MODULE);
    let mut set_evidence = evidence(dll, set, 6, "SetCursorPos entry")?;
    set_evidence.module = Some(USER32_MODULE);
    found.evidence.push(set_evidence);
    found.dependencies.insert("set_cursor_pos".into(), set);
    let sites = cursor_game_sites(image)?;
    found.dependency_modules.extend(
        sites
            .flag_rvas
            .keys()
            .map(|flag| (flag.clone(), GAME_MODULE)),
    );
    found.dependencies.extend(sites.flag_rvas);
    found.evidence.extend(sites.evidence);
    Ok(found)
}

pub struct CursorGameSites {
    pub flag_rvas: BTreeMap<String, u32>,
    pub evidence: Vec<Evidence>,
}

/// Get the cursor flag RVAs from the game executable alone.
pub fn cursor_game_sites(image: &Image) -> Result<CursorGameSites> {
    let mut flag_rvas = BTreeMap::new();
    let mut proof = Vec::new();
    for (flag, signature, offset) in [
        ("cursor_flag_one", "C6 ?? ?? 00 FF 50 18 66 C7", 3),
        ("cursor_flag_two", "C6 86 ?? ?? ?? 00 00 33 FF 89", 6),
    ] {
        let (site, _) = unique_signature(image, CURSOR_NAME, signature)?;
        let instruction = x64::decode(image.read(site, offset + 1)?, image.address(site)?)?;
        if instruction.immediate_offset != Some(offset) || instruction.len() != offset + 1 {
            return Err(Error::new(
                CURSOR_NAME,
                format!("{flag} is not a byte immediate"),
            ));
        }
        flag_rvas.insert(flag.into(), site + offset as u32);
        proof.push(evidence(image, site, instruction.len(), flag)?);
    }
    Ok(CursorGameSites {
        flag_rvas,
        evidence: proof,
    })
}
