//! Supported legacy x86-64 encodings.
use crate::{Error, Result};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Op {
    Mov,
    Lea,
    Movzx,
    Movsx,
    Add,
    Or,
    Adc,
    Sbb,
    And,
    Sub,
    Xor,
    Cmp,
    Test,
    Push,
    Pop,
    Call,
    Jump,
    Conditional(u8),
    Return,
    Nop,
    Breakpoint,
    Vector,
    Cmov,
    Setcc,
    Shift,
    Multiply,
    Unary,
    Exchange,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Register {
    pub index: u8,
    pub bits: u16,
    pub vector: bool,
    pub high_byte: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Memory {
    pub base: Option<u8>,
    pub index: Option<u8>,
    pub scale: u8,
    pub displacement: i64,
    pub rip: bool,
    pub bits: u16,
    pub segment: Option<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Operand {
    Register(Register),
    Memory(Memory),
    Immediate(i64),
    Address(u64),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Instruction {
    pub ip: u64,
    pub opcode: u16,
    pub mandatory_prefix: u8,
    pub bytes: Vec<u8>,
    pub op: Op,
    pub operands: Vec<Operand>,
    pub displacement_offset: Option<usize>,
    pub immediate_offset: Option<usize>,
}
impl Instruction {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub fn next_ip(&self) -> Result<u64> {
        self.ip
            .checked_add(self.len() as u64)
            .ok_or_else(|| Error::new("x64", "instruction address overflow"))
    }
    pub fn memory_address(&self) -> Result<Option<u64>> {
        for o in &self.operands {
            if let Operand::Memory(m) = o {
                if m.rip {
                    return add_signed(self.next_ip()?, m.displacement).map(Some);
                }
            }
        }
        Ok(None)
    }
    pub fn relocatable(&self) -> bool {
        !self.operands.iter().any(|o| {
            matches!(
                o,
                Operand::Address(_) | Operand::Memory(Memory { rip: true, .. })
            )
        })
    }
}
pub fn add_signed(base: u64, displacement: i64) -> Result<u64> {
    u64::try_from(i128::from(base) + i128::from(displacement))
        .map_err(|_| Error::new("x64", "address arithmetic overflow"))
}
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::new("x64", "instruction length overflow"))?;
        if end > 15 {
            return Err(Error::new("x64", "instruction exceeds 15 bytes"));
        }
        let v = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| Error::new("x64", "truncated instruction"))?;
        self.pos = end;
        Ok(v)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn signed(&mut self, n: usize) -> Result<i64> {
        let b = self.take(n)?;
        Ok(match n {
            1 => i64::from(b[0] as i8),
            2 => i64::from(i16::from_le_bytes(b.try_into().unwrap())),
            4 => i64::from(i32::from_le_bytes(b.try_into().unwrap())),
            8 => i64::from_le_bytes(b.try_into().unwrap()),
            _ => unreachable!(),
        })
    }
}
fn reg(index: u8, bits: u16, vector: bool, rex: u8) -> Operand {
    Operand::Register(Register {
        index: if bits == 8 && rex == 0 && index >= 4 {
            index - 4
        } else {
            index
        },
        bits,
        vector,
        high_byte: bits == 8 && rex == 0 && index >= 4,
    })
}
fn unsupported(op: u8) -> Error {
    Error::new("x64", format!("unsupported opcode/form {op:#04x}"))
}
fn arithmetic(group: u8) -> Op {
    [
        Op::Add,
        Op::Or,
        Op::Adc,
        Op::Sbb,
        Op::And,
        Op::Sub,
        Op::Xor,
        Op::Cmp,
    ][group as usize]
}

pub fn decode(bytes: &[u8], ip: u64) -> Result<Instruction> {
    let mut r = Reader { bytes, pos: 0 };
    let (mut rex, mut prefix) = (0u8, 0u8);
    let mut lock = false;
    let mut segment = None;
    let mut redundant_66 = false;
    let mut opcode = r.byte()?;
    while matches!(
        opcode,
        0x40..=0x4f | 0x66 | 0xf2 | 0xf3 | 0xf0 | 0x64 | 0x65
    ) {
        if (0x40..=0x4f).contains(&opcode) {
            if rex != 0 {
                return Err(unsupported(opcode));
            }
            rex = opcode;
        } else {
            if rex != 0 {
                return Err(unsupported(opcode));
            }
            if matches!(opcode, 0x64 | 0x65) {
                if segment.replace(opcode).is_some() {
                    return Err(unsupported(opcode));
                }
            } else if opcode == 0xf0 {
                if lock {
                    return Err(unsupported(opcode));
                }
                lock = true;
            } else {
                if prefix != 0 {
                    if prefix == 0x66 && opcode == 0x66 {
                        redundant_66 = true;
                    } else {
                        return Err(unsupported(opcode));
                    }
                }
                prefix = opcode;
            }
        }
        opcode = r.byte()?;
    }
    let bits = if rex & 8 != 0 {
        64
    } else if prefix == 0x66 {
        16
    } else {
        32
    };
    let mut op;
    let mut operands = Vec::new();
    let mut displacement_offset = None;
    let mut immediate_offset = None;
    let (mut modrm, mut width, mut vector, mut reverse, mut imm) =
        (false, bits, false, false, 0usize);
    let mut group = None;
    let mut extended = None;
    match opcode {
        0x50..=0x5f => {
            op = if opcode < 0x58 { Op::Push } else { Op::Pop };
            operands.push(reg(
                (opcode & 7) + ((rex & 1) << 3),
                if prefix == 0x66 { 16 } else { 64 },
                false,
                rex,
            ));
        }
        0x90 => {
            if rex & 1 != 0 || prefix == 0xf2 || prefix == 0xf3 {
                return Err(unsupported(opcode));
            }
            op = Op::Nop;
        }
        0xc3 | 0xc2 => {
            op = Op::Return;
            if opcode == 0xc2 {
                imm = 2;
            }
        }
        0xcc => op = Op::Breakpoint,
        0xe8 | 0xe9 | 0xeb | 0x70..=0x7f => {
            op = match opcode {
                0xe8 => Op::Call,
                0xe9 | 0xeb => Op::Jump,
                _ => Op::Conditional(opcode & 15),
            };
            imm = if matches!(opcode, 0xe8 | 0xe9) { 4 } else { 1 };
        }
        0x68 | 0x6a => {
            op = Op::Push;
            imm = if opcode == 0x6a {
                1
            } else if prefix == 0x66 {
                2
            } else {
                4
            };
        }
        0xb0..=0xbf => {
            op = Op::Mov;
            width = if opcode < 0xb8 { 8 } else { bits };
            operands.push(reg((opcode & 7) + ((rex & 1) << 3), width, false, rex));
            imm = (width / 8) as usize;
        }
        0xa0..=0xa3 => {
            op = Op::Mov;
            width = if opcode & 1 == 0 { 8 } else { bits };
            let at = r.pos;
            let address = r.signed(8)?;
            displacement_offset = Some(at);
            let m = Operand::Memory(Memory {
                base: None,
                index: None,
                scale: 1,
                displacement: address,
                rip: false,
                bits: width,
                segment,
            });
            let a = reg(0, width, false, rex);
            operands = if opcode & 2 == 0 {
                vec![a, m]
            } else {
                vec![m, a]
            };
        }
        0x00..=0x3b if opcode & 7 <= 3 => {
            op = arithmetic(opcode >> 3);
            modrm = true;
            width = if opcode & 1 == 0 { 8 } else { bits };
            reverse = opcode & 2 != 0;
        }
        0x04..=0x3d if opcode & 7 == 4 || opcode & 7 == 5 => {
            op = arithmetic(opcode >> 3);
            width = if opcode & 1 == 0 { 8 } else { bits };
            operands.push(reg(0, width, false, rex));
            imm = if width == 8 {
                1
            } else if width == 16 {
                2
            } else {
                4
            };
        }
        0x63 => {
            if rex & 8 == 0 {
                return Err(unsupported(opcode));
            }
            op = Op::Movsx;
            modrm = true;
            reverse = true;
        }
        0x80 | 0x81 | 0x83 => {
            op = Op::Add;
            modrm = true;
            group = Some(opcode);
            width = if opcode == 0x80 { 8 } else { bits };
            imm = if opcode != 0x81 || width == 8 {
                1
            } else if width == 16 {
                2
            } else {
                4
            };
        }
        0x84 | 0x85 => {
            op = Op::Test;
            modrm = true;
            width = if opcode == 0x84 { 8 } else { bits };
        }
        0x86 | 0x87 => {
            op = Op::Exchange;
            modrm = true;
            width = if opcode == 0x86 { 8 } else { bits };
        }
        0x88..=0x8b => {
            op = Op::Mov;
            modrm = true;
            reverse = opcode & 2 != 0;
            width = if opcode & 1 == 0 { 8 } else { bits };
        }
        0x8d => {
            op = Op::Lea;
            modrm = true;
            reverse = true;
        }
        0x8f => {
            op = Op::Pop;
            modrm = true;
            width = if prefix == 0x66 { 16 } else { 64 };
            group = Some(opcode);
        }
        0x69 | 0x6b => {
            op = Op::Multiply;
            modrm = true;
            reverse = true;
            imm = if opcode == 0x6b {
                1
            } else if bits == 16 {
                2
            } else {
                4
            };
        }
        0xc6 | 0xc7 => {
            op = Op::Mov;
            modrm = true;
            group = Some(opcode);
            width = if opcode == 0xc6 { 8 } else { bits };
            imm = if width == 8 {
                1
            } else if width == 16 {
                2
            } else {
                4
            };
        }
        0xa8 | 0xa9 => {
            op = Op::Test;
            width = if opcode == 0xa8 { 8 } else { bits };
            operands.push(reg(0, width, false, rex));
            imm = if width == 8 {
                1
            } else if width == 16 {
                2
            } else {
                4
            };
        }
        0xc0 | 0xc1 | 0xd0..=0xd3 => {
            op = Op::Shift;
            modrm = true;
            group = Some(opcode);
            width = if opcode & 1 == 0 { 8 } else { bits };
            if opcode < 0xd0 {
                imm = 1;
            }
        }
        0xf6 | 0xf7 | 0xfe | 0xff => {
            op = Op::Unary;
            modrm = true;
            group = Some(opcode);
            width = if opcode == 0xf6 || opcode == 0xfe {
                8
            } else {
                bits
            };
        }
        0x0f => {
            let e = r.byte()?;
            extended = Some(e);
            modrm = true;
            match e {
                0x80..=0x8f => {
                    op = Op::Conditional(e & 15);
                    modrm = false;
                    imm = 4;
                }
                0x40..=0x4f => {
                    op = Op::Cmov;
                    reverse = true;
                }
                0x90..=0x9f => {
                    op = Op::Setcc;
                    width = 8;
                    group = Some(e);
                }
                0xb6 | 0xb7 | 0xbe | 0xbf => {
                    op = if e < 0xbe { Op::Movzx } else { Op::Movsx };
                    reverse = true;
                }
                0xaf => {
                    op = Op::Multiply;
                    reverse = true;
                }
                0xb0 | 0xb1 | 0xc0 | 0xc1 => {
                    op = Op::Exchange;
                    width = if e & 1 == 0 { 8 } else { bits };
                }
                0x1f => {
                    op = Op::Nop;
                    group = Some(e);
                }
                0x71..=0x73 => {
                    if prefix != 0x66 {
                        return Err(unsupported(e));
                    }
                    op = Op::Vector;
                    vector = true;
                    width = 128;
                    imm = 1;
                    group = Some(e);
                }
                0x10
                | 0x11
                | 0x28
                | 0x29
                | 0x2e
                | 0x2f
                | 0x51..=0x59
                | 0x5a
                | 0x5b
                | 0x5c..=0x5f
                | 0x6e
                | 0x6f
                | 0x7e
                | 0x7f
                | 0xef => {
                    let legal = match e {
                        0x28 | 0x29 | 0x2e | 0x2f | 0x54..=0x57 => matches!(prefix, 0 | 0x66),
                        0x52 | 0x53 => matches!(prefix, 0 | 0xf3),
                        0x5b => matches!(prefix, 0 | 0x66 | 0xf3),
                        0xef => prefix == 0x66,
                        _ => true,
                    };
                    if !legal {
                        return Err(unsupported(e));
                    }
                    op = Op::Vector;
                    vector = true;
                    reverse = !matches!(e, 0x11 | 0x29 | 0x7f);
                    width = match prefix {
                        0xf2 => 64,
                        0xf3 => 32,
                        _ => 128,
                    };
                    if matches!(e, 0x28 | 0x29 | 0x54..=0x57 | 0x5b) {
                        width = 128;
                    }
                    if matches!(e, 0x2e | 0x2f) {
                        width = if prefix == 0x66 { 64 } else { 32 };
                    }
                    if e == 0x5a && prefix == 0 {
                        width = 64;
                    }
                    if matches!(e, 0x6f | 0x7f | 0xef) {
                        width = 128;
                        if !matches!(prefix, 0x66 | 0xf3) {
                            return Err(unsupported(e));
                        }
                    }
                    if matches!(e, 0x6e | 0x7e) {
                        if prefix != 0x66 {
                            return Err(unsupported(e));
                        }
                        width = if rex & 8 != 0 { 64 } else { 32 };
                        reverse = e == 0x6e;
                    }
                }
                _ => return Err(unsupported(e)),
            }
        }
        _ => return Err(unsupported(opcode)),
    }
    if redundant_66 && op != Op::Nop {
        return Err(unsupported(opcode));
    }
    if prefix != 0 && !vector && prefix != 0x66 {
        return Err(unsupported(opcode));
    }
    if modrm {
        let m = r.byte()?;
        let mode = m >> 6;
        let g = (m >> 3) & 7;
        let rm = m & 7;
        if let Some(e @ 0x71..=0x73) = extended {
            if mode != 3
                || !(matches!(g, 2 | 6) || g == 4 && e != 0x73 || matches!(g, 3 | 7) && e == 0x73)
            {
                return Err(unsupported(e));
            }
        }
        let register_index = g + ((rex & 4) << 1);
        let register_width =
            if extended.is_some_and(|e| matches!(e, 0xb6 | 0xb7 | 0xbe | 0xbf)) || opcode == 0x63 {
                bits
            } else {
                width
            };
        let rm_width = match extended {
            Some(0xb6 | 0xbe) => 8,
            Some(0xb7 | 0xbf) => 16,
            _ if opcode == 0x63 => 32,
            _ => width,
        };
        let rm_operand = if mode == 3 {
            if opcode == 0x8d {
                return Err(unsupported(opcode));
            }
            reg(
                rm + ((rex & 1) << 3),
                if vector && !matches!(extended, Some(0x6e | 0x7e)) {
                    128
                } else {
                    rm_width
                },
                vector && !matches!(extended, Some(0x6e | 0x7e)),
                rex,
            )
        } else {
            let (mut base, mut index, mut scale, mut rip) =
                (Some(rm + ((rex & 1) << 3)), None, 1, false);
            let mut disp_bytes = match mode {
                1 => 1,
                2 => 4,
                _ => 0,
            };
            if rm == 4 {
                let sib = r.byte()?;
                scale = 1 << (sib >> 6);
                let ix = (sib >> 3) & 7;
                if ix != 4 || rex & 2 != 0 {
                    index = Some(ix + ((rex & 2) << 2));
                }
                let b = sib & 7;
                base = Some(b + ((rex & 1) << 3));
                if mode == 0 && b == 5 {
                    base = None;
                    disp_bytes = 4;
                }
            } else if mode == 0 && rm == 5 {
                base = None;
                rip = true;
                disp_bytes = 4;
            }
            let displacement = if disp_bytes > 0 {
                displacement_offset = Some(r.pos);
                r.signed(disp_bytes)?
            } else {
                0
            };
            Operand::Memory(Memory {
                base,
                index,
                scale,
                displacement,
                rip,
                bits: rm_width,
                segment,
            })
        };
        let rr = reg(
            register_index,
            if vector { 128 } else { register_width },
            vector,
            rex,
        );
        if let Some(gr) = group {
            match opcode {
                0x80 | 0x81 | 0x83 => op = arithmetic(g),
                0xc6 | 0xc7 | 0x8f => {
                    if g != 0 {
                        return Err(unsupported(gr));
                    }
                }
                0xff => {
                    op = match g {
                        0 | 1 => Op::Unary,
                        2 => Op::Call,
                        4 => Op::Jump,
                        6 => Op::Push,
                        _ => return Err(unsupported(gr)),
                    };
                    if matches!(g, 2 | 4 | 6) {
                        width = 64;
                    }
                }
                0xfe => {
                    if g > 1 {
                        return Err(unsupported(gr));
                    }
                }
                0xf6 | 0xf7 => {
                    if g == 1 {
                        return Err(unsupported(gr));
                    }
                    if g == 0 {
                        op = Op::Test;
                        imm = if width == 8 {
                            1
                        } else if width == 16 {
                            2
                        } else {
                            4
                        };
                    }
                }
                0xc0 | 0xc1 | 0xd0..=0xd3 => {
                    if g == 6 {
                        return Err(unsupported(gr));
                    }
                }
                _ => {
                    if extended == Some(0x1f) && g != 0 {
                        return Err(unsupported(gr));
                    }
                }
            }
            let mut rm_operand = rm_operand;
            if let Operand::Register(ref mut v) = rm_operand {
                if opcode == 0xff && matches!(g, 2 | 4 | 6) {
                    v.bits = width;
                }
            }
            if let Operand::Memory(ref mut v) = rm_operand {
                if opcode == 0xff && matches!(g, 2 | 4 | 6) {
                    v.bits = width;
                }
            }
            operands.push(rm_operand);
            if matches!(opcode, 0xd0 | 0xd1) {
                operands.push(Operand::Immediate(1));
            }
            if matches!(opcode, 0xd2 | 0xd3) {
                operands.push(reg(1, 8, false, rex));
            }
        } else {
            operands = if reverse {
                vec![rr, rm_operand]
            } else {
                vec![rm_operand, rr]
            };
        }
    }
    if imm > 0 {
        immediate_offset = Some(r.pos);
        let mut value = r.signed(imm)?;
        if matches!(op, Op::Call | Op::Jump | Op::Conditional(_)) {
            operands.push(Operand::Address(add_signed(
                ip.checked_add((r.pos) as u64)
                    .ok_or_else(|| Error::new("x64", "address overflow"))?,
                value,
            )?));
        } else {
            if imm == 1 && matches!(opcode, 0xb0..=0xb7 | 0xc6 | 0x80 | 0xa8) {
                value = i64::from(value as u8);
            }
            operands.push(Operand::Immediate(value));
        }
    }
    if lock
        && (!matches!(
            op,
            Op::Add
                | Op::Or
                | Op::Adc
                | Op::Sbb
                | Op::And
                | Op::Sub
                | Op::Xor
                | Op::Unary
                | Op::Exchange
        ) || !matches!(operands.first(), Some(Operand::Memory(_))))
    {
        return Err(unsupported(opcode));
    }
    Ok(Instruction {
        ip,
        opcode: extended.map_or(u16::from(opcode), |e| 0x0f00 | u16::from(e)),
        mandatory_prefix: prefix,
        bytes: bytes[..r.pos].to_vec(),
        op,
        operands,
        displacement_offset,
        immediate_offset,
    })
}

/// Encode a 64-bit load from a base register and signed displacement.
/// Register numbers above 15 return an error.
pub fn load64(destination: u8, base: u8, displacement: i32) -> Result<Vec<u8>> {
    if destination > 15 || base > 15 {
        return Err(Error::new("x64 emitter", "register must be in 0..16"));
    }
    let mut b = vec![
        0x48 | ((destination >> 3) << 2) | (base >> 3),
        0x8b,
        0x80 | ((destination & 7) << 3) | (base & 7),
    ];
    if base & 7 == 4 {
        b.push(0x24);
    }
    b.extend_from_slice(&displacement.to_le_bytes());
    Ok(b)
}

pub fn decode_all(bytes: &[u8], ip: u64) -> Result<Vec<Instruction>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let at = ip
            .checked_add(offset as u64)
            .ok_or_else(|| Error::new("x64", "address overflow"))?;
        let i = decode(&bytes[offset..], at)
            .map_err(|e| Error::new(format!("instruction at {at:#x}"), e.to_string()))?;
        offset += i.len();
        out.push(i);
    }
    Ok(out)
}
