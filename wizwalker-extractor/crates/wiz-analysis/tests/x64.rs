use wiz_analysis::x64::{self, Memory, Op, Operand};
fn bytes(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect()
}
#[test]
fn independent_instruction_boundaries_and_operands() {
    // Encodings checked against the investigation's independent disassembly.
    for (hex, len, op) in [
        ("48 8b 45 a0", 4, Op::Mov),
        ("4c 8b bc 24 80 00 00 00", 8, Op::Mov),
        ("48 8d 4d 18", 4, Op::Lea),
        ("66 66 0f 1f 84 00 00 00 00 00", 10, Op::Nop),
        ("65 48 8b 04 25 58 00 00 00", 9, Op::Mov),
        ("0f 84 98 07 00 00", 6, Op::Conditional(4)),
        ("48 c7 44 24 20 fe ff ff ff", 9, Op::Mov),
        ("66 0f 73 d8 08", 5, Op::Vector),
    ] {
        let b = bytes(hex);
        let i = x64::decode(&b, 0x1000).unwrap();
        assert_eq!(i.len(), len, "{hex}");
        assert_eq!(i.op, op, "{hex}");
        for n in 0..b.len() {
            assert!(
                x64::decode(&b[..n], 0x1000).is_err(),
                "truncation {n}: {hex}"
            );
        }
    }
    let i = x64::decode(&bytes("48 8b 45 a0"), 0).unwrap();
    assert!(matches!(
        i.operands[1],
        Operand::Memory(Memory {
            base: Some(5),
            displacement: -96,
            bits: 64,
            ..
        })
    ));
    let i = x64::decode(&bytes("4c 8b bc 24 80 00 00 00"), 0).unwrap();
    assert!(matches!(i.operands[0],Operand::Register(r) if r.index==15&&r.bits==64));
    let i = x64::decode(&bytes("41 8a 24 8c"), 0).unwrap();
    assert!(matches!(
        i.operands[1],
        Operand::Memory(Memory {
            base: Some(12),
            index: Some(1),
            scale: 4,
            ..
        })
    ));
}
#[test]
fn relative_addresses_and_overflow_are_checked() {
    let i = x64::decode(&bytes("48 8d 05 f9 ff ff ff"), 0x1000).unwrap();
    assert_eq!(i.memory_address().unwrap(), Some(0x1000));
    assert!(!i.relocatable());
    assert!(x64::decode(&bytes("e8 00 00 00 00"), u64::MAX - 2).is_err());
    assert!(x64::decode(&bytes("eb 80"), 0).is_err());
}
#[test]
fn high_byte_aliases_and_rex_are_distinct() {
    let a = x64::decode(&bytes("88 e0"), 0).unwrap();
    let b = x64::decode(&bytes("40 88 e0"), 0).unwrap();
    assert!(matches!(a.operands[1],Operand::Register(r) if r.high_byte&&r.index==0));
    assert!(matches!(b.operands[1],Operand::Register(r) if !r.high_byte&&r.index==4));
}
#[test]
fn unsupported_forms_never_supply_a_length() {
    for b in [
        bytes("c5 f8 77"),
        bytes("62 f1 7c 48 58 c0"),
        bytes("67 48 8b 00"),
        bytes("0f 38 00 c0"),
        bytes("48 c7 c8 00 00 00 00"),
        bytes("f0 48 8b 00"),
        vec![0x66; 16],
    ] {
        assert!(x64::decode(&b, 0).is_err(), "{b:x?}");
    }
}
#[test]
fn typed_load_emitter_covers_extended_registers_sib_and_signed_displacements() {
    for dst in 0..16 {
        for base in 0..16 {
            for disp in [i32::MIN, -128, 0, 127, i32::MAX] {
                let b = x64::load64(dst, base, disp).unwrap();
                let i = x64::decode(&b, 0).unwrap();
                assert!(matches!(i.operands[0],Operand::Register(r) if r.index==dst&&r.bits==64));
                assert!(
                    matches!(i.operands[1],Operand::Memory(m) if m.base==Some(base)&&m.displacement==i64::from(disp)&&m.index.is_none())
                );
            }
        }
    }
    assert_eq!(
        x64::load64(0, 5, -96).unwrap(),
        bytes("48 8b 85 a0 ff ff ff")
    );
    assert!(x64::load64(16, 0, 0).is_err());
}
#[test]
fn deterministic_adversarial_inputs_are_bounded() {
    let mut seed = 0x123456789abcdefu64;
    for _ in 0..20000 {
        let mut b = [0u8; 16];
        for x in &mut b {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *x = seed as u8;
        }
        if let Ok(i) = x64::decode(&b, 0x1000) {
            assert!((1..=15).contains(&i.len()));
            assert_eq!(i.bytes, &b[..i.len()]);
        }
    }
}
