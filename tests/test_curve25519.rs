extern crate hacspec;
use hacspec::*;
hacspec_imports!();

extern crate hacspecs;
use hacspecs::curve25519::*;

fn ecdh(s: SerializedScalar, u: SerializedPoint, expected: SerializedPoint) {
    let r = scalarmult(s, u);
    assert_eq!(
        expected.iter().map(|x| U8::declassify(*x)).collect::<Vec<_>>(),
        r.iter().map(|x| U8::declassify(*x)).collect::<Vec<_>>()
    );
}

#[test]
fn test_kat1() {
    let s = SerializedScalar([
        U8(0xa5), U8(0x46), U8(0xe3), U8(0x6b), U8(0xf0), U8(0x52), U8(0x7c),
        U8(0x9d), U8(0x3b), U8(0x16), U8(0x15), U8(0x4b), U8(0x82), U8(0x46),
        U8(0x5e), U8(0xdd), U8(0x62), U8(0x14), U8(0x4c), U8(0x0a), U8(0xc1),
        U8(0xfc), U8(0x5a), U8(0x18), U8(0x50), U8(0x6a), U8(0x22), U8(0x44),
        U8(0xba), U8(0x44), U8(0x9a), U8(0xc4),
    ]);
    let u = SerializedPoint([
        U8(0xe6), U8(0xdb), U8(0x68), U8(0x67), U8(0x58), U8(0x30), U8(0x30),
        U8(0xdb), U8(0x35), U8(0x94), U8(0xc1), U8(0xa4), U8(0x24), U8(0xb1),
        U8(0x5f), U8(0x7c), U8(0x72), U8(0x66), U8(0x24), U8(0xec), U8(0x26),
        U8(0xb3), U8(0x35), U8(0x3b), U8(0x10), U8(0xa9), U8(0x03), U8(0xa6),
        U8(0xd0), U8(0xab), U8(0x1c), U8(0x4c),
    ]);
    let expected = SerializedPoint([
        U8(0xc3), U8(0xda), U8(0x55), U8(0x37), U8(0x9d), U8(0xe9), U8(0xc6),
        U8(0x90), U8(0x8e), U8(0x94), U8(0xea), U8(0x4d), U8(0xf2), U8(0x8d),
        U8(0x08), U8(0x4f), U8(0x32), U8(0xec), U8(0xcf), U8(0x03), U8(0x49),
        U8(0x1c), U8(0x71), U8(0xf7), U8(0x54), U8(0xb4), U8(0x07), U8(0x55),
        U8(0x77), U8(0xa2), U8(0x85), U8(0x52),
    ]);

    ecdh(s, u, expected);
}

const KAT: [(&str, &str, &str); 5] = [
    (
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    ),
    (
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "2500000000000000000000000000000000000000000000000000000000000000",
        "3c7777caf997b264416077665b4e229d0b9548dc0cd81998ddcdc5c8533c797f",
    ),
    (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "b32d1362c248d62fe62619cff04dd43db73ffc1b6308ede30b78d87380f1e834",
    ),
    (
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    ),
];

#[test]
fn test_kat() {
    for kat in KAT.iter() {
        let s = SerializedScalar::from(kat.0);
        let u = SerializedPoint::from(kat.1);
        let expected = SerializedPoint::from(kat.2);

        ecdh(s, u, expected);
    }
}
