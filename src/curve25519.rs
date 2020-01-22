// Import hacspec and all needed definitions.
use hacspec::prelude::*;

// Define field mod 2^255-19
#[field(7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed)]
struct FieldElement;

// Define 255-bit scalars
#[bits(255)]
struct Scalar;

type Point = (FieldElement, FieldElement);
bytes!(SerializedPoint, 32);
bytes!(SerializedScalar, 32);

fn mask_scalar(s: SerializedScalar) -> SerializedScalar {
    let mut k = s;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

// TODO: drop raw where possible
fn decode_scalar(s: SerializedScalar) -> Scalar {
    let k = mask_scalar(s);
    Scalar::from_bytes_le(&k.raw())
}

fn decode_point(u: SerializedPoint) -> Point {
    let u_ = Scalar::from_bytes_le(&u.raw());
    (
        FieldElement::from_bytes_le(&u_.to_bytes_le()),
        FieldElement::from(1),
    )
}

fn encode_point(p: Point) -> SerializedPoint {
    let (x, y) = p;
    let b = x * y.inv();
    SerializedPoint::from_field(b)
}

fn point_add_and_double(q: Point, nq: Point, nqp1: Point) -> (Point, Point) {
    let (x_1, _z_1) = q;
    let (x_2, z_2) = nq;
    let (x_3, z_3) = nqp1;
    let a = x_2 + z_2;
    let aa = a.pow(2);
    let b = x_2 - z_2;
    let bb = b * b;
    let e = aa - bb;
    let c = x_3 + z_3;
    let d = x_3 - z_3;
    let da = d * a;
    let cb = c * b;

    let x_3 = (da + cb).pow(2);
    let z_3 = x_1 * ((da - cb).pow(2));
    let x_2 = aa * bb;
    let e121665: FieldElement = 121665.into();
    let z_2 = e * (aa + (e121665 * e));
    ((x_2, z_2), (x_3, z_3))
}

fn montgomery_ladder(k: Scalar, init: Point) -> Point {
    let mut acc: (Point, Point) = ((1.into(), 0.into()), init);
    for i in 0..256 {
        if k.bit(255 - i) == 1 {
            // TODO: this is ugly
            let tmp = point_add_and_double(init, acc.1, acc.0);
            acc = (tmp.1, tmp.0);
        } else {
            acc = point_add_and_double(init, acc.0, acc.1);
        }
    }
    acc.0
}

pub fn scalarmult(s: SerializedScalar, p: SerializedPoint) -> SerializedPoint {
    let s_ = decode_scalar(s);
    let p_ = decode_point(p);
    let r = montgomery_ladder(s_, p_);
    encode_point(r)
}

// Test some internal functions.

#[test]
fn test_encode_decode_scalar() {
    let s = SerializedScalar::from([
        0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e,
        0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44,
        0x9a, 0xc4,
    ]);
    let s_expected =
        Scalar::from_hex("449a44ba44226a50185afcc10a4c1462dd5e46824b15163b9d7c52f06be346a0");
    let s_ = decode_scalar(s);
    assert_eq!(s_expected, s_);

    let u = SerializedPoint::from([
        0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f,
        0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab,
        0x1c, 0x4c,
    ]);
    let u_expected = (
        FieldElement::from_hex("4c1cabd0a603a9103b35b326ec2466727c5fb124a4c19435db3030586768dbe6"),
        FieldElement::from_literal(1),
    );
    let u_ = decode_point(u);
    assert_eq!(u_expected, u_);

    let u_encoded = encode_point(u_);
    assert_eq!(u, u_encoded);
}
