use crate::secp521r1::params::{Secp521r1Fq, Secp521r1Fr};
use crate::secp521r1::curve::{SECP521r1_SCALAR_SLICES, Secp521r1_Params};
use bigcurve::scalar_field::ScalarField;
use dep::bigcurve::CurveParamsTrait;
use bigcurve::BigCurve;
use bignum::BigNum;
use bignum::params::BigNumParamsGetter;
use bigcurve::curves::secp384r1::{Secp384r1Fq, Secp384r1Fr, Secp384r1_Params};
use bigcurve::curves::secp256r1::{Secp256r1Fq, Secp256r1Fr, Secp256r1_Params};

// https://github.com/madztheo/noir-ecdsa/blob/main/lib/src/secp384r1.nr
pub fn verify_ecdsa<let HASH_BYTE_SIZE: u32, let SCALAR_SLICES: u32, let LIMBS: u32, let MODULUS_BIT_SIZE: u32, let BYTES: u32, Fq_PARAMS, Fr_PARAMS, CurveParams>(
    public_key_x: BigNum<LIMBS, MODULUS_BIT_SIZE, Fq_PARAMS>,
    public_key_y: BigNum<LIMBS, MODULUS_BIT_SIZE, Fq_PARAMS>,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BigNum<LIMBS, MODULUS_BIT_SIZE, Fr_PARAMS>, BigNum<LIMBS, MODULUS_BIT_SIZE, Fr_PARAMS>),
) -> bool
where
    Fq_PARAMS: BigNumParamsGetter<LIMBS, MODULUS_BIT_SIZE>,
    Fr_PARAMS: BigNumParamsGetter<LIMBS, MODULUS_BIT_SIZE>,
    CurveParams: CurveParamsTrait<BigNum<LIMBS, MODULUS_BIT_SIZE, Fq_PARAMS>>,
{
    // 1. Unpack the signature (r, s)
    let (r, s) = signature;

    // 2. Pad the message digest to `BYTES` bytes and convert to a BigNum
    let mut formatted_message_digest: [u8; BYTES] = [0; BYTES];
    let mut startIndex = 0;

    if HASH_BYTE_SIZE < BYTES {
        startIndex = BYTES - HASH_BYTE_SIZE;
    }
    for i in startIndex..BYTES {
        formatted_message_digest[i] = message_digest[i - startIndex];
    }
    let e: BigNum<LIMBS, MODULUS_BIT_SIZE, Fr_PARAMS> =
        BigNum::from_be_bytes(formatted_message_digest);

    // 3. Compute w = s^-1 mod n
    let w = s.__invmod();
    // Check that s is the inverse of w since the previous line is unconstrained
    assert(s * w == BigNum::one());

    // 4. Compute u1 = ew mod n and u2 = rw mod n
    let u_1: ScalarField<SCALAR_SLICES> = ScalarField::from_bignum(e * w);
    let u_2: ScalarField<SCALAR_SLICES> = ScalarField::from_bignum(r * w);

    // Convert public key to jacobian coordinates
    let public_key: BigCurve<BigNum<LIMBS, MODULUS_BIT_SIZE, Fq_PARAMS>, CurveParams> =
        BigCurve { x: public_key_x, y: public_key_y, is_infinity: false };
    public_key.validate_on_curve();

    let gen: BigCurve<BigNum<LIMBS, MODULUS_BIT_SIZE, Fq_PARAMS>, CurveParams> = BigCurve::one();

    // 5. Compute the point R = u1G + u2Q
    let r_point = BigCurve::msm([gen, public_key], [u_1, u_2]);

    let r_point_x = r_point.x;
    let r_point_x_as_fr: BigNum<LIMBS, MODULUS_BIT_SIZE, Fr_PARAMS> =
        BigNum { limbs: r_point_x.limbs };
    // 6. The signature is valid if r = R.x (mod n)
    // Need to have them in the same field to do the comparison
    r_point_x_as_fr == r
}

pub fn verify_secp521r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp521r1Fq,
    public_key_y: Secp521r1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp521r1Fr, Secp521r1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 131, _, _, 66, _, _, Secp521r1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_secp384r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp384r1Fq,
    public_key_y: Secp384r1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp384r1Fr, Secp384r1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 97, _, _, 48, _, _, Secp384r1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_secp256r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp256r1Fq,
    public_key_y: Secp256r1Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp256r1Fr, Secp256r1Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 65, _, _, 32, _, _, Secp256r1_Params>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

#[test]
fn test_secp521r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );
    let r: Secp521r1Fr = BigNum {
        limbs: [
            0x5d54ec424d96736a8eb7ab6b38d908,
            0x652b2107a280804afad6f3d2cc0050,
            0xed0e5a379f9fb054d066eb356d254c,
            0xfc86bb58b30a527e65c6f834a6d3db,
            0x4d2cade92f,
        ],
    };
    let s: Secp521r1Fr = BigNum {
        limbs: [
            0xbbbde07f01798860628f5af9dd2a64,
            0x5416a9927335c1e6aae0cf33d44413,
            0xc05b8c91b0f63441f63929b0d065d4,
            0x35905117e2c37f88dcffbd84648d9f,
            0x8412499ba5,
        ],
    };
    let public_key_x: Secp521r1Fq = BigNum {
        limbs: [
            0xe976cfcef3735cd6b59ac2014c4ae3,
            0xbc1c4e1989e7b94f353e9194948ed0,
            0xdea95c2502cfe36a3479a18960cf40,
            0x69b79211e183033c2f123720e96888,
            0x191ceb966f3,
        ],
    };
    let public_key_y: Secp521r1Fq = BigNum {
        limbs: [
            0xe10762c5d5f93c2754f5172fd76a6a,
            0x4d432eaa4382eaaace7018ff2268b,
            0x5e8326529e8b8bcf701c5d29bf70d6,
            0xb494cf3fb13e60d4619a41c13775cd,
            0x1c03b12ef33,
        ],
    };
    assert(verify_secp521r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

#[test]
fn test_secp384r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );
    let r: Secp384r1Fr = BigNum {
        limbs: [
            0xeb06adc631cd09d17ed3268f65e288,
            0x4102680df5a59b6fc9f8f38cd01016,
            0x272042bb400a185ba04fefaa7c05ce,
            0x680dc4,
        ],
    };
    let s: Secp384r1Fr = BigNum {
        limbs: [
            0x711084a23ae842fc0e6702c3009784,
            0xe17e64a3c451466091c4c1aae7550f,
            0x017a18c55fc11347e0f27fa8fdb958,
            0x32ec1b,
        ],
    };
    let public_key_x: Secp384r1Fq = BigNum {
        limbs: [
            0x4bb414953ec1391fdbc6ea75e0d61a,
            0xfed1f2c9f9ac404d4bf5c0b267cddb,
            0xd1031dd17188527bc28ade5c97d23c,
            0x41b3d3,
        ],
    };
    let public_key_y: Secp384r1Fq = BigNum {
        limbs: [
            0x23db4726c61ec970c07ff770a2b380,
            0x3270662d9105998b8e26e9575147da,
            0x33e912de6612af790c627629f33de0,
            0x4b834d,
        ],
    };
    assert(verify_secp384r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}

#[test]
fn test_secp256r1_signature_verification() {
    let sha256_hash: [u8; 32] =
        dep::std::hash::sha256("Hello World! This is Noir-ECDSA".as_bytes());
    assert_eq(
        sha256_hash,
        [
            42, 204, 207, 15, 192, 246, 143, 215, 180, 110, 75, 247, 21, 126, 103, 225, 251, 180,
            86, 221, 251, 68, 216, 63, 17, 236, 32, 223, 169, 198, 9, 98,
        ],
    );
    let r: Secp256r1Fr = BigNum {
        limbs: [0x6e6dd8df9cec8c31892d01e14318fb, 0x3109c73f335657be981f6387c44d3c, 0x8e0e],
    };
    let s: Secp256r1Fr = BigNum {
        limbs: [0x262ed99e46e6577a71a75b1d5c7f4a, 0xcefc34f4b68aa019eda376372f2e76, 0x2c2d],
    };
    let public_key_x: Secp256r1Fq = BigNum {
        limbs: [0xd54378ffd74c0a0692ea56dc91e14a, 0xa683ef4c166c55cfb8d135863fc8f9, 0xaa1d],
    };
    let public_key_y: Secp256r1Fq = BigNum {
        limbs: [0x6b6c3604db3440d3dc4ee95a24f0f0, 0xc4eae722e511eeb583122a0f6ab255, 0x4b36],
    };
    assert(verify_secp256r1_ecdsa(public_key_x, public_key_y, sha256_hash, (r, s)));
}
