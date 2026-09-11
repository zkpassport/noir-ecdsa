use bignum::BigNum;
use bignum::bignum::evaluate_quadratic_expression;

use bigcurve::BigCurve;
use bigcurve::curves::brainpoolP192r1::{BrainpoolP192r1, BrainpoolP192r1_Fq, BrainpoolP192r1_Fr};
use bigcurve::curves::brainpoolP192t1::{BrainpoolP192t1, BrainpoolP192t1_Fq, BrainpoolP192t1_Fr};
use bigcurve::curves::brainpoolP224r1::{BrainpoolP224r1, BrainpoolP224r1_Fq, BrainpoolP224r1_Fr};
use bigcurve::curves::brainpoolP224t1::{BrainpoolP224t1, BrainpoolP224t1_Fq, BrainpoolP224t1_Fr};
use bigcurve::curves::brainpoolP256r1::{BrainpoolP256r1, BrainpoolP256r1_Fq, BrainpoolP256r1_Fr};
use bigcurve::curves::brainpoolP256t1::{BrainpoolP256t1, BrainpoolP256t1_Fq, BrainpoolP256t1_Fr};
use bigcurve::curves::brainpoolP384r1::{BrainpoolP384r1, BrainpoolP384r1_Fq, BrainpoolP384r1_Fr};
use bigcurve::curves::brainpoolP384t1::{BrainpoolP384t1, BrainpoolP384t1_Fq, BrainpoolP384t1_Fr};
use bigcurve::curves::brainpoolP512r1::{BrainpoolP512r1, BrainpoolP512r1_Fq, BrainpoolP512r1_Fr};
use bigcurve::curves::brainpoolP512t1::{BrainpoolP512t1, BrainpoolP512t1_Fq, BrainpoolP512t1_Fr};
use bigcurve::curves::secp192r1::{Secp192r1, Secp192r1_Fq, Secp192r1_Fr};
use bigcurve::curves::secp224r1::{Secp224r1, Secp224r1_Fq, Secp224r1_Fr};
use bigcurve::curves::secp256r1::{Secp256r1, Secp256r1_Fq, Secp256r1_Fr};
use bigcurve::curves::secp384r1::{Secp384r1, Secp384r1_Fq, Secp384r1_Fr};
use bigcurve::curves::secp521r1::{Secp521r1, Secp521r1_Fq, Secp521r1_Fr};
use bigcurve::ScalarField;

pub fn verify_ecdsa<let HASH_BYTE_SIZE: u32, let SCALAR_SLICES: u32, Fq, Fr, Curve>(
    public_key_x: Fq,
    public_key_y: Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Fr, Fr),
) -> bool
where
    Fr: BigNum,
    Fr: std::convert::From<Field>,
    Fr: std::cmp::Ord,
    Fq: BigNum,
    Curve: BigCurve<Fq>,
{
    // 1. Unpack the signature (r, s)
    let (r, s): (Fr, Fr) = signature;
    // Note: r and s are expected to be valid field elements.

    // 2.1 Validate that r != 0 (mod n). `assert_is_not_zero` is the modular check
    // (it treats the modulus itself as zero), so it holds even for a non-canonical r == n.
    r.assert_is_not_zero();

    // 2.2 Validate that s is in canonical form (s <= n/2) to prevent signature malleability
    // i.e. you could have two valid signatures (r, s) and (r, n - s) from one signature (r, s)

    let n: Fr = Fr::modulus();

    // Both operands are circuit constants (the modulus and 2), so n_half is fully
    // determined, effectively a compile-time value with no prover freedom.
    // We use `udiv_unsafe` (skips `validate_in_field` on the inputs) on purpose: the
    // numerator is the modulus itself, so the safe `udiv` would assert `n < n` and fail
    let n_half: Fr = n.udiv_unsafe(&Fr::from(2));

    assert(s <= n_half, "Signature s value is not in canonical form");

    // 3. Pad the message digest to number of bytes of Fr and convert to a BigNum
    let mut formatted_message_digest = Fr::zero().to_be_bytes();
    let mut startIndex: u32 = 0;

    if HASH_BYTE_SIZE < formatted_message_digest.len() {
        startIndex = formatted_message_digest.len() - HASH_BYTE_SIZE;
    }
    for i in startIndex..formatted_message_digest.len() {
        formatted_message_digest[i] = message_digest[i - startIndex];
    }
    // `from_be_bytes_unsafe` (not the canonical-validating `from_be_bytes`): in ECDSA the
    // message representative `e` may be >= n. It is reduced mod n only when used (e.g.
    // `u1 = e * w`), so requiring `e < n` would wrongly reject valid signatures whose digest
    // is >= n. This is sound because `e`'s bytes are fixed by `message_digest`, leaving the
    // prover no non-canonical representation to choose.
    let e: Fr = Fr::from_be_bytes_unsafe(formatted_message_digest);

    // 4. Compute w = s^-1 mod n
    // Safety: we constrain the w to be an inverse later
    let w: Fr = unsafe { s.__invmod() };

    // Constrain s * w == 1 (mod n). Equivalent to `assert(s * w == Fr::one())` but cheaper:
    // it constrains `s*w + (-1) == 0` directly rather than materializing the reduced product
    evaluate_quadratic_expression(
        [[s]],
        [[false]],
        [[w]],
        [[false]],
        [Fr::one().neg()],
        [false],
    );

    // 5. Compute u1 = ew mod n and u2 = rw mod n
    let u_1: ScalarField<SCALAR_SLICES> = ScalarField::from_bignum(e * w);
    let u_2: ScalarField<SCALAR_SLICES> = ScalarField::from_bignum(r * w);

    // Convert the public key to a curve point.
    // SECURITY: an off-curve / invalid-curve public key must be rejected, otherwise a prover
    // could forge a passing verification (invalid-curve attack).
    let public_key = Curve::from_coordinates(public_key_x, public_key_y, false);

    // `from_coordinates` does not check the point is on the curve yet, so we do it explicitly.
    // TODO(sasha): remove when the bigcurve is updated (from_coordinates will validate on curve).
    public_key.validate_on_curve();

    let gen = Curve::one();

    // 6. Compute the point R = u1 * G + u2 * Q
    let r_point = Curve::evaluate_linear_expression([gen, public_key], [u_1, u_2], []);

    // 7. The signature is valid iff r == R.x (mod n).
    let r_point_x: Fq = r_point.x();

    // `r_point.x()` is only constrained to < 2^MOD_BITS, not canonical, so for small
    // X the prover could supply X or X + p. Force it into [0, p) so the check can't
    // also accept the non-canonical r == (R.x + p) mod n.
    r_point_x.validate_in_field();

    // R.x lives in Fq (the base field). We cast it into Fr limb by limb, which works for our
    // supported curves.
    // The rule is bitlen(Fq) <= bitlen(Fr): if Fq has more bits than Fr, R.x
    // could overflow Fr's range. Check the bit lengths, don't assume - cofactor > 1 is a red
    // flag (n << p), but even a cofactor-1 curve can have bitlen(Fq) > bitlen(Fr) when p sits
    // just above a power of two.
    // (Fr wider than Fq is fine)
    let mut r_point_x_as_fr = Fr::zero();
    for i in 0..Fr::zero().num_limbs() {
        r_point_x_as_fr.set_limb(i, r_point_x.get_limb(i));
    }

    r_point_x_as_fr.eq(r)
}

pub fn verify_secp521r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp521r1_Fq,
    public_key_y: Secp521r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp521r1_Fr, Secp521r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 131, Secp521r1_Fq, Secp521r1_Fr, Secp521r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_secp384r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp384r1_Fq,
    public_key_y: Secp384r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp384r1_Fr, Secp384r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 97, Secp384r1_Fq, Secp384r1_Fr, Secp384r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_secp256r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp256r1_Fq,
    public_key_y: Secp256r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp256r1_Fr, Secp256r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 65, Secp256r1_Fq, Secp256r1_Fr, Secp256r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_secp224r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp224r1_Fq,
    public_key_y: Secp224r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp224r1_Fr, Secp224r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 57, Secp224r1_Fq, Secp224r1_Fr, Secp224r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_secp192r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp192r1_Fq,
    public_key_y: Secp192r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp192r1_Fr, Secp192r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 49, Secp192r1_Fq, Secp192r1_Fr, Secp192r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp192r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP192r1_Fq,
    public_key_y: BrainpoolP192r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP192r1_Fr, BrainpoolP192r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 49, BrainpoolP192r1_Fq, BrainpoolP192r1_Fr, BrainpoolP192r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp192t1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP192t1_Fq,
    public_key_y: BrainpoolP192t1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP192t1_Fr, BrainpoolP192t1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 49, BrainpoolP192t1_Fq, BrainpoolP192t1_Fr, BrainpoolP192t1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp224r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP224r1_Fq,
    public_key_y: BrainpoolP224r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP224r1_Fr, BrainpoolP224r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 57, BrainpoolP224r1_Fq, BrainpoolP224r1_Fr, BrainpoolP224r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp224t1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP224t1_Fq,
    public_key_y: BrainpoolP224t1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP224t1_Fr, BrainpoolP224t1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 57, BrainpoolP224t1_Fq, BrainpoolP224t1_Fr, BrainpoolP224t1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp256r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP256r1_Fq,
    public_key_y: BrainpoolP256r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP256r1_Fr, BrainpoolP256r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 65, BrainpoolP256r1_Fq, BrainpoolP256r1_Fr, BrainpoolP256r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp256t1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP256t1_Fq,
    public_key_y: BrainpoolP256t1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP256t1_Fr, BrainpoolP256t1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 65, BrainpoolP256t1_Fq, BrainpoolP256t1_Fr, BrainpoolP256t1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp384r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP384r1_Fq,
    public_key_y: BrainpoolP384r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP384r1_Fr, BrainpoolP384r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 97, BrainpoolP384r1_Fq, BrainpoolP384r1_Fr, BrainpoolP384r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp384t1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP384t1_Fq,
    public_key_y: BrainpoolP384t1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP384t1_Fr, BrainpoolP384t1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 97, BrainpoolP384t1_Fq, BrainpoolP384t1_Fr, BrainpoolP384t1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp512r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP512r1_Fq,
    public_key_y: BrainpoolP512r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP512r1_Fr, BrainpoolP512r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 129, BrainpoolP512r1_Fq, BrainpoolP512r1_Fr, BrainpoolP512r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}

pub fn verify_brainpoolp512t1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: BrainpoolP512t1_Fq,
    public_key_y: BrainpoolP512t1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (BrainpoolP512t1_Fr, BrainpoolP512t1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 129, BrainpoolP512t1_Fq, BrainpoolP512t1_Fr, BrainpoolP512t1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}
