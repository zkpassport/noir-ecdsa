use super::ecdsa::{
    verify_brainpoolp192r1_ecdsa, verify_brainpoolp192t1_ecdsa, verify_brainpoolp224r1_ecdsa,
    verify_brainpoolp224t1_ecdsa, verify_brainpoolp256r1_ecdsa, verify_brainpoolp256t1_ecdsa,
    verify_brainpoolp384r1_ecdsa, verify_brainpoolp384t1_ecdsa, verify_brainpoolp512r1_ecdsa,
    verify_brainpoolp512t1_ecdsa, verify_secp192r1_ecdsa, verify_secp224r1_ecdsa,
    verify_secp256r1_ecdsa, verify_secp384r1_ecdsa, verify_secp521r1_ecdsa,
};

use bigcurve::curves::brainpoolP192r1::{BrainpoolP192r1_Fq, BrainpoolP192r1_Fr};
use bigcurve::curves::brainpoolP192t1::{BrainpoolP192t1_Fq, BrainpoolP192t1_Fr};
use bigcurve::curves::brainpoolP224r1::{BrainpoolP224r1_Fq, BrainpoolP224r1_Fr};
use bigcurve::curves::brainpoolP224t1::{BrainpoolP224t1_Fq, BrainpoolP224t1_Fr};
use bigcurve::curves::brainpoolP256r1::{BrainpoolP256r1_Fq, BrainpoolP256r1_Fr};
use bigcurve::curves::brainpoolP256t1::{BrainpoolP256t1_Fq, BrainpoolP256t1_Fr};
use bigcurve::curves::brainpoolP384r1::{BrainpoolP384r1_Fq, BrainpoolP384r1_Fr};
use bigcurve::curves::brainpoolP384t1::{BrainpoolP384t1_Fq, BrainpoolP384t1_Fr};
use bigcurve::curves::brainpoolP512r1::{BrainpoolP512r1_Fq, BrainpoolP512r1_Fr};
use bigcurve::curves::brainpoolP512t1::{BrainpoolP512t1_Fq, BrainpoolP512t1_Fr};
use bigcurve::curves::secp192r1::{Secp192r1_Fq, Secp192r1_Fr};
use bigcurve::curves::secp224r1::{Secp224r1_Fq, Secp224r1_Fr};
use bigcurve::curves::secp256r1::{Secp256r1_Fq, Secp256r1_Fr};
use bigcurve::curves::secp384r1::{Secp384r1_Fq, Secp384r1_Fr};
use bigcurve::curves::secp521r1::{Secp521r1_Fq, Secp521r1_Fr};

// --- NIST P-curves ---------------------------------------------------------

#[export]
fn verify_secp192r1(
    public_key_x: Secp192r1_Fq,
    public_key_y: Secp192r1_Fq,
    message_digest: [u8; 32],
    r: Secp192r1_Fr,
    s: Secp192r1_Fr,
) -> bool {
    verify_secp192r1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_secp224r1(
    public_key_x: Secp224r1_Fq,
    public_key_y: Secp224r1_Fq,
    message_digest: [u8; 32],
    r: Secp224r1_Fr,
    s: Secp224r1_Fr,
) -> bool {
    verify_secp224r1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_secp256r1(
    public_key_x: Secp256r1_Fq,
    public_key_y: Secp256r1_Fq,
    message_digest: [u8; 32],
    r: Secp256r1_Fr,
    s: Secp256r1_Fr,
) -> bool {
    verify_secp256r1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_secp384r1(
    public_key_x: Secp384r1_Fq,
    public_key_y: Secp384r1_Fq,
    message_digest: [u8; 32],
    r: Secp384r1_Fr,
    s: Secp384r1_Fr,
) -> bool {
    verify_secp384r1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_secp521r1(
    public_key_x: Secp521r1_Fq,
    public_key_y: Secp521r1_Fq,
    message_digest: [u8; 32],
    r: Secp521r1_Fr,
    s: Secp521r1_Fr,
) -> bool {
    verify_secp521r1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

// --- Brainpool r1 curves ---------------------------------------------------

#[export]
fn verify_brainpoolp192r1(
    public_key_x: BrainpoolP192r1_Fq,
    public_key_y: BrainpoolP192r1_Fq,
    message_digest: [u8; 32],
    r: BrainpoolP192r1_Fr,
    s: BrainpoolP192r1_Fr,
) -> bool {
    verify_brainpoolp192r1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_brainpoolp224r1(
    public_key_x: BrainpoolP224r1_Fq,
    public_key_y: BrainpoolP224r1_Fq,
    message_digest: [u8; 32],
    r: BrainpoolP224r1_Fr,
    s: BrainpoolP224r1_Fr,
) -> bool {
    verify_brainpoolp224r1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_brainpoolp256r1(
    public_key_x: BrainpoolP256r1_Fq,
    public_key_y: BrainpoolP256r1_Fq,
    message_digest: [u8; 32],
    r: BrainpoolP256r1_Fr,
    s: BrainpoolP256r1_Fr,
) -> bool {
    verify_brainpoolp256r1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_brainpoolp384r1(
    public_key_x: BrainpoolP384r1_Fq,
    public_key_y: BrainpoolP384r1_Fq,
    message_digest: [u8; 32],
    r: BrainpoolP384r1_Fr,
    s: BrainpoolP384r1_Fr,
) -> bool {
    verify_brainpoolp384r1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_brainpoolp512r1(
    public_key_x: BrainpoolP512r1_Fq,
    public_key_y: BrainpoolP512r1_Fq,
    message_digest: [u8; 32],
    r: BrainpoolP512r1_Fr,
    s: BrainpoolP512r1_Fr,
) -> bool {
    verify_brainpoolp512r1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

// --- Brainpool t1 curves ---------------------------------------------------

#[export]
fn verify_brainpoolp192t1(
    public_key_x: BrainpoolP192t1_Fq,
    public_key_y: BrainpoolP192t1_Fq,
    message_digest: [u8; 32],
    r: BrainpoolP192t1_Fr,
    s: BrainpoolP192t1_Fr,
) -> bool {
    verify_brainpoolp192t1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_brainpoolp224t1(
    public_key_x: BrainpoolP224t1_Fq,
    public_key_y: BrainpoolP224t1_Fq,
    message_digest: [u8; 32],
    r: BrainpoolP224t1_Fr,
    s: BrainpoolP224t1_Fr,
) -> bool {
    verify_brainpoolp224t1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_brainpoolp256t1(
    public_key_x: BrainpoolP256t1_Fq,
    public_key_y: BrainpoolP256t1_Fq,
    message_digest: [u8; 32],
    r: BrainpoolP256t1_Fr,
    s: BrainpoolP256t1_Fr,
) -> bool {
    verify_brainpoolp256t1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_brainpoolp384t1(
    public_key_x: BrainpoolP384t1_Fq,
    public_key_y: BrainpoolP384t1_Fq,
    message_digest: [u8; 32],
    r: BrainpoolP384t1_Fr,
    s: BrainpoolP384t1_Fr,
) -> bool {
    verify_brainpoolp384t1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}

#[export]
fn verify_brainpoolp512t1(
    public_key_x: BrainpoolP512t1_Fq,
    public_key_y: BrainpoolP512t1_Fq,
    message_digest: [u8; 32],
    r: BrainpoolP512t1_Fr,
    s: BrainpoolP512t1_Fr,
) -> bool {
    verify_brainpoolp512t1_ecdsa(public_key_x, public_key_y, message_digest, (r, s))
}
