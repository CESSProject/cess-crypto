use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use schnorrkel::{Keypair, PublicKey, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use std::error::Error;

pub struct Capsule {
    pub e: RistrettoPoint,
    pub v: RistrettoPoint,
    pub s: Scalar,
}

/// Generate a pre-key capsule and AES key
pub fn gen_pre_key(pk_a: &PublicKey) -> Result<(Capsule, [u8; 32]), Box<dyn Error>> {
    let mut csprng = OsRng;

    let keypair_e = Keypair::generate_with(&mut csprng);
    let keypair_v = Keypair::generate_with(&mut csprng);

    let e_point = ristretto_point_from_pk(&keypair_e.public);
    let v_point = ristretto_point_from_pk(&keypair_v.public);

    let mut hasher = Sha512::new();
    hasher.update(e_point.compress().as_bytes());
    hasher.update(v_point.compress().as_bytes());
    let h_scalar = Scalar::from_hash(hasher);

    // point = pk_a^(e+v)
    let secret_bytes = keypair_v.secret.to_bytes();
    let scalar_v = Scalar::from_bytes_mod_order(
        secret_bytes
            .get(0..32)
            .ok_or("Invalid secret key length for v")?
            .try_into()?,
    );

    let secret_bytes = keypair_e.secret.to_bytes();
    let scalar_e = Scalar::from_bytes_mod_order(
        secret_bytes
            .get(0..32)
            .ok_or("Invalid secret key length for e")?
            .try_into()?,
    );

    let s = scalar_v + scalar_e * h_scalar;
    let scalar_sum = scalar_e + scalar_v;

    let pk_point = ristretto_point_from_pk(pk_a);
    let shared_point = scalar_sum * pk_point;

    let mut hasher = Sha256::new();
    hasher.update(shared_point.compress().as_bytes());
    let key = hasher.finalize();

    Ok((
        Capsule {
            e: e_point,
            v: v_point,
            s,
        },
        key.into(),
    ))
}

/// Decrypt a capsule using the secret key
pub fn decrypt_key(sk: &SecretKey, capsule: &Capsule) -> Result<[u8; 32], Box<dyn Error>> {
    let secret_bytes = sk.to_bytes();
    let sk_scalar = Scalar::from_bytes_mod_order(
        secret_bytes
            .get(0..32)
            .ok_or("Invalid secret key length: expected 32 bytes")?
            .try_into()?,
    );

    let sum = capsule.e + capsule.v;
    let point = sk_scalar * sum;

    let mut hasher = Sha256::new();
    hasher.update(point.compress().as_bytes());
    let key = hasher.finalize();

    Ok(key.into())
}

/// Generate a re-encryption key for skA -> pkB
pub fn gen_re_key(
    sk_a: &SecretKey,
    pk_b: &PublicKey,
) -> Result<(Scalar, PublicKey), Box<dyn Error>> {
    let mut csprng = OsRng;

    // Generate x,X key-pair
    let keypair_x = Keypair::generate_with(&mut csprng);
    let pk_x = keypair_x.public;
    let sk_x_scalar = Scalar::from_bytes_mod_order(keypair_x.secret.to_bytes()[0..32].try_into()?);

    // Compute d = H(X || pk_B || pk_B^x)
    let pk_b_point = ristretto_point_from_pk(pk_b);
    let point = sk_x_scalar * pk_b_point;

    let mut hasher = Sha512::new();
    hasher.update(pk_x.to_bytes());
    hasher.update(pk_b.to_bytes());
    hasher.update(point.compress().as_bytes());
    let d = Scalar::from_hash(hasher);

    // rk = skA * d^-1
    let sk_a_scalar = Scalar::from_bytes_mod_order(sk_a.to_bytes()[0..32].try_into()?);
    let rk = sk_a_scalar * d.invert();

    Ok((rk, pk_x))
}

/// Re-encrypt a capsule using a re-encryption key
pub fn re_encrypt_key(rk: &Scalar, capsule: &Capsule) -> Result<Capsule, Box<dyn Error>> {
    // sG = S * basepoint
    let s_g = capsule.s * RISTRETTO_BASEPOINT_POINT;

    // h = H(E || V)
    let mut hasher = Sha512::new();
    hasher.update(capsule.e.compress().as_bytes());
    hasher.update(capsule.v.compress().as_bytes());
    let h = Scalar::from_hash(hasher);

    // point = V + h * E
    let point = capsule.v + h * capsule.e;

    // Verify capsule
    if point != s_g {
        return Err("invalid params: re-encrypt key verification failed".into());
    }

    // Re-encrypt: E' = rk * E, V' = rk * V
    let new_e = rk * capsule.e;
    let new_v = rk * capsule.v;

    // S stays the same
    let new_s = capsule.s;

    Ok(Capsule {
        e: new_e,
        v: new_v,
        s: new_s,
    })
}

/// Decrypt a re-encrypted capsule using skB and ephemeral public key pkX
pub fn decrypt_re_key(
    sk_b: &SecretKey,
    new_capsule: &Capsule,
    pk_x: &PublicKey,
) -> Result<[u8; 32], Box<dyn Error>> {
    // S = pkX ^ skB
    let sk_b_scalar = Scalar::from_bytes_mod_order(sk_b.to_bytes()[0..32].try_into()?);
    let pk_x_point = ristretto_point_from_pk(pk_x);
    let s_point = sk_b_scalar * pk_x_point;

    // Get pkB from skB
    let pk_b = sk_b.to_public();

    // d = H(pkX || pkB || S)
    let mut hasher = Sha512::new();
    hasher.update(pk_x.to_bytes());
    hasher.update(pk_b.to_bytes());
    hasher.update(s_point.compress().as_bytes());
    let d = Scalar::from_hash(hasher);

    // point = d * (E + V)
    let sum = new_capsule.e + new_capsule.v;
    let point = d * sum;

    // AES key = SHA256(point)
    let mut sha_hasher = Sha256::new();
    sha_hasher.update(point.compress().as_bytes());
    let key = sha_hasher.finalize();

    Ok(key.into())
}

/// Helper: Convert PublicKey to RistrettoPoint
fn ristretto_point_from_pk(pk: &PublicKey) -> RistrettoPoint {
    let compressed = CompressedRistretto(pk.to_bytes());
    compressed.decompress().expect("Invalid public key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use rand::rngs::OsRng;
    use schnorrkel::Keypair;

    #[test]
    fn test_proxy_re_encryption() -> Result<(), Box<dyn std::error::Error>> {
        let mut csprng = OsRng;

        // Generate keypairs for Alice (A), Bob (B), and Carol (C)
        let keypair_a = Keypair::generate_with(&mut csprng);
        let keypair_b = Keypair::generate_with(&mut csprng);
        let keypair_c = Keypair::generate_with(&mut csprng);

        let sk_a = &keypair_a.secret;
        let pk_a = &keypair_a.public;

        let sk_b = &keypair_b.secret;
        let pk_b = &keypair_b.public;

        let sk_c = &keypair_c.secret;

        // Generate pre-key capsule and AES key for Alice
        let (capsule, aes_key) = gen_pre_key(pk_a)?;
        println!("AES key: {}", hex::encode(aes_key));

        // Decrypt capsule with Alice's key
        let de_aes_key = decrypt_key(sk_a, &capsule)?;
        println!("decrypt AES key: {}", hex::encode(de_aes_key));

        // Decrypt capsule with Carol's key (fake)
        let fde_aes_key = decrypt_key(sk_c, &capsule)?;
        println!("decrypt AES key with fake sk: {}", hex::encode(fde_aes_key));

        // Generate re-encryption key for Alice -> Bob
        let (rk, x_pk) = gen_re_key(sk_a, pk_b)?;

        // Re-encrypt the capsule
        let new_capsule = re_encrypt_key(&rk, &capsule)?;

        // Decrypt re-encrypted capsule with Bob
        let dr_aes_key = decrypt_re_key(sk_b, &new_capsule, &x_pk)?;
        println!("decrypt re-encryption AES key: {}", hex::encode(dr_aes_key));

        // Decrypt re-encrypted capsule with Carol (fake)
        let fde_re_aes_key = decrypt_re_key(sk_c, &new_capsule, &x_pk)?;
        println!(
            "decrypt re-encryption AES key with fake skB: {}",
            hex::encode(fde_re_aes_key)
        );

        Ok(())
    }
}
