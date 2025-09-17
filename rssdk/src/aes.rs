use aes_gcm::aead::rand_core::RngCore as _;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Error, Nonce};

/// Encrypts data using AES-GCM.
/// key must be 32 bytes (AES-256), nonce must be 12 bytes.
pub fn aes_encrypt(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error)?;
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, data)
}

/// Decrypts data using AES-GCM.
/// key must be 32 bytes, nonce must be 12 bytes.
pub fn aes_decrypt(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error)?;
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, data)
}

/// Generates a random 32-byte AES key.
pub fn generate_aes_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generates a random 12-byte nonce.
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let mut rng = rand::thread_rng();

        // Generate random key and nonce
        let mut key = [0u8; 32]; // 32 bytes for AES-256
        let mut nonce = [0u8; 12]; // 12 bytes for AES-GCM nonce
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);

        let plaintext = b"Test AES encryption and decryption";

        // Encrypt the data
        let ciphertext = aes_encrypt(plaintext, &key, &nonce).expect("Encryption failed");

        // Decrypt the data
        let decrypted = aes_decrypt(&ciphertext, &key, &nonce).expect("Decryption failed");

        // Assert that decrypted text matches original
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_decrypt_with_wrong_key() {
        let mut rng = rand::thread_rng();

        let mut key = [0u8; 32];
        let mut wrong_key = [0u8; 32];
        let mut nonce = [0u8; 12];

        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut wrong_key);
        rng.fill_bytes(&mut nonce);

        let plaintext = b"Sensitive data";

        let ciphertext = aes_encrypt(plaintext, &key, &nonce).expect("Encryption failed");

        // Attempt decryption with wrong key
        let result = aes_decrypt(&ciphertext, &wrong_key, &nonce);

        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_aes_decrypt_with_wrong_nonce() {
        let mut rng = rand::thread_rng();

        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        let mut wrong_nonce = [0u8; 12];

        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut wrong_nonce);

        let plaintext = b"Sensitive data";

        let ciphertext = aes_encrypt(plaintext, &key, &nonce).expect("Encryption failed");

        // Attempt decryption with wrong nonce
        let result = aes_decrypt(&ciphertext, &key, &wrong_nonce);

        assert!(result.is_err(), "Decryption with wrong nonce should fail");
    }
}
