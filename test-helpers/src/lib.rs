use hex::FromHex;
use keccak_hash::keccak_256;
use secp256k1::{ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey, SECP256K1};
use serde::Serialize;
use serde_bytes::Bytes;
use serde_cbor::ser::Serializer;
use sp_core::ecdsa::{Public, Signature};
use sp_io::crypto::ecdsa_verify_prehashed;

#[derive(Serialize)]
pub struct ProofData<'a> {
    pub ig_username: &'a str,
    pub ig_account_type: &'a str,
    pub initiator_pkey: &'a Bytes,
}

pub fn calculate_recovery_id(
    public_key: [u8; 33],
    signature: &[u8; 64],
    message: &String,
) -> Result<u8, String> {
    let pub_key: Public = Public::from_raw(public_key);

    let message_vec: Vec<u8> = <Vec<u8>>::from_hex(message).unwrap_or_default();
    let mut message_hash: [u8; 32] = [0u8; 32];
    keccak_256(&message_vec[..], &mut message_hash);

    for i in 0..4 {
        let mut signature_vec: Vec<u8> = signature.to_vec();
        signature_vec.push(i);
        let signature_with_recovery_id: [u8; 65] = signature_vec.try_into().unwrap_or([0u8; 65]);
        let sig: Signature = Signature::from_raw(signature_with_recovery_id);

        if ecdsa_verify_prehashed(&sig, &message_hash, &pub_key) {
            return Ok(i);
        }
    }

    Err("Failed to calculate recovery id".to_string())
}

pub fn generate_keys() -> (SecretKey, PublicKey) {
    let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
    let secret_key: SecretKey =
        SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key: PublicKey = PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

pub fn get_dummy_message_hex() -> String {
    String::from("64756d6d79")
}

pub fn get_invalid_message_hex() -> String {
    String::from("qwerty")
}

pub fn get_message(cbor_proof_data: &Vec<u8>) -> Message {
    let mut message_hash: [u8; 32] = [0u8; 32];
    keccak_256(&cbor_proof_data[..], &mut message_hash);
    let message: Message = Message::from_slice(&message_hash).expect("32 bytes");
    message
}

pub fn get_proof_data<'a>() -> (ProofData<'a>, Vec<u8>) {
    let initiator_pkey: &Bytes = Bytes::new(&[
        60, 145, 97, 163, 14, 245, 9, 222, 232, 176, 86, 18, 224, 229, 243, 11, 44, 109, 9, 70, 93,
        245, 137, 203, 224, 43, 235, 100, 81, 105, 129, 146,
    ]);
    let proof_data: ProofData = ProofData {
        ig_username: "dummy-ig-username",
        ig_account_type: "dummy-ig-account-type",
        initiator_pkey,
    };
    let mut cbor_proof_data: Vec<u8> = Vec::new();
    let mut serializer: Serializer<&mut Vec<u8>> = Serializer::new(&mut cbor_proof_data);
    proof_data.serialize(&mut serializer).unwrap();
    (proof_data, cbor_proof_data)
}

pub fn get_signature(message: Message, secret_key: SecretKey) -> [u8; 64] {
    let recoverable_signature: RecoverableSignature =
        SECP256K1.sign_ecdsa_recoverable(&message, &secret_key);
    let signature: [u8; 64] = recoverable_signature.serialize_compact().1;
    signature
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_dummy_message_hex_works() {
        assert_eq!(get_dummy_message_hex(), "64756d6d79");
    }

    #[test]
    fn get_invalid_message_hex_works() {
        assert_eq!(get_invalid_message_hex(), "qwerty");
    }
}
