#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod silentdata {
    const ERROR_MESSAGE: &str = "Incorrect message or signature";

    use hex::FromHex;
    use ink::env::hash::{HashOutput, Keccak256};
    use ink::prelude::{string::String, string::ToString, vec::Vec};
    use minicbor::Decoder;

    #[ink(storage)]
    pub struct Silentdata {
        enclave_public_key: String,
    }

    impl Silentdata {
        /// Constructor that initializes the `enclave_public_key` value to the given `enclave_public_key`.
        ///
        /// # Arguments
        /// * `enclave_public_key` - The hex encoded enclave public key.
        #[ink(constructor)]
        pub fn new(enclave_public_key: String) -> Self {
            Self { enclave_public_key }
        }

        /// Verifies that a Silent Data Instagram account ownership proof certificate has been signed by a secure enclave,
        /// parses the certificate and returns the Instagram username.
        ///
        /// # Arguments
        ///
        /// * `signature` - The hex encoded Secp256k1 signature of the `message` (with recovery ID). For the verification to succeed
        /// the signature must have been produced by the private key corresponding to the `enclave_public_key` that the pallet was instantiated with.
        /// * `message` - The hex encoded Silent Data proof certificate. The certificate is a CBOR encoded map of key-value pairs.
        ///
        /// # Errors
        ///
        /// * `"Incorrect message or signature"` - The signature could not be verified, either the `signature` or `message` are incorrect or the
        /// signature was produced by an invalid private key.
        #[ink(message)]
        pub fn verify_and_decode(&self, signature: String, message: String) -> String {
            if self.verify(&signature, &message) {
                self.decode(&message)
            } else {
                ERROR_MESSAGE.to_string()
            }
        }

        /// Returns `true` if the `enclave_public_key` matches the recovered ECDSA public key for a given `signature` and `message.
        ///
        /// # Arguments
        ///
        /// * `signature` - The hex encoded Secp256k1 signature of the `message` (with recovery ID). For the verification to succeed
        /// the signature must have been produced by the private key corresponding to the `enclave_public_key` that the pallet was instantiated with.
        /// * `message` - The hex encoded Silent Data proof certificate. The certificate is a CBOR encoded map of key-value pairs.
        pub fn verify(&self, signature: &String, message: &String) -> bool {
            let signature_array: [u8; 65] = <[u8; 65]>::from_hex(signature).unwrap_or([0u8; 65]);

            let message_vec: Vec<u8> = <Vec<u8>>::from_hex(message).unwrap_or_default();
            let mut message_hash: [u8; 32] = <Keccak256 as HashOutput>::Type::default();
            ink::env::hash_bytes::<Keccak256>(&message_vec[..], &mut message_hash);

            let mut output: [u8; 33] = [0; 33];

            ink::env::ecdsa_recover(&signature_array, &message_hash, &mut output)
                .unwrap_or_default();

            let enclave_public_key: [u8; 33] =
                <[u8; 33]>::from_hex(self.enclave_public_key.as_str()).unwrap_or([0u8; 33]);

            output == enclave_public_key
        }

        /// Returns the `ig_username` of a CBOR encoded message.
        /// Returns empty string when `ig_username` is not present.
        ///
        /// # Arguments
        ///
        /// * `message` - The hex encoded Silent Data proof certificate. The certificate is a CBOR encoded map of key-value pairs.
        ///
        /// Proof certificate example:
        ///
        /// {
        ///   certificate_hash: 0x6d2dc3813f958d45582829713f35371b751d9feda656cbc383c5dcbff16e778a,
        ///   check_hash: 0x17eb70034b5b71092521d184c5e7b069d47de657e51aef2be11a00c115036943,
        ///   id: 'ab918303-9c0e-4b0b-8697-5910d6520e1a',
        ///   ig_account_type: 'PERSONAL',
        ///   ig_username: 'aninstagramuser',
        ///   initiator_pkey: 0x0260a2abbfcc8eb272ed36f4685214d24e1a0fae48af77edef05c695b8d8f212,
        ///   timestamp: 1679313407
        /// }
        pub fn decode(&self, message: &String) -> String {
            let message_vec: Vec<u8> = <Vec<u8>>::from_hex(message).unwrap_or_default();

            let mut decoder: Decoder = Decoder::new(&message_vec[..]);

            let size: u64 = decoder.map().unwrap_or_default().unwrap_or_default();

            let mut ig_username: String = "".to_string();

            for _ in 0..size {
                let key: &str = decoder.str().unwrap_or_default();

                if key == "ig_username" {
                    ig_username = decoder.str().unwrap_or_default().to_string();
                } else {
                    decoder.skip().unwrap_or_default();
                }
            }

            ig_username
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use test_helpers::{
            calculate_recovery_id, generate_keys, get_dummy_message_hex, get_invalid_message_hex,
            get_message, get_proof_data, get_signature, ProofData,
        };

        #[ink::test]
        fn verify_and_decode_works() {
            let (secret_key, public_key) = generate_keys();

            let public_key_hex: String = hex::encode(public_key.serialize());
            let public_key_array: [u8; 33] =
                <[u8; 33]>::from_hex(public_key_hex.as_str()).unwrap_or([0u8; 33]);

            let (proof_data, cbor_proof_data): (ProofData, Vec<u8>) = get_proof_data();

            let message = get_message(&cbor_proof_data);
            let message_hex: String = hex::encode(cbor_proof_data.as_slice());

            let signature: [u8; 64] = get_signature(message, secret_key);
            let recovery_id: u8 = calculate_recovery_id(public_key_array, &signature, &message_hex)
                .expect("Calculate recovery id");
            let mut signature_vec: Vec<u8> = signature.to_vec();
            signature_vec.push(recovery_id);
            let signature_with_recovery_id: [u8; 65] =
                signature_vec.try_into().unwrap_or([0u8; 65]);
            let signature_hex: String = hex::encode(signature_with_recovery_id);

            let contract: Silentdata = Silentdata::new(public_key_hex);

            assert_eq!(
                contract.verify_and_decode(signature_hex.clone(), message_hex),
                proof_data.ig_username
            );

            assert_eq!(
                contract.verify_and_decode(signature_hex.clone(), get_dummy_message_hex()),
                ERROR_MESSAGE.to_string()
            );

            assert_eq!(
                contract.verify_and_decode(signature_hex.clone(), get_invalid_message_hex()),
                ERROR_MESSAGE.to_string()
            );
        }

        #[ink::test]
        fn sd_input_works() {
            let public_key_hex: String =
                "0272ff5fa57315e960d879fbbf479d39d767056a2d316608663448a73d6cff11a0".to_string();
            let public_key_array: [u8; 33] =
                <[u8; 33]>::from_hex(public_key_hex.as_str()).unwrap_or([0u8; 33]);

            let proof_data_hex: String = "a77063657274696669636174655f686173685820777c59ab7522062bb8717267c4bd33ac381dff98be3f806a3c7511bbaa6f2f896a636865636b5f68617368582017eb70034b5b71092521d184c5e7b069d47de657e51aef2be11a00c115036943626964782432393931666639322d613265302d343639372d386166362d6537386432396531643733656f69675f6163636f756e745f7479706568504552534f4e414c6b69675f757365726e616d656d62726f6f6b7379626f793130306e696e69746961746f725f706b657958200260a2abbfcc8eb272ed36f4685214d24e1a0fae48af77edef05c695b8d8f2126974696d657374616d701a6411bbe6".to_string();

            let signature_hex: String = "d6590cbc7e10511c9ea9f742d1798b938f831769363fffea32f4b14ebad2bd10ab7f065f303e8057e2db5f42f8a9ba83beb23db52c8013b6991429a841122f63".to_string();
            let signature: [u8; 64] =
                <[u8; 64]>::from_hex(signature_hex.as_str()).unwrap_or([0u8; 64]);

            let recovery_id: u8 =
                calculate_recovery_id(public_key_array, &signature, &proof_data_hex)
                    .expect("Calculate recovery id");
            let mut signature_vec: Vec<u8> = signature.to_vec();
            signature_vec.push(recovery_id);
            let signature_with_recovery_id: [u8; 65] =
                signature_vec.try_into().unwrap_or([0u8; 65]);
            let signature_rid_hex: String = hex::encode(signature_with_recovery_id);

            let contract: Silentdata = Silentdata::new(public_key_hex);

            assert_eq!(
                contract.verify_and_decode(signature_rid_hex.clone(), proof_data_hex),
                "brooksyboy100"
            );
        }

        #[ink::test]
        fn verify_works() {
            let (secret_key, public_key) = generate_keys();

            let public_key_hex: String = hex::encode(public_key.serialize());
            let public_key_array: [u8; 33] =
                <[u8; 33]>::from_hex(public_key_hex.as_str()).unwrap_or([0u8; 33]);

            let (_, cbor_proof_data): (ProofData, Vec<u8>) = get_proof_data();

            let message = get_message(&cbor_proof_data);
            let message_hex: String = hex::encode(cbor_proof_data.as_slice());

            let signature: [u8; 64] = get_signature(message, secret_key);
            let recovery_id: u8 = calculate_recovery_id(public_key_array, &signature, &message_hex)
                .expect("Calculate recovery id");
            let mut signature_vec: Vec<u8> = signature.to_vec();
            signature_vec.push(recovery_id);
            let signature_with_recovery_id: [u8; 65] =
                signature_vec.try_into().unwrap_or([0u8; 65]);
            let signature_hex: String = hex::encode(signature_with_recovery_id);

            let contract: Silentdata = Silentdata::new(public_key_hex);

            assert_eq!(contract.verify(&signature_hex, &message_hex), true);

            assert_eq!(
                contract.verify(&signature_hex, &get_dummy_message_hex()),
                false
            );

            assert_eq!(
                contract.verify(&signature_hex, &get_invalid_message_hex()),
                false
            );
        }

        #[ink::test]
        fn decode_works() {
            let (_, public_key) = generate_keys();
            let public_key_hex: String = hex::encode(public_key.serialize());

            let (proof_data, cbor_proof_data): (ProofData, Vec<u8>) = get_proof_data();

            let message: String = hex::encode(cbor_proof_data.as_slice());

            let contract: Silentdata = Silentdata::new(public_key_hex);

            assert_eq!(contract.decode(&message), proof_data.ig_username);

            assert_eq!(contract.decode(&get_dummy_message_hex()), "".to_string());

            assert_eq!(contract.decode(&get_invalid_message_hex()), "".to_string());
        }
    }
}
