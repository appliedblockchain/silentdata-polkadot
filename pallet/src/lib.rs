#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

use hex::FromHex;
use keccak_hash::keccak_256;
use minicbor::Decoder;
use sp_core::ecdsa::{Public, Signature};
use sp_io::crypto::ecdsa_verify_prehashed;
use sp_std::prelude::Vec;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    const STORAGE_KEY_LENGTH: usize = 32;

    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        #[pallet::constant]
        type EnclavePublicKey: Get<[u8; 33]>;

        #[pallet::constant]
        type MaxLength: Get<u32>;
    }

    #[pallet::error]
    pub enum Error<T> {
        VerifyFailed,
        DecodeFailed,
    }

    #[pallet::storage]
    pub(super) type Silentdata<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; STORAGE_KEY_LENGTH], BoundedVec<u8, T::MaxLength>>;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Verifies that a Silent Data Instagram account ownership proof certificate has been signed by a secure enclave,
        /// parses the certificate and creates a mapping between the subjects wallet address (stored as the equivalent public key)
        /// and Instagram username.
        ///
        /// # Arguments
        ///
        /// * `signature` - The hex encoded Secp256k1 signature of the `message` (with recovery ID) as a vector of bytes. For the
        /// verification to succeed the signature must have been produced by the private key corresponding to the `EnclavePublicKey`
        /// that the pallet was deployed with.
        /// * `message` - The hex encoded Silent Data proof certificate as a vector of bytes. The certificate is a CBOR encoded
        /// map of key-value pairs.
        ///
        /// # Errors
        ///
        /// * `VerifyFailed` - The signature could not be verified, either the `signature` or `message` are incorrect or the signature
        /// was produced by an invalid private key.
        /// * `DecodeFailed` - It was not possible to extract the wallet public key or the Instagram username from the proof certificate.
        /// It may be that the wrong type of proof certificate was used in the `message`.
        #[pallet::weight(0)]
        pub fn verify_and_decode(
            origin: OriginFor<T>,
            signature: Vec<u8>,
            message: Vec<u8>,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let enclave_public_key: [u8; 33] = T::EnclavePublicKey::get();

            ensure!(
                Self::verify(enclave_public_key, signature, &message),
                Error::<T>::VerifyFailed
            );

            let (ig_username, initiator_pkey): (Vec<u8>, Vec<u8>) = Self::decode(&message);

            ensure!(
                ig_username.len() > 0 && initiator_pkey.len() == STORAGE_KEY_LENGTH,
                Error::<T>::DecodeFailed
            );

            let key: [u8; STORAGE_KEY_LENGTH] = initiator_pkey.try_into().unwrap();

            let value: BoundedVec<u8, T::MaxLength> = BoundedVec::truncate_from(ig_username);

            <Silentdata<T>>::insert(&key, value);

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Returns `true` if the ECDSA verification succeeds.
        ///
        /// # Arguments
        ///
        /// * `enclave_public_key` - The enclave public key as an array of bytes.
        /// * `signature` - The hex encoded Secp256k1 signature of the `message` (with recovery ID) as a vector of bytes. For the
        /// verification to succeed the signature must have been produced by the private key corresponding to the `EnclavePublicKey`
        /// that the pallet was deployed with.
        /// * `message` - The hex encoded Silent Data proof certificate as a vector of bytes. The certificate is a CBOR encoded
        /// map of key-value pairs.
        pub fn verify(enclave_public_key: [u8; 33], signature: Vec<u8>, message: &Vec<u8>) -> bool {
            let signature_array: [u8; 65] = <[u8; 65]>::from_hex(signature).unwrap_or([0u8; 65]);
            let sig: Signature = Signature::from_raw(signature_array);

            let message_vec: Vec<u8> = <Vec<u8>>::from_hex(message).unwrap_or_default();
            let mut message_hash: [u8; 32] = [0u8; 32];
            keccak_256(&message_vec[..], &mut message_hash);

            let enc_pub_key: Public = Public::from_raw(enclave_public_key);

            ecdsa_verify_prehashed(&sig, &message_hash, &enc_pub_key)
        }

        /// Returns a tuple with the `ig_username` as a vector of bytes and `initiator_pkey` as a vector of bytes of a CBOR encoded message.
        /// Returns empty vector of bytes when `ig_username` is not present.
        /// Returns empty vector of bytes when `initiator_pkey` is not present.
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
        pub fn decode(message: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
            let message_vec: Vec<u8> = <Vec<u8>>::from_hex(message).unwrap_or_default();

            let mut decoder: Decoder = Decoder::new(&message_vec[..]);

            let size: u64 = decoder.map().unwrap_or_default().unwrap_or_default();

            let mut ig_username: &str = "";
            let mut initiator_pkey: &[u8] = &[];

            for _ in 0..size {
                let key: &str = decoder.str().unwrap_or_default();

                if key == "ig_username" {
                    ig_username = decoder.str().unwrap_or_default();
                } else if key == "initiator_pkey" {
                    initiator_pkey = decoder.bytes().unwrap_or_default();
                } else {
                    decoder.skip().unwrap_or_default();
                }
            }

            (ig_username.as_bytes().to_vec(), initiator_pkey.to_vec())
        }
    }
}
