use super::*;
use crate as pallet_silentdata;
use frame_support::{
    assert_noop, assert_ok, parameter_types,
    traits::{ConstU32, ConstU64},
};
use sp_core::H256;
use sp_runtime::{
    testing::Header,
    traits::{BlakeTwo256, IdentityLookup},
};
use test_helpers::{
    calculate_recovery_id, generate_keys, get_dummy_message_hex, get_invalid_message_hex,
    get_message, get_proof_data, get_signature, ProofData,
};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
        {
            System: frame_system,
            Silentdata: pallet_silentdata,
        }
);

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type RuntimeCall = RuntimeCall;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub const EnclavePublicKey:[u8; 33] = [2, 185, 138, 127, 184, 204, 0, 112, 72, 98, 91, 100, 70, 173, 73, 161, 179, 167, 34, 223, 140, 28, 169, 117, 184, 113, 96, 2, 62, 20, 209, 144, 151];
}

impl Config for Test {
    type EnclavePublicKey = EnclavePublicKey;
    type MaxLength = ConstU32<30>;
}

fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();
    t.into()
}

#[test]
fn verify_and_decode_works() {
    new_test_ext().execute_with(|| {
        let signature: Vec<u8> = vec![
            97, 100, 53, 98, 100, 52, 97, 48, 101, 50, 98, 101, 55, 98, 100, 50, 101, 99, 98, 53,
            48, 52, 101, 49, 54, 57, 100, 50, 100, 48, 102, 57, 102, 56, 48, 97, 97, 49, 97, 98,
            53, 98, 99, 97, 99, 98, 54, 55, 101, 48, 100, 49, 50, 48, 51, 50, 99, 98, 54, 49, 48,
            57, 52, 50, 50, 54, 100, 99, 56, 102, 54, 48, 57, 98, 49, 99, 98, 55, 49, 51, 51, 53,
            97, 53, 53, 55, 100, 55, 100, 57, 51, 100, 55, 98, 54, 54, 48, 100, 55, 52, 51, 54, 51,
            49, 53, 49, 99, 101, 102, 55, 52, 98, 102, 50, 52, 98, 99, 99, 101, 50, 53, 98, 48,
            100, 50, 101, 56, 54, 48, 49,
        ];
        let message: Vec<u8> = vec![
            97, 51, 54, 98, 54, 57, 54, 55, 53, 102, 55, 53, 55, 51, 54, 53, 55, 50, 54, 101, 54,
            49, 54, 100, 54, 53, 55, 49, 54, 52, 55, 53, 54, 100, 54, 100, 55, 57, 50, 100, 54, 57,
            54, 55, 50, 100, 55, 53, 55, 51, 54, 53, 55, 50, 54, 101, 54, 49, 54, 100, 54, 53, 54,
            102, 54, 57, 54, 55, 53, 102, 54, 49, 54, 51, 54, 51, 54, 102, 55, 53, 54, 101, 55, 52,
            53, 102, 55, 52, 55, 57, 55, 48, 54, 53, 55, 53, 54, 52, 55, 53, 54, 100, 54, 100, 55,
            57, 50, 100, 54, 57, 54, 55, 50, 100, 54, 49, 54, 51, 54, 51, 54, 102, 55, 53, 54, 101,
            55, 52, 50, 100, 55, 52, 55, 57, 55, 48, 54, 53, 54, 101, 54, 57, 54, 101, 54, 57, 55,
            52, 54, 57, 54, 49, 55, 52, 54, 102, 55, 50, 53, 102, 55, 48, 54, 98, 54, 53, 55, 57,
            53, 56, 50, 48, 51, 99, 57, 49, 54, 49, 97, 51, 48, 101, 102, 53, 48, 57, 100, 101,
            101, 56, 98, 48, 53, 54, 49, 50, 101, 48, 101, 53, 102, 51, 48, 98, 50, 99, 54, 100,
            48, 57, 52, 54, 53, 100, 102, 53, 56, 57, 99, 98, 101, 48, 50, 98, 101, 98, 54, 52, 53,
            49, 54, 57, 56, 49, 57, 50,
        ];

        let (ig_username, initiator_pkey): (Vec<u8>, Vec<u8>) = Silentdata::decode(&message);

        let initiator_pkey_key: [u8; 32] = initiator_pkey.try_into().unwrap();

        assert_eq!(
            <pallet_silentdata::Silentdata<Test>>::get(initiator_pkey_key),
            None
        );

        assert_ok!(Silentdata::verify_and_decode(
            RuntimeOrigin::signed(1),
            signature,
            message
        ));

        assert_eq!(
            <pallet_silentdata::Silentdata<Test>>::get(initiator_pkey_key).unwrap(),
            ig_username
        );
    });
}

#[test]
fn verify_and_decode_verify_error_catching_works() {
    new_test_ext().execute_with(|| {
        let signature: Vec<u8> = vec![1, 2, 3];
        let message: Vec<u8> = vec![1, 2, 3];

        assert_noop!(
            Silentdata::verify_and_decode(RuntimeOrigin::signed(1), signature, message),
            pallet_silentdata::Error::<Test>::VerifyFailed
        );
    });
}

#[test]
fn verify_and_decode_decode_error_catching_works() {
    new_test_ext().execute_with(|| {
        let signature_without_ig_username: Vec<u8> = vec![
            100, 50, 51, 48, 99, 51, 50, 48, 98, 49, 50, 99, 54, 100, 56, 102, 56, 97, 51, 49, 50,
            102, 51, 55, 50, 102, 52, 52, 56, 98, 97, 99, 101, 99, 51, 98, 102, 51, 48, 51, 54, 97,
            50, 51, 56, 51, 98, 48, 100, 101, 51, 101, 54, 48, 53, 55, 54, 55, 55, 49, 52, 100, 53,
            52, 55, 57, 49, 100, 101, 97, 51, 100, 99, 53, 101, 48, 101, 99, 53, 97, 99, 57, 53,
            97, 57, 50, 100, 56, 100, 52, 54, 49, 55, 56, 49, 57, 51, 49, 53, 97, 97, 55, 98, 97,
            101, 97, 51, 100, 101, 97, 57, 56, 48, 51, 51, 100, 57, 101, 97, 51, 51, 52, 101, 53,
            98, 53, 52, 102, 48, 48,
        ];
        let message_without_ig_username: Vec<u8> = vec![
            97, 50, 54, 102, 54, 57, 54, 55, 53, 102, 54, 49, 54, 51, 54, 51, 54, 102, 55, 53, 54,
            101, 55, 52, 53, 102, 55, 52, 55, 57, 55, 48, 54, 53, 55, 53, 54, 52, 55, 53, 54, 100,
            54, 100, 55, 57, 50, 100, 54, 57, 54, 55, 50, 100, 54, 49, 54, 51, 54, 51, 54, 102, 55,
            53, 54, 101, 55, 52, 50, 100, 55, 52, 55, 57, 55, 48, 54, 53, 54, 101, 54, 57, 54, 101,
            54, 57, 55, 52, 54, 57, 54, 49, 55, 52, 54, 102, 55, 50, 53, 102, 55, 48, 54, 98, 54,
            53, 55, 57, 53, 56, 50, 48, 51, 99, 57, 49, 54, 49, 97, 51, 48, 101, 102, 53, 48, 57,
            100, 101, 101, 56, 98, 48, 53, 54, 49, 50, 101, 48, 101, 53, 102, 51, 48, 98, 50, 99,
            54, 100, 48, 57, 52, 54, 53, 100, 102, 53, 56, 57, 99, 98, 101, 48, 50, 98, 101, 98,
            54, 52, 53, 49, 54, 57, 56, 49, 57, 50,
        ];
        let signature_without_initiator_pkey: Vec<u8> = vec![
            101, 100, 54, 51, 52, 101, 56, 56, 100, 54, 49, 100, 48, 53, 101, 49, 56, 54, 53, 50,
            98, 54, 53, 55, 98, 98, 51, 50, 56, 98, 57, 49, 57, 51, 55, 98, 99, 50, 50, 101, 57,
            57, 52, 100, 51, 48, 101, 56, 48, 99, 49, 52, 53, 97, 54, 55, 97, 49, 50, 53, 99, 50,
            55, 52, 51, 52, 52, 57, 50, 101, 51, 50, 48, 101, 50, 102, 52, 49, 49, 54, 49, 56, 50,
            56, 102, 48, 56, 100, 101, 102, 52, 48, 102, 55, 48, 56, 99, 102, 51, 101, 57, 57, 51,
            56, 49, 101, 102, 48, 57, 98, 57, 52, 97, 102, 53, 49, 97, 48, 56, 97, 56, 49, 98, 101,
            57, 55, 51, 98, 48, 49,
        ];
        let message_without_initiator_pkey: Vec<u8> = vec![
            97, 50, 54, 98, 54, 57, 54, 55, 53, 102, 55, 53, 55, 51, 54, 53, 55, 50, 54, 101, 54,
            49, 54, 100, 54, 53, 55, 49, 54, 52, 55, 53, 54, 100, 54, 100, 55, 57, 50, 100, 54, 57,
            54, 55, 50, 100, 55, 53, 55, 51, 54, 53, 55, 50, 54, 101, 54, 49, 54, 100, 54, 53, 54,
            102, 54, 57, 54, 55, 53, 102, 54, 49, 54, 51, 54, 51, 54, 102, 55, 53, 54, 101, 55, 52,
            53, 102, 55, 52, 55, 57, 55, 48, 54, 53, 55, 53, 54, 52, 55, 53, 54, 100, 54, 100, 55,
            57, 50, 100, 54, 57, 54, 55, 50, 100, 54, 49, 54, 51, 54, 51, 54, 102, 55, 53, 54, 101,
            55, 52, 50, 100, 55, 52, 55, 57, 55, 48, 54, 53,
        ];

        assert_noop!(
            Silentdata::verify_and_decode(
                RuntimeOrigin::signed(1),
                signature_without_ig_username,
                message_without_ig_username
            ),
            pallet_silentdata::Error::<Test>::DecodeFailed
        );

        assert_noop!(
            Silentdata::verify_and_decode(
                RuntimeOrigin::signed(1),
                signature_without_initiator_pkey,
                message_without_initiator_pkey
            ),
            pallet_silentdata::Error::<Test>::DecodeFailed
        );
    });
}

#[test]
fn verify_works() {
    let (secret_key, public_key) = generate_keys();

    let enclave_public_key: [u8; 33] = public_key.serialize().try_into().unwrap();

    let (_, cbor_proof_data): (ProofData, Vec<u8>) = get_proof_data();

    let msg = get_message(&cbor_proof_data);
    let message_hex: String = hex::encode(cbor_proof_data.as_slice());
    let message: Vec<u8> = message_hex.as_bytes().to_vec();

    let sig: [u8; 64] = get_signature(msg, secret_key);
    let recovery_id: u8 = calculate_recovery_id(enclave_public_key, &sig, &message_hex)
        .expect("Calculate recovery id");
    let mut signature_vec: Vec<u8> = sig.to_vec();
    signature_vec.push(recovery_id);
    let signature_with_recovery_id: [u8; 65] = signature_vec.try_into().unwrap_or([0u8; 65]);
    let signature_hex: String = hex::encode(signature_with_recovery_id);
    let signature: Vec<u8> = signature_hex.as_bytes().to_vec();

    assert_eq!(
        Silentdata::verify(enclave_public_key, signature.clone(), &message),
        true
    );

    assert_eq!(
        Silentdata::verify(
            enclave_public_key,
            signature.clone(),
            &get_dummy_message_hex().as_bytes().to_vec()
        ),
        false
    );

    assert_eq!(
        Silentdata::verify(
            enclave_public_key,
            signature.clone(),
            &get_invalid_message_hex().as_bytes().to_vec()
        ),
        false
    );
}

#[test]
fn decode_works() {
    let (proof_data, cbor_proof_data): (ProofData, Vec<u8>) = get_proof_data();

    let message: String = hex::encode(cbor_proof_data.as_slice());

    Silentdata::decode(&message.as_bytes().to_vec());

    assert_eq!(
        Silentdata::decode(&message.as_bytes().to_vec()),
        (
            proof_data.ig_username.as_bytes().to_vec(),
            proof_data.initiator_pkey.to_vec()
        )
    );

    assert_eq!(
        Silentdata::decode(&get_dummy_message_hex().as_bytes().to_vec()),
        ("".as_bytes().to_vec(), vec![])
    );

    assert_eq!(
        Silentdata::decode(&get_invalid_message_hex().as_bytes().to_vec()),
        ("".as_bytes().to_vec(), vec![])
    );
}
