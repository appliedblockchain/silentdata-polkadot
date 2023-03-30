# Pallet for Silent Data

This directory contains an example pallet for using Silent Data Instagram certificates to create an on chain mapping between wallet addresses and Instagram usernames.

To test it you will need:

- The proof certificate (hex encoded)
- The signature (hex encoded ecdsa signature with recovery ID)
- The public key of the secure enclave that generated the proof certificate (hex encoded)

The secure enclave contains a persistent key used for signing certificates, so once the trust of that enclave has been established you can configure the pallet with that public key. Then for each new certificate you only need the certificate data and signature to perform the verification.

This pallet verifies the signature and extracts the Instagram username and wallet address, it then stores a mapping between them that can be queried.

## Run the tests

Follow the [installation instructions](https://docs.substrate.io/tutorials/get-started/build-local-blockchain/) for setting up a development environment.

Run the tests:

```bash
cargo test
```

## Deploy the pallet

### With docker

Build the docker image from the top level directory:

```bash
docker build -f docker/Dockerfile.node -t silentdata-node .
```

Run the docker image (runs a node and frontend):

```bash
docker run -p 8000:8000 -p 9944:9944 silentdata-node
```

### Full instructions

Start a local node:

```bash
git clone --branch polkadot-v0.9.30 https://github.com/substrate-developer-hub/substrate-node-template
cd substrate-node-template
```

Add the silentdata pallet to the dependencies `runtime/Cargo.toml`:

```toml
...
[dependencies]
silentdata = { default-features = false, path = "../../" } 
...
[features]
...
std = [
  ...
  "silentdata/std",
  ...
]
```

Add silentdata to the runtime `runtime/src/lib.rs`:

```rust
...
pub use silentdata;

parameter_types! {
  pub const EnclavePublicKey:[u8; 33] = <public key>;
}

impl silentdata::Config for Runtime {
  type EnclavePublicKey = EnclavePublicKey;

  type MaxLength = ConstU32<50>;
}

construct_runtime!(
  pub struct Runtime
  where
    Block = Block,
    NodeBlock = opaque::Block,
    UncheckedExtrinsic = UncheckedExtrinsic,
  {
    ...
    Silentdata: silentdata,
  }
);
...
```

Check the dependencies:

```bash
cargo check -p node-template-runtime --release
```

Build and run the node:

```bash
cargo build --release
./target/release/node-template --dev
```

Start the frontend template:

```bash
git clone https://github.com/substrate-developer-hub/substrate-front-end-template
cd substrate-front-end-template
rm yarn.lock
yarn install
yarn start
```

## Use the pallet

On the frontend, navigate to the pallet interactor, select Extrinsic interaction type, `silentdata` as the pallet, and `verifyAndDecode` as the method. Enter the hex values for the signature and message (with no preceeding `0x`). You should then see a `system:ExtrinsicSuccess` message.

Change the interaction type to Query, select `silentdata` as the pallet, and `silentdata` as the method. Enter the wallet address of the user you want to query (in the form of the hex encoded public key). If there is a verified Instagram username associated with that wallet address it will be returned (also as a hex string).

These values can be used to test (the verified username should be `brooksyboy100`/`0x62726f6f6b7379626f79313030`):

- Public key: `[2, 114, 255, 95, 165, 115, 21, 233, 96, 216, 121, 251, 191, 71, 157, 57, 215, 103, 5, 106, 45, 49, 102, 8, 102, 52, 72, 167, 61, 108, 255, 17, 160]`
- Proof certificate: `a77063657274696669636174655f686173685820777c59ab7522062bb8717267c4bd33ac381dff98be3f806a3c7511bbaa6f2f896a636865636b5f68617368582017eb70034b5b71092521d184c5e7b069d47de657e51aef2be11a00c115036943626964782432393931666639322d613265302d343639372d386166362d6537386432396531643733656f69675f6163636f756e745f7479706568504552534f4e414c6b69675f757365726e616d656d62726f6f6b7379626f793130306e696e69746961746f725f706b657958200260a2abbfcc8eb272ed36f4685214d24e1a0fae48af77edef05c695b8d8f2126974696d657374616d701a6411bbe6`
- Signature: `d6590cbc7e10511c9ea9f742d1798b938f831769363fffea32f4b14ebad2bd10ab7f065f303e8057e2db5f42f8a9ba83beb23db52c8013b6991429a841122f6301`
- Users public key: `0x0260a2abbfcc8eb272ed36f4685214d24e1a0fae48af77edef05c695b8d8f212`
