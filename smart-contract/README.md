# Smart Contract for Silent Data

This directory contains an example smart contract for verifying a Silent Data Instagram certificate.

To test it you will need:

- The proof certificate (hex encoded)
- The signature (hex encoded ecdsa signature with recovery ID)
- The public key of the secure enclave that generated the proof certificate (hex encoded)

The secure enclave contains a persistent key used for signing certificates, so once the trust of that enclave has been established you can deploy the smart contract with that public key. Then for each new certificate you only need the certificate data and signature to perform the verification.

This smart contract simply verifies the signature and extracts and returns the Instagram username, it is meant as a basis for more complicated smart contracts that have use for verified usernames. (e.g. whitelisting users)

## Run the tests

Follow the [installation instructions](https://docs.substrate.io/tutorials/smart-contracts/prepare-your-first-contract/) for setting up a development environment.

Run the tests:

```bash
cargo test
```

## Deploy the contract

Set up development environment:

```bash
rustup component add rust-src
rustup target add wasm32-unknown-unknown --toolchain nightly
cargo install --force --locked cargo-contract --version 2.0.0-rc
cargo install contracts-node --git https://github.com/paritytech/substrate-contracts-node.git --force --locked
```

Build the contract:

```bash
cargo contract build
```

Start contracts node:

```bash
substrate-contracts-node --log info,runtime::contracts=debug 2>&1
```

Deploy the contract:

```bash
cargo contract instantiate --constructor new --args '"<public key>".to_string()' --suri //Alice --salt $(date +%s)
export INSTANTIATED_CONTRACT_ADDRESS=<contract address from output>
```

Call the contract:

```bash
cargo contract call --contract $INSTANTIATED_CONTRACT_ADDRESS --message verify_and_decode --args '"<signature>".to_string()' '"<proof certificate>".to_string()' --suri //Alice --dry-run
```

These values can be used to test (the verified username should be `brooksyboy100`):

- Public key: `0272ff5fa57315e960d879fbbf479d39d767056a2d316608663448a73d6cff11a0`
- Proof certificate: `a77063657274696669636174655f686173685820777c59ab7522062bb8717267c4bd33ac381dff98be3f806a3c7511bbaa6f2f896a636865636b5f68617368582017eb70034b5b71092521d184c5e7b069d47de657e51aef2be11a00c115036943626964782432393931666639322d613265302d343639372d386166362d6537386432396531643733656f69675f6163636f756e745f7479706568504552534f4e414c6b69675f757365726e616d656d62726f6f6b7379626f793130306e696e69746961746f725f706b657958200260a2abbfcc8eb272ed36f4685214d24e1a0fae48af77edef05c695b8d8f2126974696d657374616d701a6411bbe6`
- Signature: `d6590cbc7e10511c9ea9f742d1798b938f831769363fffea32f4b14ebad2bd10ab7f065f303e8057e2db5f42f8a9ba83beb23db52c8013b6991429a841122f6301`
