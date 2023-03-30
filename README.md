# Smart Contract and Pallet for Silent Data

**Disclaimer:** The code in this repository is for demonstration purposes only. It has not been audited and should not be used in production.

This repository contains examples of how Silent Data proofs can be integrated into Substrate pallets and ink! smart contracts.

[Silent Data](https://silentdata.com/) leverages hardware secure enclaves with attestation, in particular, Intel SGX in order to enable privacy-preserving retrieval and processing of off-chain data, and generation of cryptographic proofs that are verifiable in blockchain smart contracts.

The Silent Data proof certificate used here is an Instagram identity check which can be used to verifiably link instagram usernames and wallet addresses. Silent Data enables users to prove they are the owner of an Instagram account and a wallet address by simply logging in to their account and signing a message with their wallet, without having to trust any third parties with their data.

The process for generating one of these certificates is as follows:

- Register for an account on Silent Data and sign up to a plan
- Get your client ID and API key from the Silent Data app
- Make a call to the `checks/instagram` endpoint using the [Node.js library](https://github.com/appliedblockchain/silentdata-node/), specifying the `blockchain` as `POLKADOT` and setting the `walletAddress` to the Polkadot address of the Instagram user.
- A unique link will be generated for the user to follow as well as a check ID that can be used to fetch the certificate.
- The user will connect their wallet and log in to their instagram account, a secure enclave will verify this and produce the proof certificate.
- Fetch the completed certificate from the Silent Data API along with the signature and the public signing key of the secure enclave.
- The `pallet` and `smart-contract` directories contain further instructions on how to verify the certificate
