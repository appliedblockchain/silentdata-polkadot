# Example

## Node

Using node version 18.15.0

### Install

```bash
npm install
```

### Build

```bash
npm run build
```

### Run

#### Create instagram check

```bash
npm run start -- \
--clientId={CLIENT_ID} \
--clientSecret={CLIENT_SECRET} \
--action=create \
--walletAddress={WALLET_ADDRESS}
```

#### Read instagram check

```bash
npm run start -- \
--clientId={CLIENT_ID} \
--clientSecret={CLIENT_SECRET} \
--action=create \
--walletAddress={WALLET_ADDRESS}
```

## Docker

### Build

```bash
docker build -t silentdata-example .
```

### Run

#### Create instagram check

```bash
docker run silentdata-example \
--clientId={CLIENT_ID} \
--clientSecret={CLIENT_SECRET} \
--action=create \
--walletAddress={WALLET_ADDRESS}
```

#### Read instagram check

```bash
docker run silentdata-example \
--clientId={CLIENT_ID} \
--clientSecret={CLIENT_SECRET} \
--action=read \
--checkId={CHECK_ID}
```
