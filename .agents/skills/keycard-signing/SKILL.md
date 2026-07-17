---
name: keycard-signing
description: >
  Sign messages, files, and raw hashes with a Status Keycard hardware wallet.
  Export public keys at any HD path. Derive BIP85 child keys for non-crypto
  services (SSH, PGP, passwords). Use when the user needs to sign data, derive
  keys, or inspect card status. Does NOT cover card provisioning, PIN changes,
  or any destructive operation.
---

# Keycard Signing

Sign data and derive keys using a [Status Keycard](https://github.com/keycard-tech/status-keycard) — a programmable NFC/USB hardware wallet.

All commands support `--json` for machine-readable output.

## Prerequisites

- Keycard inserted into a USB smart card reader (contact readers preferred over NFC)
- PC/SC daemon running (`pcscd` on Linux)
- Card already initialized with a key loaded
- `KEYCARD_PIN` environment variable set by the user

## Execution Rule

**Commands must run strictly sequentially — never in parallel.** The card can only process one command at a time. Running concurrent commands causes APDU errors (`6982`, `6985`) or card resets. Always wait for a command to complete before issuing the next one.

## Security

- **PIN is managed exclusively via the `KEYCARD_PIN` environment variable.** The CLI reads it automatically — never pass `--pin` explicitly and never echo or log the PIN value.
- This skill covers **read and signing operations only**. If a task requires card provisioning, PIN changes, key removal, seed loading, or factory reset, report to the user that an administrative action is needed and stop.

## Commands

### Card Info

```bash
keycard info --json
```

Returns card applet version, initialization status, capabilities, and certificate info. Use this first to confirm the card is present and operational.

**Output:**

```json
{
  "keycard": {
    "installed": true,
    "initialized": true,
    "app_version": "4.0",
    "app_version_hex": "0x0400",
    "has_master_key": true,
    "key_uid": "0xba5408bf...",
    "secure_channel_version": "v2",
    "capabilities": [
      "secure-channel",
      "key-management",
      "credentials-management",
      "ndef"
    ],
    "pin_retries": 3,
    "lee_mode": false,
    "has_factory_reset_capability": true,
    "certificate": "038ffb...",
    "identity_pub_key": "0x038ffb...",
    "certificate_verification_error": "..."
  }
}
```

### Get Status

```bash
keycard get-status --json
```

Returns PIN/PUK retries remaining, key initialization status, and current key path.

**Output:**

```json
{
  "pin_retry_count": 3,
  "puk_retry_count": 5,
  "key_initialized": true,
  "key_path": ""
}
```

### Get Name

```bash
keycard get-name --json
```

Returns the card's display name (if set). Fails if no metadata is stored.

**Output:**

```json
{
  "name": "My Keycard"
}
```

### Sign a Raw Hash

```bash
keycard sign --hex "<32-byte-hex>" --path "<hd-path>" --algo <ecdsa|schnorr> --json
```

Sign a 32-byte hash. The hash must be provided as hex (with or without `0x` prefix).

- `--path` — HD derivation path, e.g. `m/44'/60'/0'/0/0` (Ethereum account 0). **Always required** — always specify an explicit derivation path.
- `--algo` — `ecdsa` (default) or `schnorr`

**Output:**

```json
{
  "signature_r": "0xddb8f5eed942ceacefce70468d8ccd68238f946597d5a8685667aa30b0346ed0",
  "signature_s": "0x5bdb934f86b2823bc94114c3adbe60cbbe95bc0661271a71f933217d7ca500a5",
  "signature_v": 0
}
```

### Sign a Message (Ethereum Signed Message format)

```bash
keycard sign-message "<message text>" --path "<hd-path>" --json
```

Signs a human-readable message using the Ethereum Signed Message hashing format (`\x19Ethereum Signed Message...\n<len><message>`).

Supports `--algo` flag (`ecdsa` default, `schnorr`).

**Output:**

```json
{
  "signature_r": "0xb07c00a1b08934df99133e76a041d11ba3fc23552f5dfe129cb24225f3391444",
  "signature_s": "0x9999777894d4fcb3e8f4aca8b5d6171ff5e8c5c86fdf20afb2eb4ed2ba020002",
  "signature_v": 0
}
```

### Sign a File

```bash
keycard sign-file --file <path> --path "<hd-path>" --json
```

Hashes the file content with Keccak256 and signs the resulting hash.

Supports `--algo` flag (`ecdsa` default, `schnorr`).

**Output:**

```json
{
  "signature_r": "0x69fd939926761a6c249899a11a2bbc387e384d07954c1bd06e7b652532211350",
  "signature_s": "0xe074d6504d94ca8473921f575b440abec30416999b6e7b16c1160e258f900090",
  "signature_v": 0,
  "file": "/tmp/test_sign.txt"
}
```

### Export Public Key

```bash
keycard export-public-key --path "<hd-path>" --json
```

Derives and exports the public key at the given HD path. The private key never leaves the card.

**Output:**

```json
{
  "public_key": "0x04e2537d3b85a3ac8ce13012e337f19a91a1e4eca2f0fa60b2c082b35e6401d72def6d53290ab6f0c8d57a72e074ec9d39cdba3bc2525c83607414af875fd5a677",
  "address": "0x9BCBEAdfbBd73d8B934657db1136fAB157611279",
  "path": "m/44'/60'/0'/0/0"
}
```

The `public_key` is uncompressed (65 bytes, `0x` + `04` + X + Y). The `address` is the derived Ethereum address (when the public key is a valid secp256k1 key).

### Export Extended Key

```bash
keycard export-extended-key --path "<hd-path>" --json
```

Export the extended key (public key + chain code) at the given path.

**Output:**

```json
{
  "public_key": "0x04e2537d3b85a3ac8ce13012e337f19a91a1e4eca2f0fa60b2c082b35e6401d72def6d53290ab6f0c8d57a72e074ec9d39cdba3bc2525c83607414af875fd5a677",
  "chain_code": "0x14814f1e7f9e52d502f127245500cc33d90228d8d0f38f0bebb2067840829f8e",
  "address": "0x9BCBEAdfbBd73d8B934657db1136fAB157611279",
  "path": "m/44'/60'/0'/0/0"
}
```

### Export LEE Key (applet ≥ 4.0)

```bash
keycard export-lee-key --path "<hd-path>" --json
```

Export a Logos Execution Environment key. Supports extended derivation paths. Requires the card to be in LEE mode.

**Output:**

```json
{
  "key": "0x...",
  "path": "m/44'/60'/0'/0/0"
}
```

### Export BIP85 Child Key (applet ≥ 4.0)

```bash
keycard export-bip85 --path "<bip85-path>" --length <bytes> --json
```

Derive entropy using [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) from the card's master seed. The output is raw key material (hex) that can be fed into any wallet or key-generation scheme.

`--path` is a BIP85 derivation path of the form `m/83696968'/{app_no}'/{index}'`. `--length` controls output size in bytes (default 64, max 64).

**Output:**

```json
{
  "key": "0x373d48ef278c6d62df6f8745373f684a",
  "path": "m/83696968'/39'/0'/12'/0'"
}
```

**Application numbers** should be semantic (e.g. a BIP number). The only currently standardized application is `39'` (BIP39). For other uses, pick a convention and document it. Suggestions below encode a 4-letter magic as a big-endian ASCII integer (fits comfortably in the 31-bit hardened index space).

| App no | Magic | Path format |
|--------|-------|------------|
| `39'` | — (BIP number) | `m/83696968'/39'/{language}'/{words}'/{index}'` |
| `1346850899'` | `PGPS` | `m/83696968'/1346850899'/{index}'` |
| `1397966923'` | `SSHK` | `m/83696968'/1397966923'/{index}'` |
| `1346458451'` | `PASS` | `m/83696968'/1346458451'/{index}'` |
| `1464616276'` | `WLET` | `m/83696968'/1464616276'/{index}'` |

BIP39 path components:
- `{language}`: `0'`=English, `1'`=Japanese, `2'`=Korean, `3'`=Spanish, `4'`=Chinese Simplified, `5'`=Chinese Traditional, `6'`=French, `7'`=Italian, `8'`=Czech, `9'`=Portuguese
- `{words}`: `12'` (128 bits), `15'` (160 bits), `18'` (192 bits), `21'` (224 bits), `24'` (256 bits)
- `{index}`: account index (`0'`, `1'`, etc.)

## Common Workflows

### Sign an Ethereum Transaction Hash

The user provides a transaction hash (32 bytes). Sign it with ECDSA:

```bash
keycard sign --hex "0xabcd...<64 hex chars>" --path "m/44'/60'/0'/0/0" --algo ecdsa --json
```

Extract `signature_r` and `signature_s` from the JSON result to build the transaction. Combine them as `r || s` (64 bytes) for the raw signature.

### Derive an Ethereum Public Key / Address

```bash
keycard export-public-key --path "m/44'/60'/0'/0/0" --json
```

The `address` field in the output is the Ethereum address derived from the public key. The `public_key` is uncompressed (65 bytes) — strip the leading `04` and hash the remaining 64 bytes with keccak256 to verify the address.

### Derive a Bitcoin Public Key (Native SegWit)

```bash
keycard export-public-key --path "m/84'/0'/0'/0/0" --json
```

Use `m/84'/0'/0'/0/0` for mainnet Native SegWit (Bech32). Use `m/84'/1'/0'/0/0` for testnet.

The returned `public_key` is uncompressed. For Bitcoin use, you typically need the compressed form (33 bytes): take the first byte (`02` or `03` based on Y parity) + the X coordinate (first 32 bytes after `04`).

### Derive a BIP39 Mnemonic (BIP85)

Derive a 12-word English BIP39 mnemonic from the card's seed:

```bash
keycard export-bip85 --path "m/83696968'/39'/0'/12'/0'" --length 16 --json
```

The `key` field (16 bytes / 128 bits as hex with `0x` prefix) is the entropy input for BIP39. Feed it into a BIP39 implementation to get the 12-word mnemonic. For 24 words, use `--length 32` and path `m/83696968'/39'/0'/24'/0'`.

### Derive a PGP Key Seed (BIP85)

Derive entropy for generating an OpenPGP key. The output can be piped into `gpg`'s batch mode:

```bash
keycard export-bip85 --path "m/83696968'/1346850899'/0'" --length 64 --json
```

Use the hex output as deterministic input for `gpg --homedir ... --full-generate-key` (via `%echo` or batch mode entropy). Increment the index (`1'`, `2'`, etc.) for additional keys.

### Derive an SSH Key Seed (BIP85)

Derive 64 bytes of entropy for SSH key generation:

```bash
keycard export-bip85 --path "m/83696968'/1397966923'/0'" --length 64 --json
```

The hex output can be used as seed material for `ssh-keygen` or fed into a deterministic key generation tool. For ED25519 keys, 32 bytes (`--length 32`) is sufficient.

### Derive Password Material (BIP85)

Derive deterministic password/passphrase material:

```bash
keycard export-bip85 --path "m/83696968'/1346458451'/0'" --length 32 --json
```

Convert the hex output to a usable password (e.g., encode as base32, take first N characters, or hash through a KDF). Use different indices for different services.

## JSON Output Format

All commands with `--json` return a single JSON object. Key fields vary by command:

| Command | Key result fields |
|---------|------------------|
| `info` | nested `keycard` object: `installed`, `initialized`, `app_version`, `has_master_key`, `key_uid`, `secure_channel_version`, `capabilities`, `pin_retries`, `lee_mode`, `certificate`, `identity_pub_key` |
| `get-status` | `pin_retry_count`, `puk_retry_count`, `key_initialized`, `key_path` |
| `get-name` | `name` |
| `sign` / `sign-message` / `sign-file` | `signature_r`, `signature_s`, `signature_v` (all hex with `0x` prefix except `v` which is an integer). `sign-file` also includes `file`. |
| `export-public-key` | `public_key` (hex with `0x`, uncompressed 65 bytes), `address` (Ethereum address), `path` |
| `export-extended-key` | `public_key`, `chain_code`, `address`, `path` |
| `export-lee-key` | `key` (hex with `0x`), `path` |
| `export-bip85` | `key` (hex with `0x`), `path` |

All hex values include the `0x` prefix.

## Error Handling

When a command fails, check the error message and act as follows:

| Error condition | Action |
|----------------|--------|
| Card not found / reader error | Tell the user: "No keycard detected. Please insert the card into a USB reader and ensure pcscd is running." |
| Card not initialized | Report to the user that the card needs to be initialized (admin action required). |
| No key loaded | Report to the user that a key must be loaded onto the card (admin action required). |
| PIN verification failed / PIN blocked | Report to the user that the PIN is incorrect or blocked and they need to unblock it with the PUK (admin action required). |
| Secure channel / pairing error | Report to the user that the card has a pairing or secure channel issue (admin action required). |
| `bad response 6982` / `bad response 6985` | APDU security errors — the card may need a moment to stabilize. Retry after a brief delay. If persistent, report to the user. |
| Applet version too old for a feature | Tell the user the specific feature requires a newer applet version and they may need to update the card (admin action required). |
| Missing `--path` on sign/export | Always include `--path "m/..."` on all sign and export commands. |
| Unknown / unexpected error | Report the full error message to the user. |

**Rule:** Never attempt to fix initialization, PIN, pairing, or key-loading issues yourself. Always report to the user.
