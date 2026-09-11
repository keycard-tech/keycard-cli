# keycard-cli

`keycard` is a command line tool to manage [Status Keycards](https://github.com/keycard-tech/status-keycard) — programmable NFC/USB hardware wallets for Ethereum and other cryptographic operations.

- [Dependencies](#dependencies)
- [Installation](#installation)
- [Building from Source](#building-from-source)
- [Global Flags](#global-flags)
- [Environment Variables](#environment-variables)
- [CLI Commands](#cli-commands)
  - [Lifecycle](#lifecycle)
  - [Pairing](#pairing)
  - [Key Management](#key-management)
  - [Signing](#signing)
  - [Credentials](#credentials)
  - [Data](#data)
  - [Metadata](#metadata)
  - [Cash Applet](#cash-applet)
  - [Ident Applet](#ident-applet)
  - [Shell](#shell)

## Dependencies

- A USB smart card reader (contact readers are more reliable than NFC readers).
- On Linux, install and run the [PC/SC daemon](https://linux.die.net/man/8/pcscd).

## Installation

Download the pre-built binary for your platform from the [releases page](https://github.com/keycard-tech/keycard-cli/releases) and rename the file to `keycard`, removing the platform-specific suffix.

## Building from Source

```bash
make build
./build/bin/keycard --help
```

To run tests:

```bash
make test
```

## Global Flags

The following flags are available on all commands:

| Flag | Description |
|------|-------------|
| `--log-level <level>` | Log level: `debug`, `info`, `warn`, `error` (default: `info`) |
| `--pin <pin>` | PIN for card authentication (or `KEYCARD_PIN` env var) |
| `--puk <puk>` | PUK for card unblocking (or `KEYCARD_PUK` env var) |
| `--pairing-password <pw>` | Pairing password for V1 cards (or `KEYCARD_PAIRING_PASSWORD` env var) |
| `--reader <name>` | Specific reader name to use (auto-detect if omitted) |
| `--json` / `-j` | Output in JSON format |
| `--yes` / `-y` | Skip interactive confirmations |
| `--card-ca <hex>` | CA public key for V2 certificate verification (hex, 33 bytes compressed) |
| `--test-card` | Shortcut for `--card-ca` with the test CA public key |
| `--whitelist-card <hex>` | Whitelisted card identity public key (hex, 33 bytes compressed) |
| `--show-secrets` | Show secrets (PIN, PUK, pairing keys) in output. Hidden by default |

> **Security tip:** Passing credentials like `--pin`, `--puk`, `--pairing-password`, `--new`, or `--new-pin` on the command line exposes them in your shell history and `ps` output. Prefer using the `KEYCARD_PIN`, `KEYCARD_PUK`, `KEYCARD_PAIRING_PASSWORD`, `KEYCARD_NEW_PIN`, `KEYCARD_NEW_PUK`, and `KEYCARD_NEW_PAIRING_PASSWORD` environment variables instead.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KEYCARD_PIN` | Default PIN for card authentication |
| `KEYCARD_PUK` | Default PUK for card unblocking |
| `KEYCARD_PAIRING_PASSWORD` | Default pairing password for V1 cards |
| `KEYCARD_NEW_PIN` | New PIN for `change-pin` and `unblock-pin` |
| `KEYCARD_NEW_PUK` | New PUK for `change-puk` |
| `KEYCARD_NEW_PAIRING_PASSWORD` | New pairing password for `change-pairing-password` |
| `KEYCARD_CARD_CA` | CA public key for V2 certificate verification |
| `KEYCARD_TEST_CARD` | Use test card CA (boolean) |
| `KEYCARD_WHITELIST_CARD` | Whitelisted card identity public key |

## CLI Commands

### Lifecycle

#### `version`

Show the CLI version.

```bash
keycard version
```

#### `info`

Show card information (applet version, initialization status, public key, etc.).

```bash
keycard info
keycard info --json
```

#### `install`

Install applets to the card. Download the `cap` file from the [keycard-tech/status-keycard releases](https://github.com/keycard-tech/status-keycard/releases) page.

```bash
keycard install --applet-file PATH_TO_CAP_FILE
```

By default, the keycard and ident applets are installed. Control which applets get installed:

| Flag | Default | Description |
|------|---------|-------------|
| `--keycard-applet` | `true` | Install keycard applet |
| `--ident-applet` | `true` | Install ident applet |
| `--cash-applet` | `false` | Install cash applet |
| `--ndef-applet` | `false` | Install NDEF applet |
| `--force` / `-f` | | Force reinstallation if already installed |
| `--ndef <url>` | | URL for the NDEF record (supports `{{.cashAddress}}` variable) |

#### `delete`

⚠️ **WARNING: This command removes all applets and all keys from the card.**

```bash
keycard delete --yes
```

#### `init`

Initialize the card and generate the secrets needed for authentication.

```bash
keycard init
```

Options:

| Flag | Description |
|------|-------------|
| `--pin <pin>` | Set a specific PIN (random if omitted) |
| `--puk <puk>` | Set a specific PUK (random if omitted) |
| `--pairing-password <pw>` | Set pairing password (V1 only; defaults to `KeycardDefaultPairing` if omitted) |
| `--alt-pin <pin>` | Set alternative PIN (random if omitted) |
| `--pin-retries <n>` | Number of PIN retries allowed (default: 3) |
| `--puk-retries <n>` | Number of PUK retries allowed (default: 5) |

On V2 cards (Secure Channel V2), the pairing password is not used.

#### `factory-reset`

⚠️ **WARNING: This command erases all data from the card.**

```bash
keycard factory-reset --yes
```

### Pairing

> Pairing is only needed for applet versions < 4.0 (Secure Channel V1). V2 cards use certificate-based authentication.

#### `pair`

Pair with the card to establish a secure channel.

```bash
keycard pair --pairing-password YOUR_PAIRING_PASSWORD
```

#### `unpair`

Unpair a specific pairing index.

```bash
keycard unpair --index 0 --pin YOUR_PIN
```

#### `unpair-all`

Remove all pairings from the card (including the current session).

```bash
keycard unpair-all --pin YOUR_PIN
```

### Key Management

#### `generate-key`

Generate a new random key on the card.

```bash
keycard generate-key --pin YOUR_PIN
```

#### `generate-mnemonic`

Generate a BIP39 mnemonic phrase using the card's secure RNG. The phrase is returned but not loaded by default. Use `--save` to also load the mnemonic's seed onto the card.

```bash
keycard generate-mnemonic --words 12                           # Generate only (no PIN needed)
keycard generate-mnemonic --words 24 --save --pin YOUR_PIN     # Generate and load onto card
```

| Flag | Default | Description |
|------|---------|-------------|
| `--words <n>` | `12` | Number of words: 12, 15, 18, 21, or 24 |
| `--save` | | Also load the mnemonic's binary seed onto the card (requires PIN) |

#### `remove-key`

Remove the current key from the card.

```bash
keycard remove-key --pin $KEYCARD_PIN
```

#### `derive-key`

Derive a key at the given path (applet < 4.0 only).

```bash
keycard derive-key --path "m/44'/60'/0'/0/0" --pin $KEYCARD_PIN
```

#### `load-seed`

Load a BIP39 seed onto the card.

```bash
keycard load-seed --mnemonic "word1 word2 ... word12" --pin YOUR_PIN
keycard load-seed --hex "0x..." --pin YOUR_PIN
```

#### `load-lee-seed`

Load a seed for usage with the LEE (Logos Execution Environment) onto the card (applet >= 4.0 only).

```bash
keycard load-lee-seed --mnemonic "word1 word2 ... word12" --pin YOUR_PIN
```

#### `export-public-key`

Export the public key.

```bash
keycard export-public-key --path "m/44'/60'/0'/0/0" --pin YOUR_PIN
```

#### `export-private-key`

Export the private key. Only works for paths in the EIP-1581 tree.

```bash
keycard export-private-key --path "m/43'/60'/1581'/4'/1469833213'/1555737549" --pin YOUR_PIN
```

#### `export-extended-key`

Export the extended key (public key + chain code).

```bash
keycard export-extended-key --path "m/44'/60'/0'/0/0" --pin YOUR_PIN
```

#### `export-lee-key`

Export a LEE key at the given path (applet >= 4.0 only).

```bash
keycard export-lee-key --path "m/44'/60'/0'/0/0" --pin YOUR_PIN
```

#### `export-bip85`

Export a BIP85 derived key (applet >= 4.0 only).

```bash
keycard export-bip85 --path "m/83696968'/39'/0'/12'/0'" --length 16 --pin YOUR_PIN
```

#### `ecdh`

Compute an ECDH shared secret between the key derived at the given path and a peer public key (applet >= 4.0 only).

```bash
keycard ecdh --peer-key "0x04..." --path "m/44'/1237'/0'/0/0" --pin YOUR_PIN
```

### Signing

#### `sign`

Sign a 32-byte hash.

```bash
keycard sign --hex "0x..." --path "m/44'/60'/0'/0/0" --algo ecdsa --pin YOUR_PIN
keycard sign --hex "0x..." --path "m/44'/60'/0'/0/0" --algo schnorr --pin YOUR_PIN
keycard sign --hex "0x..." --path "m/44'/60'/0'/0/0" --algo schnorr --tweak "0x..." --pin YOUR_PIN
```

The `--tweak` flag (32 bytes hex) is only valid when `--algo schnorr` is used and requires `--path`.

#### `sign-message`

Sign a message using the Ethereum Signed Message format.

```bash
keycard sign-message "Hello, Keycard!" --path "m/44'/60'/0'/0/0" --pin YOUR_PIN
keycard sign-message "Hello, Keycard!" --path "m/44'/60'/0'/0/0" --algo schnorr --tweak "0x..." --pin YOUR_PIN
```

#### `sign-file`

Sign a file (hashes the file content with Keccak256).

```bash
keycard sign-file --file /path/to/file --path "m/44'/60'/0'/0/0" --pin $KEYCARD_PIN
keycard sign-file --file /path/to/file --path "m/44'/60'/0'/0/0" --algo schnorr --tweak "0x..." --pin $KEYCARD_PIN
```

#### `set-pinless-path` / `reset-pinless-path`

Set or reset the pinless signing path (applet < 4.0 only).

```bash
keycard set-pinless-path --path "m/44'/60'/0'/0/0" --pin $KEYCARD_PIN
keycard reset-pinless-path --pin $KEYCARD_PIN
```

#### `sign-pinless`

Sign without PIN verification (applet < 4.0 only). Requires the pinless signing path to have been set.

```bash
keycard sign-pinless --hex "0x..."
```

#### `sign-message-pinless`

Sign a message without PIN (applet < 4.0 only). Requires the pinless signing path to have been set.

```bash
keycard sign-message-pinless "Hello"
```

#### `identify`

Identify the card (applet < 4.0 only).

```bash
keycard identify
```

### Credentials

> **Note:** The examples below pass credentials on the command line for clarity. In production, use environment variables (`KEYCARD_PIN`, `KEYCARD_PUK`, `KEYCARD_PAIRING_PASSWORD`, `KEYCARD_NEW_PIN`, `KEYCARD_NEW_PUK`, `KEYCARD_NEW_PAIRING_PASSWORD`) to avoid exposing secrets in shell history and `ps` output.

#### `verify-pin`

Verify the PIN.

```bash
keycard verify-pin --pin YOUR_PIN
```

#### `change-pin`

Change the PIN.

```bash
keycard change-pin --new NEW_PIN --pin YOUR_PIN
```

#### `change-puk`

Change the PUK.

```bash
keycard change-puk --new NEW_PUK --pin YOUR_PIN
```

#### `unblock-pin`

Unblock the PIN using the PUK.

```bash
keycard unblock-pin --puk YOUR_PUK --new-pin NEW_PIN
```

#### `change-pairing-password`

Change the pairing password (applet < 4.0 only).

```bash
keycard change-pairing-password --new NEW_PASSWORD --pin YOUR_PIN
```

### Data

#### `get-data`

Read data from the card.

```bash
keycard get-data --type public
keycard get-data --type ndef
keycard get-data --type cash
```

#### `store-data`

Store data on the card.

```bash
keycard store-data --type public --hex "0x..." --pin YOUR_PIN
keycard store-data --type public --file /path/to/data --pin YOUR_PIN
```

#### `get-challenge`

Get a random challenge from the card (applet >= 4.0 only).

```bash
keycard get-challenge --length 32
```

#### `set-ndef`

Set the NDEF record on the card.

```bash
keycard set-ndef --hex "0x..." --pin YOUR_PIN
keycard set-ndef --file /path/to/ndef --pin YOUR_PIN
```

#### `get-status`

Get card status (PIN retries, key path, etc.).

```bash
keycard get-status
```

### Metadata

#### `get-name`

Get the card's display name.

```bash
keycard get-name
```

#### `set-name`

Set the card's display name.

```bash
keycard set-name --name "My Keycard" --pin YOUR_PIN
```

### Cash Applet

#### `cash-info`

Show Cash applet information.

```bash
keycard cash-info
```

#### `cash-sign`

Sign data using the Cash applet.

```bash
keycard cash-sign --hex "0x..."
```

### Ident Applet

#### `load-ident`

Load an identity certificate onto the Ident applet.

```bash
keycard load-ident --hex "0x..."
keycard load-ident --test
```

### Shell

Start a shell session that reads commands from a script file or stdin for batch operations.
**The shell is non-interactive** — it requires either a script file (`-f`) or piped input via stdin.

```bash
# Run a script file
keycard shell -f script.sh

# Pipe commands from stdin (example: select the applet)
echo "keycard-select" | keycard shell

# JSON output (JSONL)
keycard shell -f script.sh --json
```

The shell supports template functions like `{{env "KEYCARD_PIN"}}`, `{{session_pairing_key}}`, `{{session_pin}}`, etc. See the [`_shell-commands-examples`](./_shell-commands-examples/) directory for examples.
