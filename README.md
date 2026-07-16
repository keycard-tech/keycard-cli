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

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KEYCARD_PIN` | Default PIN for card authentication |
| `KEYCARD_PUK` | Default PUK for card unblocking |
| `KEYCARD_PAIRING_PASSWORD` | Default pairing password for V1 cards |

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
| `--pairing-password <pw>` | Set pairing password (V1 only, random if omitted) |
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

Remove all other pairings (keep current session).

```bash
keycard unpair-all --pin YOUR_PIN
```

### Key Management

#### `generate-key`

Generate a new random key on the card.

```bash
keycard generate-key --pin YOUR_PIN
```

#### `remove-key`

Remove the current key from the card.

```bash
keycard remove-key --pin YOUR_PIN
```

#### `load-seed`

Load a BIP39 seed onto the card.

```bash
keycard load-seed --mnemonic "word1 word2 ... word12" --pin YOUR_PIN
keycard load-seed --hex "0x..." --pin YOUR_PIN
```

#### `load-lee-seed`

Load a LEE (Lightweight Ethereum Extension) seed onto the card (applet >= 4.0 only).

```bash
keycard load-lee-seed --mnemonic "word1 word2 ... word12" --pin YOUR_PIN
```

#### `export-public-key`

Export the public key.

```bash
keycard export-public-key --path "m/44'/60'/0'/0/0" --pin YOUR_PIN
```

#### `export-private-key`

Export the private key.

```bash
keycard export-private-key --path "m/44'/60'/0'/0/0" --pin YOUR_PIN
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
keycard export-bip85 --path "1" --length 64 --pin YOUR_PIN
```

### Signing

#### `sign`

Sign a 32-byte hash.

```bash
keycard sign --hex "0x..." --path "m/44'/60'/0'/0/0" --algo ecdsa --pin YOUR_PIN
keycard sign --hex "0x..." --path "m/44'/60'/0'/0/0" --algo schnorr --pin YOUR_PIN
```

#### `sign-message`

Sign a message using the Ethereum Signed Message format.

```bash
keycard sign-message "Hello, Keycard!" --path "m/44'/60'/0'/0/0" --pin YOUR_PIN
```

#### `sign-file`

Sign a file (hashes the file content with Keccak256).

```bash
keycard sign-file --file /path/to/file --path "m/44'/60'/0'/0/0" --pin YOUR_PIN
```

### Credentials

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

Start an interactive shell or run a script file for batch operations.

```bash
# Interactive shell
keycard shell

# Run a script file
keycard shell -f script.sh

# Pipe commands from stdin
echo "info" | keycard shell

# JSON output (JSONL)
keycard shell -f script.sh --json
```

The shell supports template functions like `{{env "KEYCARD_PIN"}}`, `{{session_pairing_key}}`, `{{session_pin}}`, etc. See the [`_shell-commands-examples`](./_shell-commands-examples/) directory for examples.
