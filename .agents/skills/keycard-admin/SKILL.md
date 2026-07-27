---
name: keycard-admin
description: >
  Full administrative control of a Status Keycard hardware wallet: provisioning,
  applet installation, initialization, pairing, PIN/PUK management, key generation,
  seed loading, data storage, and factory reset. Use only for card setup,
  maintenance, and testing. Covers all CLI commands including destructive
  operations (factory-reset, delete, remove-key). Pinless signing,
  derive-key, identify, and set/reset-pinless-path are also covered.
disable-model-invocation: true
---

# Keycard Admin

Full administrative operations for [Status Keycard](https://github.com/keycard-tech/status-keycard) hardware wallets.

> **WARNING:** This skill includes destructive operations (factory reset, delete applets, remove keys). Confirm with the user before executing any destructive command.

## Prerequisites

- Keycard inserted into a USB smart card reader
- PC/SC daemon running (`pcscd` on Linux)
- `KEYCARD_PIN` and optionally `KEYCARD_PUK` environment variables set

## Execution Rule

**Commands must run strictly sequentially — never in parallel.** The card can only process one command at a time. Running concurrent commands causes APDU errors (`6982`, `6985`) or card resets. Always wait for a command to complete before issuing the next one.

## Security

- PIN is managed via `KEYCARD_PIN` env var. The CLI reads it automatically — **prefer the env var over `--pin`** (command-line flags are visible in `ps` and shell history).
- PUK is managed via `KEYCARD_PUK` env var. PUK is needed for PIN unblocking **and** for `init` (it's part of the card credentials).
- Pairing password (V1 cards only) via `KEYCARD_PAIRING_PASSWORD` env var.
- Outputs mask secrets by default. Use `--show-secrets` only during debugging and never in logs.
- **Always confirm destructive operations with the user before proceeding.**

## Global Flags (available on all commands)

| Flag | Description |
|------|-------------|
| `--json` / `-j` | JSON output |
| `--yes` / `-y` | Skip interactive confirmations |
| `--pin <pin>` | Override PIN (prefer `KEYCARD_PIN` env var) |
| `--puk <puk>` | Override PUK (prefer `KEYCARD_PUK` env var) |
| `--pairing-password <pw>` | Override pairing password (V1 only) |
| `--reader <name>` | Select specific reader |
| `--log-level <level>` | debug, info, warn, error |
| `--show-secrets` | Show secrets in output (hidden by default) |
| `--test-card` | Use test CA for V2 certificate verification |
| `--card-ca <hex>` | CA public key for V2 cert verification (33 bytes compressed, with or without `0x`) |
| `--whitelist-card <hex>` | Whitelisted card identity public key (33 bytes compressed, with or without `0x`) |

## Command Reference

### Lifecycle

```bash
keycard version                                    # CLI version
keycard info [--json]                              # Card info (applet, key, status)
keycard get-status [--json]                        # PIN retries, key path, etc.
keycard get-name [--json]                          # Card display name
keycard set-name --name "My Card"        # Set display name
```

### Applet Installation (development / blank cards only)

> **These commands only work on blank cards or development builds.** On production cards, GlobalPlatform restrictions prevent installing or deleting applets. To re-provision a production card, use `factory-reset` followed by `init` and `generate-mnemonic --save` (or `load-seed`).

```bash
keycard install -a <cap-file> [--keycard-applet] [--ident-applet] [--cash-applet] [--ndef-applet] [-f] [--ndef <url>]
```

Install applets from a CAP file. By default installs keycard + ident applets. Use `-f` to force reinstallation. Use `--ndef <url>` to set an NDEF record (supports `{{.cashAddress}}` variable).

Use this when building your own card image or working with a blank/development card.

### Initialization

```bash
keycard init [--pin <pin>] [--puk <puk>] [--pairing-password <pw>] [--alt-pin <pin>] [--pin-retries <n>] [--puk-retries <n>]
```

Initialize the card and generate authentication secrets. If PIN/PUK are omitted, random values are generated. Pairing password defaults to `KeycardDefaultPairing` if omitted (V1 only). On V2 cards, pairing-password is not used.

### ⚠️ Destructive Operations

```bash
keycard factory-reset --yes                        # Erase all card data (works on all cards)
keycard delete --yes                               # Remove all applets (development/blank cards only)
```

`factory-reset` is the standard way to wipe a card. It works on all cards including production cards and resets the applet to factory state without removing it.

`delete` removes applets entirely via GlobalPlatform — this only works on blank or development cards. On production cards, GP restrictions prevent applet deletion. Use `factory-reset` instead.

### Pairing (V1 cards only, applet < 4.0)

```bash
keycard pair --pairing-password <pw>               # Establish secure channel
keycard unpair --index <n>               # Remove a pairing
keycard unpair-all                       # Remove all pairings (including current session)
```

V2 cards (applet ≥ 4.0) use certificate-based authentication — pairing is not needed.

### Credentials

> PIN is 6 digits, PUK is 12 digits.

```bash
keycard verify-pin                       # Verify PIN
keycard change-pin --new <new-pin>       # Change PIN (6 digits)
keycard change-puk --new <new-puk>       # Change PUK (12 digits)
keycard unblock-pin --puk $PUK --new-pin <new-pin> # Unblock PIN with PUK
keycard change-pairing-password --new <pw>   # Change pairing password (V1 only)
```

### Key Management

```bash
keycard generate-mnemonic --words 12 --save        # Generate mnemonic and load seed (requires --pin)
keycard generate-mnemonic --words 12               # Generate mnemonic only (no load, no --pin needed)
keycard generate-key                               # Generate random key on card
keycard remove-key                                 # Remove current key
keycard load-seed --mnemonic "word1 word2 ..."     # Load BIP39 seed
keycard load-seed --hex "0x..."                    # Load raw seed hex
keycard load-lee-seed --mnemonic "word1 ..."       # Load LEE seed (applet ≥ 4.0)
```

### Key Export

> **Always include `--path`** on all export commands. On applet ≥ 4.0, `--path` is required; on older applets it is optional (falls back to the current key).

```bash
keycard export-public-key --path "m/44'/60'/0'/0/0" 
keycard export-private-key --path "m/43'/60'/1581'/4'/1469833213'/1555737549"   # EIP1581 path (enforced by the applet)
keycard export-extended-key --path "m/44'/60'/0'/0/0" 
keycard export-lee-key --path "m/44'/60'/0'/0/0"           # applet ≥ 4.0
keycard export-bip85 --path "m/83696968'/39'/0'/12'/0'" --length 16  # BIP39 12-word English, applet ≥ 4.0
# Path format: m/83696968'/{app_no}'/{index}' — app 39' = BIP39 mnemonics
```

Use `--current` to export the current key on applets < 4.0.

**JSON output** (`export-public-key`): `public_key` (uncompressed, 65 bytes hex with `0x`), `address` (Ethereum address), `path`.  
**JSON output** (`export-bip85` / `export-lee-key`): `key` (hex with `0x`), `path`.

### Signing

> **Always include `--path`** on all sign and export commands. On applet ≥ 4.0, `--path` is required; on older applets it is optional (falls back to the current key). Omitting the path relies on the card's current derived key, which is error-prone.

```bash
keycard sign --hex "<32-byte-hex>" --path "<hd-path>" --algo <ecdsa|schnorr> 
keycard sign-message "<message>" --path "<hd-path>" --algo <ecdsa|schnorr>
keycard sign-file --file /path/to/file --path "<hd-path>" --algo <ecdsa|schnorr> 
```

**Note:** `--algo schnorr` requires `--path` to be specified.

**JSON output** (all signing commands): `signature_r`, `signature_s`, `signature_v` (hex with `0x` prefix, except `v` which is an integer). `sign-file` also includes `file`.

### Data Storage

```bash
keycard get-data --type <public|ndef|cash> [--json]
keycard store-data --type public --hex "0x..." 
keycard store-data --type public --file /path/to/data 
keycard set-ndef --hex "0x..." 
keycard set-ndef --file /path/to/ndef 
keycard get-challenge --length 32                    # applet ≥ 4.0
```

### Cash Applet

```bash
keycard cash-info [--json]                           # Cash applet info
keycard cash-sign --hex "<hex>"                      # Sign with Cash applet
```

### Ident Applet (development cards only)

> Production cards have the identity certificate loaded at the factory. `load-ident` is only needed when building your own card. It is a **mandatory step immediately after `install`** and only works once — subsequent attempts fail with `6985`.

```bash
keycard load-ident --hex "0x..."                     # Load identity certificate
keycard load-ident --test                            # Load test certificate
```

## Shell Scripting

The `keycard shell` command runs scripts with session state and template variables:

```bash
keycard shell -f script.sh --json    # Run script from file, JSONL output
echo "keycard-select" | keycard shell  # Pipe commands from stdin (omit -f)
```

### Shell Template Variables

| Variable | Description |
|----------|-------------|
| `{{env "KEYCARD_PIN"}}` | Read env variable |
| `{{session_pin}}` | PIN from session secrets |
| `{{session_puk}}` | PUK from session secrets |
| `{{session_pairing_password}}` | Pairing password from session |
| `{{session_pairing_key}}` | Current pairing key (hex with `0x`, V1 only — empty on V2) |
| `{{session_pairing_index}}` | Current pairing index (V1 only — `0` on V2) |

### Shell Commands (subset)

Shell commands use a simplified syntax (no flags, positional args only). Key commands:

```
keycard-select
keycard-set-secrets <pin> <puk> [pairing-password]
keycard-init
keycard-pair
keycard-open-secure-channel
keycard-verify-pin <pin>
keycard-unpair <index>
keycard-generate-key
keycard-generate-mnemonic [words]          # Generate mnemonic phrase only
keycard-save-mnemonic [words]              # Generate mnemonic and load seed
keycard-load-seed <mnemonic-or-hex>               # Mnemonic phrase (space-separated words) or hex
keycard-export-key-public <path>
keycard-export-key-private <path>
keycard-sign <hex-hash> [path]                   # Path optional (falls back to current key)
keycard-sign-message <message...> [path]        # Path optional, detected if starts with m/
keycard-sign-file <file>                         # No path argument
keycard-remove-key
keycard-factory-reset
keycard-generate-mnemonic [words]               # 12 (default), 15, 18, 21, 24
keycard-save-mnemonic [words]
keycard-get-data <type>
keycard-store-data <type> <hex>
keycard-get-challenge <length>
keycard-set-ndef <hex>
keycard-get-name
keycard-set-name <name>
keycard-identify [expected-pubkey-hex]
keycard-derive-key <path>
keycard-change-pin <new-pin>
keycard-change-puk <new-puk>
keycard-unblock-pin <puk> <new-pin>
keycard-change-pairing-secret <new-pw>
keycard-set-pinless-path <path>
keycard-reset-pinless-path
keycard-sign-pinless <hex>
keycard-sign-message-pinless <message...>
keycard-get-status
keycard-set-pairing <key-hex> <index>
keycard-unpair-others
keycard-open-secure-channel
gp-select [aid]
gp-open-secure-channel
gp-delete <aid>
gp-load <cap-file> <aid>
gp-install-for-install <pkg-aid> <applet-aid> <instance-aid> [params]
gp-get-status
cash-select
cash-sign <hex>
ident-select
ident-load [hex]
echo <text>
```

See `_shell-commands-examples/` in the project for full examples.

## Common Workflows

### Provision a New Card (development / blank card)

> These steps assume a blank or development card where `install` is permitted. For production cards that already have applets, skip the install step and start from `factory-reset` or `init`.

```bash
# 1. Install applets (blank/dev cards only)
keycard install --applet-file keycard_v4.cap --force --yes

# 2. Load identity certificate (mandatory after install, dev cards only)
keycard load-ident --test

# 3. Initialize (generates random PIN/PUK if not specified)
keycard init --pin-retries 3 --puk-retries 5

# 4. Generate a mnemonic and load it onto the card
keycard generate-mnemonic --save 

# 5. Verify
keycard info --json
keycard get-status --json
```

### Load a Seed and Derive Keys

```bash
# Load BIP39 mnemonic
keycard load-seed --mnemonic "word1 word2 ... word12" 

# Export public keys for multiple accounts
for i in 0 1 2; do
  keycard export-public-key --path "m/44'/60'/0'/0/$i" --json
done
```

### Full Card Reset and Re-Provision

```bash
# ⚠️ Destructive — confirm with user first
# factory-reset works on all cards (including production)
keycard factory-reset --yes

# Re-initialize and load keys
keycard init
keycard generate-mnemonic --save
```

For development/blank cards where you also need to reinstall applets:

```bash
keycard install -a keycard_v4.cap -f
keycard load-ident --test
keycard init
keycard generate-mnemonic --save
```

### Shell Script: Sign Multiple Messages

```bash
keycard shell --json <<'EOF'
keycard-select
keycard-set-secrets {{env "KEYCARD_PIN"}} {{env "KEYCARD_PUK"}}
keycard-pair
keycard-open-secure-channel
keycard-verify-pin {{session_pin}}
keycard-sign-message Transaction A m/44'/60'/0'/0/0
keycard-sign-message Transaction B m/44'/60'/0'/0/0
keycard-unpair {{session_pairing_index}}
EOF
```

## Error Patterns

| Error | Likely Cause | Fix |
|-------|-------------|-----|
| `no smartcard reader found` | No USB reader connected or pcscd not running | Check reader, restart pcscd |
| `reader not found: <name> (available: ...)` | Bad `--reader` name | Check reader name; omit `--reader` to auto-detect |
| *(blocks indefinitely)* | Reader present but no card inserted | Insert the card. Use a timeout when scripting. |
| `keycard applet not installed. Run 'keycard install' first` | Card is blank or applets were deleted | Run `keycard install` |
| `wrong pin. remaining attempts: N` | Wrong PIN | Check `KEYCARD_PIN`; note remaining attempts |
| `wrong pin. remaining attempts: 0` | PIN blocked (too many failed attempts) | Use `keycard unblock-pin --puk $KEYCARD_PUK` |
| `cannot open secure channel without pairing` | Pairing issue (V1) | Re-pair or check `--pairing-password` / `KEYCARD_PAIRING_PASSWORD` |
| `card certificate verification failed: ...` | Cert mismatch (V2) | Check `--card-ca` / `--test-card` |
| `<cmd> is not available on applet version 4.0+` | Command requires applet < 4.0 | Downgrade command or update card |
| `<cmd> is only available on applet version 4.0+` | Command requires applet ≥ 4.0 | Update applet via `keycard install` (dev cards only) |
| `bad response 6982` / `bad response 6985` | APDU security error (`sw=6982`/`sw=6985`) | Card may need a moment to stabilize. Retry after a brief delay. |
| `--path is required for applet version 4.0+` | Missing path on sign/export | Always include `--path "m/..."` on sign and export commands |
