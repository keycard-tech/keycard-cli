---
name: keycard-admin
description: >
  Full administrative control of a Status Keycard hardware wallet: provisioning,
  applet installation, initialization, pairing, PIN/PUK management, key generation,
  seed loading, data storage, and factory reset. Use only for card setup,
  maintenance, and testing. Covers all CLI commands including destructive
  operations (factory-reset, delete, remove-key).
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

- PIN is managed via `KEYCARD_PIN` env var. The CLI reads it automatically — **prefer the env var over `--pin`**.
- PUK is managed via `KEYCARD_PUK` env var (only needed for PIN unblocking).
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
keycard install --applet-file <cap-file> [--keycard-applet] [--ident-applet] [--cash-applet] [--ndef-applet] [--force]
```

Install applets from a CAP file. By default installs keycard + ident applets. Use `--force` to reinstall.

Use this when building your own card image or working with a blank/development card.

### Initialization

```bash
keycard init [--pin <pin>] [--puk <puk>] [--pairing-password <pw>] [--alt-pin <pin>] [--pin-retries <n>] [--puk-retries <n>]
```

Initialize the card and generate authentication secrets. If PIN/PUK/pairing-password are omitted, random values are generated.

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
keycard unpair-all                       # Remove all other pairings
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

> **Always include `--path`** on all export commands.

```bash
keycard export-public-key --path "m/44'/60'/0'/0/0" 
keycard export-private-key --path "m/43'/60'/1581'/4'/1469833213'/1555737549"   # EIP1581 path only
keycard export-extended-key --path "m/44'/60'/0'/0/0" 
keycard export-lee-key --path "m/44'/60'/0'/0/0"           # applet ≥ 4.0
keycard export-bip85 --path "m/83696968'/39'/0'/12'/0'" --length 16  # BIP39 12-word English, applet ≥ 4.0
# Path format: m/83696968'/{app_no}'/{index}' — app 39' = BIP39 mnemonics
```

**JSON output** (`export-public-key`): `public_key` (uncompressed, 65 bytes hex with `0x`), `address` (Ethereum address), `path`.  
**JSON output** (`export-bip85` / `export-lee-key`): `key` (hex with `0x`), `path`.

### Signing

> **Always include `--path`** on all sign and export commands. Omitting the path relies on the card's current derived key, which is error-prone.

```bash
keycard sign --hex "<32-byte-hex>" --path "<hd-path>" --algo <ecdsa|schnorr> 
keycard sign-message "Hello" --path "<hd-path>" 
keycard sign-file --file /path/to/file --path "<hd-path>" 
```

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
echo "info" | keycard shell          # Pipe commands from stdin (omit -f)
```

### Shell Template Variables

| Variable | Description |
|----------|-------------|
| `{{env "KEYCARD_PIN"}}` | Read env variable |
| `{{session_pin}}` | PIN from session secrets |
| `{{session_puk}}` | PUK from session secrets |
| `{{session_pairing_password}}` | Pairing password from session |
| `{{session_pairing_key}}` | Current pairing key (hex) |
| `{{session_pairing_index}}` | Current pairing index |

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
keycard-load-seed <mnemonic-or-hex>
keycard-export-key-public <path>
keycard-export-key-private <path>
keycard-sign <hex-hash> <path>
keycard-sign-message <message> <path>
keycard-sign-file <file> <path>
keycard-remove-key
keycard-factory-reset
gp-select [aid]
gp-open-secure-channel
gp-delete <aid>
gp-load <cap-file> <aid>
gp-install-for-install <pkg-aid> <applet-aid> <instance-aid> [params]
```

> **Note:** `keycard-sign`, `keycard-sign-message`, and `keycard-sign-file` require `<path>` as the second argument.

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
keycard install --applet-file keycard_v4.cap --force --yes
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
| `no readers found` | No USB reader connected or pcscd not running | Check reader, restart pcscd |
| `card not found` | Card not inserted or reader issue | Reinsert card, try different reader |
| `card not initialized` | Fresh card, never set up | Run `keycard init` |
| `applet not installed` | Applets were deleted or card is blank | Run `keycard install` |
| `PIN verification failed` | Wrong PIN | Check `KEYCARD_PIN`, use `unblock-pin` if blocked |
| `PIN blocked` | Too many failed attempts | Use `keycard unblock-pin --puk $KEYCARD_PUK` |
| `no key loaded` | Key was removed or card reset | Run `keycard generate-mnemonic --save` or `load-seed` |
| `secure channel error` | Pairing issue (V1) or cert mismatch (V2) | Re-pair or check `--card-ca` / `--test-card` |
| `command not available` | Applet version too old | Update applet via `keycard install` (dev cards only) |
| `bad response 6982` / `6985` | APDU security error | Card may need a moment to stabilize. Retry after a brief delay. |
| `--path is required` | Missing path on sign/export | Always include `--path "m/..."` on sign and export commands |
