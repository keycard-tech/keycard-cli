package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	"github.com/status-im/keycard-go/types"

	"github.com/status-im/keycard-cli/internal"
)

// RegisterShellCommands returns the full list of shell commands.
// This is the single source of truth for what the shell can execute.
// When new commands are added to the top-level CLI, add them here too.
func RegisterShellCommands() []shellCommand {
	return []shellCommand{
		// Shell-only commands
		{name: "cash-select", usage: "Select the Cash applet", handler: shellCashSelect},

		// GP commands
		{name: "gp-send-apdu", usage: "Send a raw APDU command", handler: shellGPSendAPDU},
		{name: "gp-select", usage: "Select an AID", handler: shellGPSelect},
		{name: "gp-open-secure-channel", usage: "Open a GP secure channel", handler: shellGPOpenSecureChannel},
		{name: "gp-delete", usage: "Delete an object by AID", handler: shellGPDelete},
		{name: "gp-load", usage: "Load a package from a CAP file", handler: shellGPLoad},
		{name: "gp-install-for-install", usage: "Install for install", handler: shellGPInstallForInstall},
		{name: "gp-get-status", usage: "Get card status", handler: shellGPGetStatus},

		// Keycard lifecycle
		{name: "keycard-select", usage: "Select the Keycard applet", handler: shellKeycardSelect},
		{name: "keycard-info", usage: "Show card information", handler: shellKeycardInfo},
		{name: "keycard-init", usage: "Initialize the card", handler: shellKeycardInit},
		{name: "keycard-factory-reset", usage: "Factory reset the card", handler: shellKeycardFactoryReset},
		{name: "keycard-get-status", usage: "Get card status", handler: shellKeycardGetStatus},

		// Secrets / pairing (shell-specific for session state)
		{name: "keycard-set-secrets", usage: "Set session secrets (PIN, PUK, pairing password)", handler: shellKeycardSetSecrets},
		{name: "keycard-set-pairing", usage: "Set session pairing info", handler: shellKeycardSetPairing},

		// Pairing
		{name: "keycard-pair", usage: "Pair with the card (V1 only)", handler: shellKeycardPair},
		{name: "keycard-unpair", usage: "Unpair from the card (V1 only)", handler: shellKeycardUnpair},
		{name: "keycard-unpair-others", usage: "Unpair all other pairings (V1 only)", handler: shellKeycardUnpairOthers},
		{name: "keycard-open-secure-channel", usage: "Open secure channel", handler: shellKeycardOpenSecureChannel},
		{name: "keycard-secure-channel-version", usage: "Show secure channel version", handler: shellKeycardSecureChannelVersion},

		// Credentials
		{name: "keycard-verify-pin", usage: "Verify the PIN", handler: shellKeycardVerifyPIN},
		{name: "keycard-change-pin", usage: "Change the PIN", handler: shellKeycardChangePIN},
		{name: "keycard-change-puk", usage: "Change the PUK", handler: shellKeycardChangePUK},
		{name: "keycard-unblock-pin", usage: "Unblock the PIN using the PUK", handler: shellKeycardUnblockPin},
		{name: "keycard-change-pairing-secret", usage: "Change the pairing secret (V1 only)", handler: shellKeycardChangePairingSecret},

		// Key management
		{name: "keycard-generate-key", usage: "Generate a new key on the card", handler: shellKeycardGenerateKey},
		{name: "keycard-remove-key", usage: "Remove the current key", handler: shellKeycardRemoveKey},
		{name: "keycard-derive-key", usage: "Derive a key at the given path", handler: shellKeycardDeriveKey},
		{name: "keycard-load-seed", usage: "Load a BIP39 seed onto the card", handler: shellKeycardLoadSeed},
		{name: "keycard-load-lee-key", usage: "Load a LEE key onto the card", handler: shellKeycardLoadLEEKey},
		{name: "keycard-export-key-public", usage: "Export the public key", handler: shellKeycardExportKeyPublic},
		{name: "keycard-export-key-private", usage: "Export the private key", handler: shellKeycardExportKeyPrivate},
		{name: "keycard-export-extended-key", usage: "Export the extended key (public key + chain code)", handler: shellKeycardExportExtendedKey},
		{name: "keycard-export-lee-key", usage: "Export a LEE key at the given path", handler: shellKeycardExportLEEKey},
		{name: "keycard-export-bip85", usage: "Export a BIP85 derived key", handler: shellKeycardExportBIP85},

		// Signing
		{name: "keycard-sign", usage: "Sign a 32-byte hash", handler: shellKeycardSign},
		{name: "keycard-sign-with-path", usage: "Sign with a derivation path", handler: shellKeycardSignWithPath},
		{name: "keycard-sign-message", usage: "Sign a message (Ethereum Signed Message format)", handler: shellKeycardSignMessage},
		{name: "keycard-sign-file", usage: "Sign a file (hashes file content)", handler: shellKeycardSignFile},
		{name: "keycard-sign-pinless", usage: "Sign without PIN (applet < 4.0 only)", handler: shellKeycardSignPinless},
		{name: "keycard-sign-message-pinless", usage: "Sign a message without PIN (applet < 4.0 only)", handler: shellKeycardSignMessagePinless},

		// Pinless path
		{name: "keycard-set-pinless-path", usage: "Set the pinless signing path", handler: shellKeycardSetPinlessPath},
		{name: "keycard-reset-pinless-path", usage: "Reset the pinless signing path", handler: shellKeycardResetPinlessPath},

		// Mnemonic
		{name: "keycard-generate-mnemonic", usage: "Generate mnemonic indexes", handler: shellKeycardGenerateMnemonic},

		// Data management
		{name: "keycard-get-data", usage: "Get data from the card (public, ndef, cash)", handler: shellKeycardGetData},
		{name: "keycard-store-data", usage: "Store data on the card (public, ndef, cash)", handler: shellKeycardStoreData},
		{name: "keycard-get-challenge", usage: "Get a random challenge from the card", handler: shellKeycardGetChallenge},
		{name: "keycard-set-ndef", usage: "Set the NDEF record on the card", handler: shellKeycardSetNDEF},

		// Metadata
		{name: "keycard-get-name", usage: "Get the card's display name", handler: shellKeycardGetName},
		{name: "keycard-set-name", usage: "Set the card's display name", handler: shellKeycardSetName},

		// Identify
		{name: "keycard-identify", usage: "Identify the card (V1 only)", handler: shellKeycardIdentify},

		// Cash
		{name: "cash-sign", usage: "Sign with the Cash applet", handler: shellCashSign},
	}
}

// ---------------------------------------------------------------------------
// Shell-only commands
// ---------------------------------------------------------------------------

func shellCashSelect(ctx *shellCtx, _ []string) (shellResult, error) {
	info, err := doCashSelect(ctx.cashKC)
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Installed: %v\n", info.Installed))
	ctx.write(fmt.Sprintf("PublicKey: %x\n", info.PublicKey))
	ctx.write(fmt.Sprintf("Version: %x\n\n", info.Version))
	return shellResult{
		"installed":  info.Installed,
		"public_key": "0x" + hex.EncodeToString(info.PublicKey),
		"version":    "0x" + hex.EncodeToString(info.Version),
	}, nil
}

// ---------------------------------------------------------------------------
// GP shell commands (delegate to core)
// ---------------------------------------------------------------------------

func shellGPSendAPDU(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	rawCmd, err := hex.DecodeString(args[0])
	if err != nil {
		return nil, err
	}
	resp, err := doGPSendAPDU(ctx.gp, rawCmd)
	if err != nil {
		return nil, err
	}
	if resp.Sw != apdu.SwOK {
		return nil, apdu.NewErrBadResponse(resp.Sw, "unexpected response")
	}
	return shellResult{
		"sw":   fmt.Sprintf("0x%04x", resp.Sw),
		"data": "0x" + hex.EncodeToString(resp.Data),
	}, nil
}

func shellGPSelect(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 0, 1); err != nil {
		return nil, err
	}
	var aid []byte
	if len(args) == 1 {
		var err error
		aid, err = hex.DecodeString(args[0])
		if err != nil {
			return nil, err
		}
	}
	if err := doGPSelect(ctx.gp, aid); err != nil {
		return nil, err
	}
	if aid != nil {
		ctx.write(fmt.Sprintf("Selected AID: %s\n", args[0]))
		return shellResult{"selected_aid": args[0]}, nil
	}
	ctx.write("Selected ISD\n")
	return shellResult{"selected": "isd"}, nil
}

func shellGPOpenSecureChannel(ctx *shellCtx, _ []string) (shellResult, error) {
	if err := ctx.gp.OpenSecureChannel(); err != nil {
		return nil, err
	}
	ctx.write("GP secure channel opened\n")
	return shellResult{"secure_channel": "opened"}, nil
}

func shellGPDelete(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	aid, err := hex.DecodeString(args[0])
	if err != nil {
		return nil, err
	}
	if err := ctx.gp.DeleteObject(aid); err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Deleted AID: %s\n", args[0]))
	return shellResult{"deleted_aid": args[0]}, nil
}

func shellGPLoad(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 2); err != nil {
		return nil, err
	}
	f, err := os.Open(args[0])
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pkgAID, err := hex.DecodeString(args[1])
	if err != nil {
		return nil, err
	}
	if err := ctx.gp.LoadPackage(f, pkgAID, func(int, int) {}); err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Package loaded: %s\n", args[1]))
	return shellResult{"package_aid": args[1], "loaded": true}, nil
}

func shellGPInstallForInstall(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 3, 4); err != nil {
		return nil, err
	}
	pkgAID, err := hex.DecodeString(args[0])
	if err != nil {
		return nil, err
	}
	appletAID, err := hex.DecodeString(args[1])
	if err != nil {
		return nil, err
	}
	instanceAID, err := hex.DecodeString(args[2])
	if err != nil {
		return nil, err
	}
	var params []byte
	if len(args) == 4 {
		params, err = hex.DecodeString(args[3])
		if err != nil {
			return nil, err
		}
	}
	if err := ctx.gp.InstallForInstall(pkgAID, appletAID, instanceAID, params); err != nil {
		return nil, err
	}
	ctx.write("Install for install complete\n")
	return shellResult{
		"package_aid":  args[0],
		"applet_aid":   args[1],
		"instance_aid": args[2],
		"installed":    true,
	}, nil
}

func shellGPGetStatus(ctx *shellCtx, _ []string) (shellResult, error) {
	status, err := doGPGetStatus(ctx.gp)
	if err != nil {
		return nil, err
	}
	lifecycle := status.LifeCycle()
	ctx.write(fmt.Sprintf("CARD STATUS: %s\n\n", lifecycle))
	return shellResult{"lifecycle": lifecycle}, nil
}

// ---------------------------------------------------------------------------
// Keycard lifecycle shell commands (delegate to core)
// ---------------------------------------------------------------------------

func shellKeycardSelect(ctx *shellCtx, _ []string) (shellResult, error) {
	info, err := doKeycardSelect(ctx.kc)
	if err != nil {
		// Still show info even if select errored (V4+ cert issues)
	}
	ctx.write(fmt.Sprintf("Installed: %v\n", info.Installed))
	ctx.write(fmt.Sprintf("Initialized: %v\n", info.Initialized))
	ctx.write(fmt.Sprintf("Key Initialized: %v\n", len(info.KeyUID) > 0))
	ctx.write(fmt.Sprintf("Version: %x\n", info.AppVersion()))
	ctx.write(fmt.Sprintf("KeyUID: %x\n\n", info.KeyUID))
	return shellResult{
		"installed":     info.Installed,
		"initialized":   info.Initialized,
		"key_uid":       "0x" + hex.EncodeToString(info.KeyUID),
		"app_version":   fmt.Sprintf("0x%04x", info.AppVersion()),
	}, err
}

func shellKeycardInfo(ctx *shellCtx, _ []string) (shellResult, error) {
	// Re-select to get fresh info
	var selectErr error
	if selectErr = ctx.kc.Select(); selectErr != nil {
		if e, ok := selectErr.(*apdu.ErrBadResponse); ok && e.Sw == globalplatform.SwFileNotFound {
			// Applet not installed, continue
		} else if ctx.kc.AppInfo() == nil || !ctx.kc.AppInfo().Installed {
			return nil, selectErr
		}
	}

	cashKC := keycard.NewCashCommandSet(ctx.ch)
	if err := cashKC.Select(); err != nil {
		if e, ok := err.(*apdu.ErrBadResponse); !(ok && e.Sw == globalplatform.SwFileNotFound) {
			return nil, err
		}
	}

	result, err := doKeycardInfo(ctx.kc, cashKC, selectErr)
	if err != nil {
		return nil, err
	}

	formatKeycardInfoShell(ctx.write, result)

	// Build JSON result manually
	kcMap := shellResult{
		"installed":                result.Keycard.Installed,
		"initialized":              result.Keycard.Initialized,
		"app_version":              result.Keycard.AppVersion,
		"app_version_hex":          result.Keycard.AppVersionHex,
		"has_master_key":           result.Keycard.HasMasterKey,
		"key_uid":                  result.Keycard.KeyUID,
		"secure_channel_version":   result.Keycard.SecureChannelVersion,
		"capabilities":             result.Keycard.Capabilities,
		"pin_retries":              result.Keycard.PINRetries,
		"lee_mode":                 result.Keycard.LEEMode,
		"has_factory_reset_cap":    result.Keycard.HasFactoryResetCap,
		"instance_uid":             result.Keycard.InstanceUID,
		"certificate":              result.Keycard.Certificate,
		"identity_pub_key":         result.Keycard.IdentityPubKey,
		"certificate_verification": result.Keycard.CertVerification,
	}
	if result.Keycard.AvailableSlots != nil {
		kcMap["available_slots"] = *result.Keycard.AvailableSlots
	}

	cashMap := shellResult{
		"installed":  result.Cash.Installed,
		"public_key": result.Cash.PublicKey,
		"address":    result.Cash.Address,
		"version":    result.Cash.Version,
	}

	return shellResult{
		"keycard": kcMap,
		"cash":    cashMap,
	}, nil
}

func shellKeycardInit(ctx *shellCtx, _ []string) (shellResult, error) {
	if ctx.kc.AppInfo() == nil || !ctx.kc.AppInfo().Installed {
		return nil, errors.New("keycard applet not installed")
	}
	if ctx.kc.AppInfo().Initialized {
		return nil, errors.New("card already initialized")
	}
	if ctx.secrets == nil {
		secrets, err := keycard.GenerateSecrets()
		if err != nil {
			return nil, err
		}
		ctx.secrets = secrets
	}

	if err := doKeycardInit(ctx.kc, ctx.secrets); err != nil {
		return nil, err
	}

	ctx.write(fmt.Sprintf("PIN: %s\n", ctx.secrets.Pin()))
	ctx.write(fmt.Sprintf("PUK: %s\n", ctx.secrets.Puk()))
	v2 := internal.IsSecureChannelV2(ctx.kc)
	if !v2 {
		ctx.write(fmt.Sprintf("PAIRING PASSWORD: %s\n\n", ctx.secrets.PairingPass()))
	}
	return shellResult{
		"pin":              ctx.secrets.Pin(),
		"puk":              ctx.secrets.Puk(),
		"pairing_password": ctx.secrets.PairingPass(),
	}, nil
}

func shellKeycardFactoryReset(ctx *shellCtx, _ []string) (shellResult, error) {
	info := ctx.kc.AppInfo()
	if !info.Installed {
		return nil, errors.New("keycard applet not installed")
	}
	if !info.HasFactoryResetCapability() {
		return nil, errors.New("card does not support factory reset")
	}
	if err := ctx.kc.FactoryReset(); err != nil {
		return nil, err
	}
	ctx.write("Card factory reset complete\n")
	return shellResult{"factory_reset": true}, nil
}

func shellKeycardGetStatus(ctx *shellCtx, _ []string) (shellResult, error) {
	result, err := doKeycardGetStatusResult(ctx.kc)
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("STATUS - PIN RETRY COUNT: %d\n", result.PinRetryCount))
	ctx.write(fmt.Sprintf("STATUS - PUK RETRY COUNT: %d\n", result.PUKRetryCount))
	ctx.write(fmt.Sprintf("STATUS - KEY INITIALIZED: %v\n", result.KeyInitialized))
	ctx.write(fmt.Sprintf("STATUS - KEY PATH: %v\n\n", result.KeyPath))
	return shellResult{
		"pin_retry_count":  result.PinRetryCount,
		"puk_retry_count":  result.PUKRetryCount,
		"key_initialized":  result.KeyInitialized,
		"key_path":         result.KeyPath,
	}, nil
}

// ---------------------------------------------------------------------------
// Secrets / pairing (shell session state)
// ---------------------------------------------------------------------------

func shellKeycardSetSecrets(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 3); err != nil {
		return nil, err
	}
	ctx.secrets = keycard.NewSecrets(args[0], args[1], args[2])
	return shellResult{
		"pin":              args[0],
		"puk":              args[1],
		"pairing_password": args[2],
	}, nil
}

func shellKeycardSetPairing(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 2); err != nil {
		return nil, err
	}
	key, err := parseHexShell(args[0])
	if err != nil {
		return nil, err
	}
	index, err := strconv.ParseInt(args[1], 10, 8)
	if err != nil {
		return nil, err
	}
	var keyArr [32]byte
	copy(keyArr[:], key)
	ctx.kc.SetPairing(types.NewPairing(keyArr, uint8(index)))
	return shellResult{
		"pairing_key":   args[0],
		"pairing_index": int(index),
	}, nil
}

// ---------------------------------------------------------------------------
// Pairing shell commands (delegate to core)
// ---------------------------------------------------------------------------

func shellKeycardPair(ctx *shellCtx, _ []string) (shellResult, error) {
	if ctx.secrets == nil {
		return nil, errors.New("cannot pair without setting secrets")
	}
	pairing, err := doKeycardPair(ctx.kc, ctx.secrets.PairingPass())
	if err != nil {
		return nil, err
	}
	key := pairing.Key()
	ctx.write(fmt.Sprintf("PAIRING KEY: %x\n", key[:]))
	ctx.write(fmt.Sprintf("PAIRING INDEX: %v\n\n", pairing.Index()))
	return shellResult{
		"pairing_key":   fmt.Sprintf("0x%x", key[:]),
		"pairing_index": pairing.Index(),
	}, nil
}

func shellKeycardUnpair(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	indexInt, err := strconv.ParseInt(args[0], 10, 8)
	if err != nil {
		return nil, err
	}
	if ctx.secrets == nil {
		return nil, errors.New("cannot unpair without setting secrets")
	}
	if err := ctx.kc.Unpair(uint8(indexInt)); err != nil {
		return nil, err
	}
	ctx.write("UNPAIRED\n\n")
	return shellResult{"unpaired_index": int(indexInt)}, nil
}

func shellKeycardUnpairOthers(ctx *shellCtx, _ []string) (shellResult, error) {
	if internal.IsSecureChannelV2(ctx.kc) {
		return nil, errors.New("unpair-others is not needed for Secure Channel V2 cards")
	}
	if err := ctx.kc.UnpairOthers(); err != nil {
		return nil, err
	}
	ctx.write("All other pairings removed\n")
	return shellResult{"unpaired_others": true}, nil
}

func shellKeycardOpenSecureChannel(ctx *shellCtx, _ []string) (shellResult, error) {
	if ctx.kc.Pairing() == nil {
		return nil, errors.New("cannot open secure channel without setting pairing info")
	}
	if err := ctx.kc.OpenSecureChannel(); err != nil {
		return nil, err
	}
	ctx.write("Secure channel opened\n")
	return shellResult{"secure_channel": "opened"}, nil
}

func shellKeycardSecureChannelVersion(ctx *shellCtx, _ []string) (shellResult, error) {
	version, err := doKeycardSecureChannelVersion(ctx.kc)
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Secure channel version: %s\n", version))
	return shellResult{"secure_channel_version": version}, nil
}

// ---------------------------------------------------------------------------
// Credentials shell commands
// ---------------------------------------------------------------------------

func shellKeycardVerifyPIN(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := ctx.kc.VerifyPIN(args[0]); err != nil {
		return nil, err
	}
	ctx.write("PIN verified\n")
	return shellResult{"pin_verified": true}, nil
}

func shellKeycardChangePIN(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := ctx.kc.ChangePIN(args[0]); err != nil {
		return nil, err
	}
	ctx.write("PIN changed\n")
	return shellResult{"pin_changed": true}, nil
}

func shellKeycardChangePUK(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := ctx.kc.ChangePUK(args[0]); err != nil {
		return nil, err
	}
	ctx.write("PUK changed\n")
	return shellResult{"puk_changed": true}, nil
}

func shellKeycardUnblockPin(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 2); err != nil {
		return nil, err
	}
	if err := ctx.kc.UnblockPIN(args[0], args[1]); err != nil {
		return nil, err
	}
	ctx.write("PIN unblocked\n")
	return shellResult{"pin_unblocked": true}, nil
}

func shellKeycardChangePairingSecret(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := ctx.kc.ChangePairingSecret(args[0]); err != nil {
		return nil, err
	}
	ctx.write("Pairing secret changed\n")
	return shellResult{"pairing_secret_changed": true}, nil
}

// ---------------------------------------------------------------------------
// Key management shell commands (delegate to core)
// ---------------------------------------------------------------------------

func shellKeycardGenerateKey(ctx *shellCtx, _ []string) (shellResult, error) {
	keyUID, err := doKeycardGenerateKey(ctx.kc)
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("KEY UID %x\n\n", keyUID))
	return shellResult{"key_uid": "0x" + hex.EncodeToString(keyUID)}, nil
}

func shellKeycardRemoveKey(ctx *shellCtx, _ []string) (shellResult, error) {
	if err := ctx.kc.RemoveKey(); err != nil {
		return nil, err
	}
	ctx.write("KEY REMOVED\n\n")
	return shellResult{"key_removed": true}, nil
}

func shellKeycardDeriveKey(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := ctx.kc.DeriveKey(args[0]); err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Key derived at path: %s\n", args[0]))
	return shellResult{"path": args[0], "derived": true}, nil
}

func shellKeycardLoadSeed(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	seed, err := parseHexShell(args[0])
	if err != nil {
		return nil, err
	}
	keyID, err := ctx.kc.LoadSeed(seed)
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("KEY ID %x\n\n", keyID))
	return shellResult{"key_id": "0x" + hex.EncodeToString(keyID)}, nil
}

func shellKeycardLoadLEEKey(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	key, err := parseHexShell(args[0])
	if err != nil {
		return nil, err
	}
	if err := ctx.kc.LoadLEEKey(key); err != nil {
		return nil, err
	}
	ctx.write("LEE key loaded\n")
	return shellResult{"lee_key_loaded": true}, nil
}

func shellKeycardExportKeyPublic(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	exported, err := doKeycardExportKey(ctx.kc, args[0], false, keycard.P2ExportKeyPublicOnly)
	if err != nil {
		return nil, err
	}
	result := doKeycardExportKeyResult(exported, false, args[0])
	ctx.write(fmt.Sprintf("PUBLIC KEY: %s\n", result.PublicKey))
	if result.Address != "" {
		ctx.write(fmt.Sprintf("ADDRESS: %s\n", result.Address))
	}
	return shellResult{
		"public_key": result.PublicKey,
		"address":    result.Address,
		"path":       result.Path,
	}, nil
}

func shellKeycardExportKeyPrivate(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	exported, err := doKeycardExportKey(ctx.kc, args[0], false, keycard.P2ExportKeyPrivateAndPublic)
	if err != nil {
		return nil, err
	}
	result := doKeycardExportKeyResult(exported, true, args[0])
	ctx.write(fmt.Sprintf("PRIVATE KEY: %s\n", result.PrivateKey))
	ctx.write(fmt.Sprintf("PUBLIC KEY: %s\n", result.PublicKey))
	if result.Address != "" {
		ctx.write(fmt.Sprintf("ADDRESS: %s\n", result.Address))
	}
	return shellResult{
		"private_key": result.PrivateKey,
		"public_key":  result.PublicKey,
		"address":     result.Address,
		"path":        result.Path,
	}, nil
}

func shellKeycardExportExtendedKey(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	exported, err := doKeycardExportKey(ctx.kc, args[0], false, keycard.P2ExportKeyExtendedPublic)
	if err != nil {
		return nil, err
	}
	result := doKeycardExportExtendedKeyResult(exported, args[0])
	ctx.write(fmt.Sprintf("PUBLIC KEY: %s\n", result.PublicKey))
	ctx.write(fmt.Sprintf("CHAIN CODE: %s\n", result.ChainCode))
	if result.Address != "" {
		ctx.write(fmt.Sprintf("ADDRESS: %s\n", result.Address))
	}
	return shellResult{
		"public_key": result.PublicKey,
		"chain_code": result.ChainCode,
		"address":    result.Address,
		"path":       result.Path,
	}, nil
}

func shellKeycardExportLEEKey(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	key, err := ctx.kc.ExportLEEKey(args[0])
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("LEE KEY: %s\n", "0x"+hex.EncodeToString(key)))
	return shellResult{"key": "0x" + hex.EncodeToString(key), "path": args[0]}, nil
}

func shellKeycardExportBIP85(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 2); err != nil {
		return nil, err
	}
	length, err := strconv.ParseInt(args[1], 10, 8)
	if err != nil {
		return nil, err
	}
	key, err := ctx.kc.ExportBIP85(args[0], uint8(length))
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("BIP85 KEY: %s\n", "0x"+hex.EncodeToString(key)))
	return shellResult{"key": "0x" + hex.EncodeToString(key), "path": args[0]}, nil
}

// ---------------------------------------------------------------------------
// Signing shell commands (delegate to core)
// ---------------------------------------------------------------------------

func shellKeycardSign(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	data, err := parseHexShell(args[0])
	if err != nil {
		return nil, err
	}
	sig, err := doKeycardSign(ctx.kc, data)
	if err != nil {
		return nil, err
	}
	formatSignatureShell(ctx.write, sig)
	return shellSignatureResult(sig), nil
}

func shellKeycardSignWithPath(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 2); err != nil {
		return nil, err
	}
	data, err := parseHexShell(args[0])
	if err != nil {
		return nil, err
	}
	sig, err := doKeycardSignWithPath(ctx.kc, data, args[1])
	if err != nil {
		return nil, err
	}
	formatSignatureShell(ctx.write, sig)
	return shellSignatureResultWithPath(sig, args[1]), nil
}

func shellKeycardSignMessage(ctx *shellCtx, args []string) (shellResult, error) {
	if len(args) < 1 {
		return nil, errors.New("keycard-sign-message requires at least 1 parameter")
	}
	hash := hashEthereumMessage(strings.Join(args, " "))
	sig, err := doKeycardSign(ctx.kc, hash)
	if err != nil {
		return nil, err
	}
	formatSignatureShell(ctx.write, sig)
	return shellSignatureResult(sig), nil
}

func shellKeycardSignFile(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	content, err := os.ReadFile(args[0])
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	hash := cryptoKeccak256Shell(content)
	sig, err := doKeycardSign(ctx.kc, hash)
	if err != nil {
		return nil, err
	}
	formatSignatureShell(ctx.write, sig)
	return shellSignatureResultWithFile(sig, args[0]), nil
}

func shellKeycardSignPinless(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	data, err := parseHexShell(args[0])
	if err != nil {
		return nil, err
	}
	sig, err := doKeycardSignPinless(ctx.kc, data)
	if err != nil {
		return nil, err
	}
	formatSignatureShell(ctx.write, sig)
	return shellSignatureResult(sig), nil
}

func shellKeycardSignMessagePinless(ctx *shellCtx, args []string) (shellResult, error) {
	if len(args) < 1 {
		return nil, errors.New("keycard-sign-message-pinless requires at least 1 parameter")
	}
	hash := hashEthereumMessage(strings.Join(args, " "))
	sig, err := doKeycardSignPinless(ctx.kc, hash)
	if err != nil {
		return nil, err
	}
	formatSignatureShell(ctx.write, sig)
	return shellSignatureResult(sig), nil
}

// ---------------------------------------------------------------------------
// Pinless path shell commands
// ---------------------------------------------------------------------------

func shellKeycardSetPinlessPath(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	if internal.IsAppletV4Plus(ctx.kc) {
		return nil, errors.New("pinless signing is not available on applet version 4.0+")
	}
	if err := ctx.kc.SetPinlessPath(args[0]); err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Pinless path set: %s\n", args[0]))
	return shellResult{"pinless_path": args[0]}, nil
}

func shellKeycardResetPinlessPath(ctx *shellCtx, _ []string) (shellResult, error) {
	if internal.IsAppletV4Plus(ctx.kc) {
		return nil, errors.New("pinless signing is not available on applet version 4.0+")
	}
	if err := ctx.kc.ResetPinlessPath(); err != nil {
		return nil, err
	}
	ctx.write("Pinless path reset\n")
	return shellResult{"pinless_path_reset": true}, nil
}

// ---------------------------------------------------------------------------
// Mnemonic shell commands
// ---------------------------------------------------------------------------

func shellKeycardGenerateMnemonic(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	checksumSize, err := strconv.ParseInt(args[0], 10, 8)
	if err != nil {
		return nil, err
	}
	indexes, err := ctx.kc.GenerateMnemonic(int(checksumSize))
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("MNEMONIC INDEXES %v\n\n", indexes))
	return shellResult{"mnemonic_indexes": indexes}, nil
}

// ---------------------------------------------------------------------------
// Data management shell commands (delegate to core)
// ---------------------------------------------------------------------------

func shellKeycardGetData(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	dataType, err := parseDataType(args[0])
	if err != nil {
		return nil, err
	}
	data, err := doKeycardGetData(ctx.kc, dataType)
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Data (%s): 0x%x\n", args[0], data))
	return shellResult{
		"type": args[0],
		"data": "0x" + hex.EncodeToString(data),
	}, nil
}

func shellKeycardStoreData(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 2); err != nil {
		return nil, err
	}
	dataType, err := parseDataType(args[0])
	if err != nil {
		return nil, err
	}
	data, err := parseHexShell(args[1])
	if err != nil {
		return nil, err
	}
	if err := doKeycardStoreData(ctx.kc, dataType, data); err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Data stored (%s, %d bytes)\n", args[0], len(data)))
	return shellResult{"type": args[0], "bytes": len(data), "stored": true}, nil
}

func shellKeycardGetChallenge(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	length, err := strconv.ParseInt(args[0], 10, 8)
	if err != nil {
		return nil, err
	}
	challenge, err := ctx.kc.GetChallenge(uint8(length))
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Challenge: 0x%x\n", challenge))
	return shellResult{"challenge": "0x" + hex.EncodeToString(challenge)}, nil
}

func shellKeycardSetNDEF(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	ndefData, err := parseHexShell(args[0])
	if err != nil {
		return nil, err
	}
	if err := ctx.kc.SetNDEF(ndefData); err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("NDEF set (%d bytes)\n", len(ndefData)))
	return shellResult{"bytes": len(ndefData), "set": true}, nil
}

// ---------------------------------------------------------------------------
// Metadata shell commands (delegate to core)
// ---------------------------------------------------------------------------

func shellKeycardGetName(ctx *shellCtx, _ []string) (shellResult, error) {
	name, err := doKeycardGetName(ctx.kc)
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Card name: %s\n", name))
	return shellResult{"name": name}, nil
}

func shellKeycardSetName(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	if err := doKeycardSetName(ctx.kc, args[0]); err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("Card name set: %s\n", args[0]))
	return shellResult{"name": args[0]}, nil
}

// ---------------------------------------------------------------------------
// Identify shell command (delegate to core)
// ---------------------------------------------------------------------------

func shellKeycardIdentify(ctx *shellCtx, args []string) (shellResult, error) {
	var expectedPubKey []byte
	if len(args) == 1 {
		var err error
		expectedPubKey, err = parseHexShell(args[0])
		if err != nil {
			return nil, err
		}
	}
	pubkey, err := doKeycardIdentify(ctx.kc, expectedPubKey)
	if err != nil {
		return nil, err
	}
	ctx.write(fmt.Sprintf("IDENTIFICATION OK (public key: %x)\n\n", pubkey))
	return shellResult{
		"identified": true,
		"public_key": "0x" + hex.EncodeToString(pubkey),
	}, nil
}

// ---------------------------------------------------------------------------
// Cash shell command (delegate to core)
// ---------------------------------------------------------------------------

func shellCashSign(ctx *shellCtx, args []string) (shellResult, error) {
	if err := requireArgs(args, 1); err != nil {
		return nil, err
	}
	data, err := parseHexShell(args[0])
	if err != nil {
		return nil, err
	}
	sig, err := doCashSign(ctx.cashKC, data)
	if err != nil {
		return nil, err
	}
	formatSignatureShell(ctx.write, sig)
	return shellSignatureResult(sig), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// cryptoKeccak256Shell computes keccak256 hash (used by shell sign-file).
func cryptoKeccak256Shell(data []byte) []byte {
	return crypto.Keccak256(data)
}
