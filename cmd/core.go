// Package cmd contains the CLI and shell command implementations.
//
// Architecture:
//
//   - core.go: pure business logic functions (no I/O, no cli.Command dependency).
//     These take card command sets and parameters, return structured results.
//   - *.go (gp, lifecycle, pairing, etc.): top-level CLI commands. Parse flags,
//     call runCard/runGP/runCash, delegate to core functions, format output.
//   - shell.go + shell_commands.go: shell interpreter. Parse positional args,
//     maintain session state, delegate to core functions, format output.
//
// To add a new command:
//  1. Add the core business logic function in core.go
//  2. Add the CLI command in the appropriate *.go file
//  3. Register in shell_commands.go RegisterShellCommands()

package cmd

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	keycard "github.com/status-im/keycard-go"
	"github.com/status-im/keycard-go/apdu"
	"github.com/status-im/keycard-go/globalplatform"
	"github.com/status-im/keycard-go/types"

	"github.com/status-im/keycard-cli/internal"
)

// ---------------------------------------------------------------------------
// Result types — shared between CLI and shell for structured output
// ---------------------------------------------------------------------------

// GPResult holds the result of a GP APDU send.
type GPResult struct {
	SW   uint16
	Data []byte
}

// KeycardInfoResult holds comprehensive card information.
type KeycardInfoResult struct {
	Keycard KeycardInfo `json:"keycard"`
	Cash    CashInfo    `json:"cash"`
}

// KeycardInfo holds keycard applet info.
type KeycardInfo struct {
	Installed            bool     `json:"installed"`
	Initialized          bool     `json:"initialized"`
	AppVersion           string   `json:"app_version,omitempty"`
	AppVersionHex        string   `json:"app_version_hex,omitempty"`
	HasMasterKey         bool     `json:"has_master_key"`
	KeyUID               string   `json:"key_uid,omitempty"`
	SecureChannelVersion string   `json:"secure_channel_version,omitempty"`
	Capabilities         []string `json:"capabilities,omitempty"`
	PINRetries           int      `json:"pin_retries,omitempty"`
	LEEMode              bool     `json:"lee_mode"`
	HasFactoryResetCap   bool     `json:"has_factory_reset_capability"`
	// V1-V3 fields
	InstanceUID    string `json:"instance_uid,omitempty"`
	AvailableSlots *int   `json:"available_slots,omitempty"`
	// V4+ fields
	Certificate      string `json:"certificate,omitempty"`
	IdentityPubKey   string `json:"identity_pub_key,omitempty"`
	CertVerification string `json:"certificate_verification_error,omitempty"`
}

// CashInfo holds cash applet info.
type CashInfo struct {
	Installed bool   `json:"installed"`
	PublicKey string `json:"public_key,omitempty"`
	Address   string `json:"address,omitempty"`
	Version   string `json:"version,omitempty"`
}

// AppStatusResult holds keycard application status.
type AppStatusResult struct {
	PinRetryCount  int    `json:"pin_retry_count"`
	PUKRetryCount  int    `json:"puk_retry_count"`
	KeyInitialized bool   `json:"key_initialized"`
	KeyPath        string `json:"key_path"`
}

// PairingResult holds pairing information.
type PairingResult struct {
	PairingKey   string `json:"pairing_key"`
	PairingIndex int    `json:"pairing_index"`
}

// KeyResult holds key generation/loading results.
type KeyResult struct {
	KeyUID string `json:"key_uid,omitempty"`
	KeyID  string `json:"key_id,omitempty"`
}

// ExportedKeyResult holds exported key data.
type ExportedKeyResult struct {
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key"`
	ChainCode  string `json:"chain_code,omitempty"`
	Address    string `json:"address,omitempty"`
	Path       string `json:"path,omitempty"`
}

// SignatureResult holds signature data.
type SignatureResult struct {
	R           string `json:"signature_r"`
	S           string `json:"signature_s"`
	V           int    `json:"signature_v"`
	ETHSignature string `json:"eth_signature"`
	PublicKey   string `json:"public_key"`
	Address     string `json:"address"`
	Path        string `json:"path,omitempty"`
	File        string `json:"file,omitempty"`
}

// DataResult holds stored/retrieved data.
type DataResult struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Bytes int   `json:"bytes,omitempty"`
}

// ChallengeResult holds a random challenge.
type ChallengeResult struct {
	Challenge string `json:"challenge"`
}

// NameResult holds card display name.
type NameResult struct {
	Name string `json:"name"`
}

// IdentifyResult holds card identification result.
type IdentifyResult struct {
	Identified bool   `json:"identified"`
	PublicKey  string `json:"public_key"`
}

// SecureChannelVersionResult holds the secure channel version.
type SecureChannelVersionResult struct {
	Version string `json:"secure_channel_version"`
}

// MnemonicResult holds generated mnemonic indexes.
type MnemonicResult struct {
	Indexes []int `json:"mnemonic_indexes"`
}

// ---------------------------------------------------------------------------
// Helper: build SignatureResult from a types.Signature
// ---------------------------------------------------------------------------

func newSignatureResult(sig *types.Signature) SignatureResult {
	ethSig := append(sig.R(), sig.S()...)
	ethSig = append(ethSig, sig.V()+27)
	pubKey := sig.PubKey()
	ethAddr := ""
	if pubkey, err := crypto.UnmarshalPubkey(pubKey); err == nil {
		ethAddr = crypto.PubkeyToAddress(*pubkey).Hex()
	}
	return SignatureResult{
		R:            "0x" + hex.EncodeToString(sig.R()),
		S:            "0x" + hex.EncodeToString(sig.S()),
		V:            int(sig.V()),
		ETHSignature: "0x" + hex.EncodeToString(ethSig),
		PublicKey:    "0x" + hex.EncodeToString(pubKey),
		Address:      ethAddr,
	}
}

// ---------------------------------------------------------------------------
// Helper: hash a message in Ethereum Signed Message format
// ---------------------------------------------------------------------------

func hashEthereumMessage(message string) []byte {
	data := []byte(message)
	if strings.HasPrefix(message, "0x") {
		if value, err := hex.DecodeString(message[2:]); err == nil {
			data = value
		}
	}
	wrappedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(wrappedMessage))
}

// ---------------------------------------------------------------------------
// Helper: parse data type string to P1 constant
// ---------------------------------------------------------------------------

func parseDataType(s string) (uint8, error) {
	switch strings.ToLower(s) {
	case "public":
		return keycard.P1StoreDataPublic, nil
	case "ndef":
		return keycard.P1StoreDataNDEF, nil
	case "cash":
		return keycard.P1StoreDataCash, nil
	default:
		return 0, fmt.Errorf("invalid data type: %s (must be public, ndef, or cash)", s)
	}
}

// ---------------------------------------------------------------------------
// GP core functions
// ---------------------------------------------------------------------------

// doGPSendAPDU sends a raw APDU via the GP command set's channel.
func doGPSendAPDU(gp *globalplatform.CommandSet, rawCmd []byte) (*apdu.Response, error) {
	apduCmd, err := apdu.ParseCommand(rawCmd)
	if err != nil {
		return nil, err
	}
	var channel interface{ Send(*apdu.Command) (*apdu.Response, error) }
	if sc := gp.SecureChannel(); sc != nil {
		channel = sc
	} else {
		channel = gp.Channel()
	}
	return channel.Send(apduCmd)
}

// doGPSelect selects ISD (aid == nil) or a specific AID.
func doGPSelect(gp *globalplatform.CommandSet, aid []byte) error {
	if aid == nil {
		return gp.Select()
	}
	return gp.SelectAID(aid)
}

// doGPGetStatus returns the card's GP status.
func doGPGetStatus(gp *globalplatform.CommandSet) (*types.CardStatus, error) {
	return gp.GetStatus()
}

// ---------------------------------------------------------------------------
// Keycard lifecycle core functions
// ---------------------------------------------------------------------------

// doKeycardSelect selects the keycard applet and returns its info.
// selectErr is non-nil if Select failed (e.g. V4+ cert error) but info is available.
func doKeycardSelect(kc *keycard.CommandSet) (*types.ApplicationInfo, error) {
	if err := kc.Select(); err != nil {
		return kc.AppInfo(), err
	}
	return kc.AppInfo(), nil
}

// doKeycardInit initializes the card. Handles V1 vs V2 automatically.
func doKeycardInit(kc *keycard.CommandSet, secrets *keycard.Secrets) error {
	if internal.IsSecureChannelV2(kc) {
		return kc.InitV2(secrets.Pin(), secrets.Puk())
	}
	return kc.Init(secrets)
}

// doKeycardGetStatus returns application and key path status.
func doKeycardGetStatus(kc *keycard.CommandSet) (*types.ApplicationStatus, *types.ApplicationStatus, error) {
	appStatus, err := kc.GetStatusApplication()
	if err != nil {
		return nil, nil, err
	}
	keyStatus, err := kc.GetStatusKeyPath()
	if err != nil {
		return nil, nil, err
	}
	return appStatus, keyStatus, nil
}

// doKeycardGetStatusResult returns a typed status result.
func doKeycardGetStatusResult(kc *keycard.CommandSet) (AppStatusResult, error) {
	appStatus, keyStatus, err := doKeycardGetStatus(kc)
	if err != nil {
		return AppStatusResult{}, err
	}
	return AppStatusResult{
		PinRetryCount:  appStatus.PinRetryCount,
		PUKRetryCount:  appStatus.PUKRetryCount,
		KeyInitialized: appStatus.KeyInitialized,
		KeyPath:        keyStatus.Path,
	}, nil
}

// doKeycardInfo builds comprehensive card info.
// selectErr is the error from kc.Select() if any (for V4+ cert verification display).
func doKeycardInfo(kc *keycard.CommandSet, cashKC *keycard.CashCommandSet, selectErr error) (*KeycardInfoResult, error) {
	info := kc.AppInfo()
	cashInfo := cashKC.CashApplicationInfo

	appVersion := uint16(0)
	if info != nil && info.Installed {
		appVersion = info.AppVersion()
	}
	isV4Plus := appVersion >= 0x0400

	result := &KeycardInfoResult{}

	if info != nil && info.Installed {
		result.Keycard.Installed = true
		result.Keycard.Initialized = info.Initialized
		result.Keycard.AppVersion = info.AppVersionString()
		result.Keycard.AppVersionHex = fmt.Sprintf("0x%04x", info.AppVersion())
		result.Keycard.LEEMode = info.IsLEEMode()
		result.Keycard.HasFactoryResetCap = info.HasFactoryResetCapability()
		if retries, ok := info.PINRetries(); ok {
			result.Keycard.PINRetries = int(retries)
		}
		if len(info.KeyUID) > 0 {
			result.Keycard.HasMasterKey = true
			result.Keycard.KeyUID = "0x" + hex.EncodeToString(info.KeyUID)
		}
		if ver, ok := kc.SecureChannelVersion(); ok {
			result.Keycard.SecureChannelVersion = fmt.Sprintf("v%d", ver+1)
		}
		if info.HasSecureChannelCapability() {
			result.Keycard.Capabilities = append(result.Keycard.Capabilities, "secure-channel")
		}
		if info.HasKeyManagementCapability() {
			result.Keycard.Capabilities = append(result.Keycard.Capabilities, "key-management")
		}
		if info.HasCredentialsManagementCapability() {
			result.Keycard.Capabilities = append(result.Keycard.Capabilities, "credentials-management")
		}
		if info.HasNDEFCapability() {
			result.Keycard.Capabilities = append(result.Keycard.Capabilities, "ndef")
		}

		if !isV4Plus {
			if len(info.InstanceUID) > 0 {
				result.Keycard.InstanceUID = "0x" + hex.EncodeToString(info.InstanceUID)
			}
			if len(info.AvailableSlots) > 0 {
				slots := int(info.AvailableSlots[0])
				result.Keycard.AvailableSlots = &slots
			}
		}
		if isV4Plus && len(info.CertData) > 0 {
			result.Keycard.Certificate = hex.EncodeToString(info.CertData)
			if cert, err := types.ParseCertificate(info.CertData); err == nil {
				identPub := cert.IdentPub()
				result.Keycard.IdentityPubKey = "0x" + hex.EncodeToString(identPub[:])
			}
		}
		if selectErr != nil {
			result.Keycard.CertVerification = selectErr.Error()
		}
	}

	if cashInfo != nil && cashInfo.Installed {
		result.Cash.Installed = true
		result.Cash.PublicKey = "0x" + hex.EncodeToString(cashInfo.PublicKey)
		result.Cash.Version = "0x" + hex.EncodeToString(cashInfo.Version)
		if len(cashInfo.PublicKey) > 0 {
			if pubkey, err := crypto.UnmarshalPubkey(cashInfo.PublicKey); err == nil {
				result.Cash.Address = crypto.PubkeyToAddress(*pubkey).Hex()
			}
		}
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Pairing core functions
// ---------------------------------------------------------------------------

// doKeycardPair pairs with the card using the given pairing password (V1 only).
func doKeycardPair(kc *keycard.CommandSet, pairingPass string) (*types.Pairing, error) {
	if err := kc.Pair(pairingPass); err != nil {
		return nil, err
	}
	return kc.Pairing(), nil
}

// doKeycardSecureChannelVersion returns the secure channel version string.
func doKeycardSecureChannelVersion(kc *keycard.CommandSet) (string, error) {
	ver, ok := kc.SecureChannelVersion()
	if !ok {
		return "", errors.New("could not determine secure channel version")
	}
	return fmt.Sprintf("v%d", ver+1), nil
}

// ---------------------------------------------------------------------------
// Key management core functions
// ---------------------------------------------------------------------------

// doKeycardGenerateKey generates a new key and returns its UID.
func doKeycardGenerateKey(kc *keycard.CommandSet) ([]byte, error) {
	appStatus, _, err := doKeycardGetStatus(kc)
	if err != nil {
		return nil, err
	}
	if appStatus.KeyInitialized {
		return nil, errors.New("key already generated. Remove it first with 'remove-key'")
	}
	return kc.GenerateKey()
}

// doKeycardExportKey exports a key with the given P2 parameter.
func doKeycardExportKey(kc *keycard.CommandSet, path string, current bool, p2 uint8) (*types.ExportedKey, error) {
	derive := path != ""
	makeCurrent := false
	if !derive && !current {
		derive = false
	}
	return kc.ExportKeyWithP2(derive, makeCurrent, p2, path)
}

// doKeycardExportKeyResult builds an ExportedKeyResult from an exported key.
func doKeycardExportKeyResult(exported *types.ExportedKey, showPrivate bool, path string) ExportedKeyResult {
	pubKey := exported.PubKey()
	ethAddr := ""
	if pubkey, err := crypto.UnmarshalPubkey(pubKey); err == nil {
		ethAddr = crypto.PubkeyToAddress(*pubkey).Hex()
	}
	result := ExportedKeyResult{
		PublicKey: "0x" + hex.EncodeToString(pubKey),
		Address:   ethAddr,
		Path:      path,
	}
	if showPrivate {
		result.PrivateKey = "0x" + hex.EncodeToString(exported.PrivKey())
	}
	return result
}

// doKeycardExportExtendedKeyResult builds an ExportedKeyResult with chain code.
func doKeycardExportExtendedKeyResult(exported *types.ExportedKey, path string) ExportedKeyResult {
	pubKey := exported.PubKey()
	chainCode := exported.ChainCode()
	ethAddr := ""
	if pubkey, err := crypto.UnmarshalPubkey(pubKey); err == nil {
		ethAddr = crypto.PubkeyToAddress(*pubkey).Hex()
	}
	return ExportedKeyResult{
		PublicKey: "0x" + hex.EncodeToString(pubKey),
		ChainCode: "0x" + hex.EncodeToString(chainCode),
		Address:   ethAddr,
		Path:      path,
	}
}

// ---------------------------------------------------------------------------
// Signing core functions
// ---------------------------------------------------------------------------

// doKeycardSign signs data with the current key.
func doKeycardSign(kc *keycard.CommandSet, data []byte) (*types.Signature, error) {
	return kc.Sign(data)
}

// doKeycardSignWithPath signs data deriving at the given path.
func doKeycardSignWithPath(kc *keycard.CommandSet, data []byte, path string) (*types.Signature, error) {
	return kc.SignWithPath(data, path)
}

// doKeycardSignWithPathAndAlgo signs data with a specific algorithm.
func doKeycardSignWithPathAndAlgo(kc *keycard.CommandSet, data []byte, path string, p2 uint8) (*types.Signature, error) {
	return kc.SignWithPathAndAlgo(data, path, p2)
}

// doKeycardSignPinless signs without PIN verification (applet < 4.0 only).
func doKeycardSignPinless(kc *keycard.CommandSet, data []byte) (*types.Signature, error) {
	if internal.IsAppletV4Plus(kc) {
		return nil, errors.New("pinless signing is not available on applet version 4.0+")
	}
	return kc.SignPinless(data)
}

// ---------------------------------------------------------------------------
// Data management core functions
// ---------------------------------------------------------------------------

// doKeycardGetData retrieves data of the given type.
func doKeycardGetData(kc *keycard.CommandSet, dataType uint8) ([]byte, error) {
	return kc.GetData(dataType)
}

// doKeycardStoreData stores data, auto-chunking if > 240 bytes.
func doKeycardStoreData(kc *keycard.CommandSet, dataType uint8, data []byte) error {
	if len(data) > 240 {
		return doStoreDataChunked(kc, dataType, data)
	}
	return kc.StoreData(dataType, data)
}

func doStoreDataChunked(kc *keycard.CommandSet, dataType uint8, data []byte) error {
	chunkSize := 220
	offset := uint16(0)
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		if offset > 0 {
			if err := kc.StoreDataWithOffset(dataType, chunk, offset); err != nil {
				return err
			}
		} else {
			if err := kc.StoreData(dataType, chunk); err != nil {
				return err
			}
		}
		offset += uint16(len(chunk))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Metadata core functions
// ---------------------------------------------------------------------------

// doKeycardGetName reads the card's display name from public data metadata.
func doKeycardGetName(kc *keycard.CommandSet) (string, error) {
	data, err := kc.GetData(keycard.P1StoreDataPublic)
	if err != nil {
		return "", err
	}
	metadata, err := types.ParseMetadata(data)
	if err != nil {
		return "", fmt.Errorf("failed to parse metadata: %w", err)
	}
	return metadata.Name(), nil
}

// doKeycardSetName writes the card's display name to public data metadata.
func doKeycardSetName(kc *keycard.CommandSet, name string) error {
	var metadata *types.Metadata
	existingData, err := kc.GetData(keycard.P1StoreDataPublic)
	if err == nil {
		metadata, err = types.ParseMetadata(existingData)
		if err != nil {
			metadata = types.EmptyMetadata()
		}
	} else {
		metadata = types.EmptyMetadata()
	}
	if err := metadata.SetName(name); err != nil {
		return err
	}
	return kc.StoreData(keycard.P1StoreDataPublic, metadata.Serialize())
}

// ---------------------------------------------------------------------------
// Identify core function
// ---------------------------------------------------------------------------

// doKeycardIdentify performs card identification (V1 only).
// If expectedPubKey is non-nil, verifies the returned key matches.
func doKeycardIdentify(kc *keycard.CommandSet, expectedPubKey []byte) ([]byte, error) {
	pubkey, err := kc.Identify()
	if err != nil {
		return nil, err
	}
	if expectedPubKey != nil && !bytes.Equal(expectedPubKey, pubkey) {
		return nil, fmt.Errorf("genuinity check failed: expected 0x%x, got 0x%x", expectedPubKey, pubkey)
	}
	return pubkey, nil
}

// ---------------------------------------------------------------------------
// Cash core functions
// ---------------------------------------------------------------------------

// doCashSelect selects the Cash applet and returns its info.
func doCashSelect(cashKC *keycard.CashCommandSet) (*types.CashApplicationInfo, error) {
	if err := cashKC.Select(); err != nil {
		return nil, err
	}
	return cashKC.CashApplicationInfo, nil
}

// doCashSign signs data with the Cash applet.
func doCashSign(cashKC *keycard.CashCommandSet, data []byte) (*types.Signature, error) {
	return cashKC.Sign(data)
}

// ---------------------------------------------------------------------------
// Output formatting — shared between CLI and shell
// ---------------------------------------------------------------------------

// formatSignature prints a signature in human-readable format.
func formatSignature(w *strings.Builder, sig *types.Signature) {
	res := newSignatureResult(sig)
	w.WriteString(fmt.Sprintf("Signature R: 0x%s\n", res.R[2:]))
	w.WriteString(fmt.Sprintf("Signature S: 0x%s\n", res.S[2:]))
	w.WriteString(fmt.Sprintf("Signature V: %d\n", res.V))
	w.WriteString(fmt.Sprintf("ETH Signature: %s\n", res.ETHSignature))
	w.WriteString(fmt.Sprintf("Public key: 0x%s\n", res.PublicKey[2:]))
	if res.Address != "" {
		w.WriteString(fmt.Sprintf("Address: %s\n", res.Address))
	}
}

// formatSignatureShell prints a signature in shell format (uppercase labels).
func formatSignatureShell(write func(string), sig *types.Signature) {
	res := newSignatureResult(sig)
	write(fmt.Sprintf("SIGNATURE R: %s\n", res.R))
	write(fmt.Sprintf("SIGNATURE S: %s\n", res.S))
	write(fmt.Sprintf("SIGNATURE V: %x\n", byte(res.V)))
	write(fmt.Sprintf("ETH SIGNATURE: %s\n", res.ETHSignature))
	write(fmt.Sprintf("PUBLIC KEY: %s\n", res.PublicKey))
	write(fmt.Sprintf("ADDRESS: %s\n\n", res.Address))
}

// formatKeycardInfo prints card info in human-readable format.
func formatKeycardInfo(w *strings.Builder, result *KeycardInfoResult) {
	kc := result.Keycard
	w.WriteString("Keycard Applet:\n")
	if !kc.Installed {
		w.WriteString("  Installed: false\n")
	} else {
		w.WriteString("  Installed: true\n")
		w.WriteString(fmt.Sprintf("  Initialized: %v\n", kc.Initialized))
		w.WriteString(fmt.Sprintf("  App Version: %s (%s)\n", kc.AppVersion, kc.AppVersionHex))
		w.WriteString(fmt.Sprintf("  LEE Mode: %v\n", kc.LEEMode))
		w.WriteString(fmt.Sprintf("  Key Initialized: %v\n", kc.HasMasterKey))
		if kc.KeyUID != "" {
			w.WriteString(fmt.Sprintf("  Key UID: %s\n", kc.KeyUID))
		}
		w.WriteString("  Capabilities:\n")
		for _, cap := range kc.Capabilities {
			w.WriteString(fmt.Sprintf("    %s\n", cap))
		}
		if kc.InstanceUID != "" {
			w.WriteString(fmt.Sprintf("  Instance UID: %s\n", kc.InstanceUID))
		}
		if kc.AvailableSlots != nil {
			w.WriteString(fmt.Sprintf("  Available pairing slots: %d\n", *kc.AvailableSlots))
		}
		if kc.Certificate != "" {
			w.WriteString(fmt.Sprintf("  Certificate: %s\n", kc.Certificate))
			if kc.IdentityPubKey != "" {
				w.WriteString(fmt.Sprintf("  Identity public key: %s\n", kc.IdentityPubKey))
			}
		}
		if kc.CertVerification != "" {
			w.WriteString(fmt.Sprintf("  Certificate verification error: %s\n", kc.CertVerification))
		}
	}

	w.WriteString("Cash Applet:\n")
	cash := result.Cash
	if !cash.Installed {
		w.WriteString("  Installed: false\n")
	} else {
		w.WriteString("  Installed: true\n")
		w.WriteString(fmt.Sprintf("  PublicKey: %s\n", cash.PublicKey))
		if cash.Address != "" {
			w.WriteString(fmt.Sprintf("  Address: %s\n", cash.Address))
		}
		w.WriteString(fmt.Sprintf("  Version: %s\n", cash.Version))
	}
}

// formatKeycardInfoShell prints card info in shell format.
func formatKeycardInfoShell(write func(string), result *KeycardInfoResult) {
	kc := result.Keycard
	write("Keycard Applet:\n")
	if !kc.Installed {
		write("  Installed: false\n")
	} else {
		write(fmt.Sprintf("  Installed: true\n"))
		write(fmt.Sprintf("  Initialized: %v\n", kc.Initialized))
		write(fmt.Sprintf("  App Version: %s (%s)\n", kc.AppVersion, kc.AppVersionHex))
		write(fmt.Sprintf("  LEE Mode: %v\n", kc.LEEMode))
		write(fmt.Sprintf("  Key Initialized: %v\n", kc.HasMasterKey))
		if kc.KeyUID != "" {
			write(fmt.Sprintf("  Key UID: %s\n", kc.KeyUID))
		}
	}

	write("Cash Applet:\n")
	cash := result.Cash
	if !cash.Installed {
		write("  Installed: false\n")
	} else {
		write(fmt.Sprintf("  Installed: true\n"))
		write(fmt.Sprintf("  PublicKey: %s\n", cash.PublicKey))
		write(fmt.Sprintf("  Version: %s\n", cash.Version))
	}
}

// ---------------------------------------------------------------------------
// BIP39 mnemonic validation (shared between CLI and shell)
// ---------------------------------------------------------------------------

// validateMnemonic checks that the mnemonic has a valid word count
// and that each word exists in the BIP39 English wordlist.
func validateMnemonic(phrase string) bool {
	words := strings.Fields(phrase)
	n := len(words)
	if n%3 != 0 || n < 12 || n > 24 {
		return false
	}
	for _, word := range words {
		if !containsBIP39Word(word) {
			return false
		}
	}
	return true
}

func containsBIP39Word(word string) bool {
	for i := 0; i < len(types.BIP39EnglishWordlist); i++ {
		if types.BIP39EnglishWordlist[i] == word {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Shell-specific helpers
// ---------------------------------------------------------------------------

// shellCtx holds the card channels and session state for shell commands.
type shellCtx struct {
	ch      types.Channel
	kc      *keycard.CommandSet
	cashKC  *keycard.CashCommandSet
	gp      *globalplatform.CommandSet
	secrets *keycard.Secrets
	write   func(string)
}

// shellResult is the return type for registered shell commands.
type shellResult = map[string]interface{}

// shellFn is the signature for a registered shell command.
type shellFn = func(ctx *shellCtx, args []string) (shellResult, error)

// shellCommand defines a command registered in the shell.
type shellCommand struct {
	name    string
	usage   string
	handler shellFn
}

// requireArgs validates argument count for shell commands.
func requireArgs(args []string, possibleArgsN ...int) error {
	for _, n := range possibleArgsN {
		if len(args) == n {
			return nil
		}
	}
	ns := make([]string, len(possibleArgsN))
	for i, n := range possibleArgsN {
		ns[i] = fmt.Sprintf("%d", n)
	}
	return fmt.Errorf("wrong number of arguments. got: %d, expected: %v", len(args), strings.Join(ns, " | "))
}

// parseHexShell parses a hex string, stripping optional 0x prefix.
func parseHexShell(str string) ([]byte, error) {
	if strings.HasPrefix(str, "0x") {
		str = str[2:]
	}
	return hex.DecodeString(str)
}

// shellSignatureResult converts a SignatureResult to shellResult format.
func shellSignatureResult(sig *types.Signature) shellResult {
	res := newSignatureResult(sig)
	result := shellResult{
		"signature_r":   res.R,
		"signature_s":   res.S,
		"signature_v":   res.V,
		"eth_signature": res.ETHSignature,
		"public_key":    res.PublicKey,
		"address":       res.Address,
	}
	return result
}

// shellSignatureResultWithPath like shellSignatureResult but adds path.
func shellSignatureResultWithPath(sig *types.Signature, path string) shellResult {
	result := shellSignatureResult(sig)
	result["path"] = path
	return result
}

// shellSignatureResultWithFile like shellSignatureResult but adds file.
func shellSignatureResultWithFile(sig *types.Signature, file string) shellResult {
	result := shellSignatureResult(sig)
	result["file"] = file
	return result
}
