// Package cmd contains the CLI and shell command implementations.
//
// Architecture:
//
//   - core.go: business logic functions and shared result types.
//     Result types implement Format() for text output and carry json tags for JSON.
//   - *.go (gp, lifecycle, pairing, etc.): top-level CLI commands. Parse flags,
//     call runCard/runGP/runCash, delegate to core functions, emit via PrintResultCLI.
//   - shell.go + shell_commands.go: shell interpreter. Parse positional args,
//     maintain session state, delegate to core functions, emit via PrintResult.
//
// To add a new command:
//  1. Add the core business logic function in core.go
//  2. Add the CLI command in the appropriate *.go file
//  3. Register in shell_commands.go RegisterShellCommands()

package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	keycard "github.com/keycard-tech/keycard-go/v4"
	"github.com/keycard-tech/keycard-go/v4/apdu"
	"github.com/keycard-tech/keycard-go/v4/globalplatform"
	"github.com/keycard-tech/keycard-go/v4/types"

	"github.com/keycard-tech/keycard-cli/internal"
)

// ---------------------------------------------------------------------------
// Output dispatcher — shared between CLI and shell
// ---------------------------------------------------------------------------

// OutputMode controls output format.
type OutputMode int

// Version is the CLI version string. Set by main package at startup from the
// -ldflags value; defaults to "dev" for local builds.
var Version = "dev"

const (
	OutputText OutputMode = iota
	OutputJSON
)

// Result is implemented by all command result types.
type Result interface {
	Format(showSecrets bool) string
}

// PrintResult writes r to stdout as JSON (if mode == OutputJSON) or
// as formatted text (r.Format(showSecrets)).
func PrintResult(mode OutputMode, r Result, showSecrets bool) error {
	if mode == OutputJSON {
		var result interface{} = r
		if !showSecrets {
			result = maskResultForJSON(r)
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(data))
		return nil
	}
	fmt.Print(r.Format(showSecrets))
	return nil
}

// PrintResultCLI is a convenience wrapper for standalone CLI commands.
// It reads the --json and --show-secrets flags from cmd and dispatches to PrintResult.
func PrintResultCLI(cmd interface{ Bool(string) bool }, r Result) error {
	mode := OutputText
	if cmd.Bool("json") {
		mode = OutputJSON
	}
	return PrintResult(mode, r, cmd.Bool("show-secrets"))
}

// MaxStoreDataLen is the maximum number of bytes that can be stored in a single
// store-data operation. The applet encodes the offset as a single byte
// (offset/4), so offsets ≥ 1024 would wrap and overwrite earlier data.
const MaxStoreDataLen = 1020

// maskResultForJSON returns a copy of r with secret fields masked. Call this
// only when secrets should be hidden (i.e. --show-secrets was not set).
func maskResultForJSON(r Result) interface{} {
	switch v := r.(type) {
	case InitResult:
		result := InitResult{
			Pin: "***",
			Puk: "***",
		}
		if v.PairingPassword != "" {
			result.PairingPassword = "***"
		}
		return result
	case SetSecretsResult:
		return SetSecretsResult{
			Pin:             "***",
			Puk:             "***",
			PairingPassword: "***",
		}
	case SetPairingResult:
		return SetPairingResult{
			PairingKey:   "***",
			PairingIndex: v.PairingIndex,
		}
	case PairingResult:
		return PairingResult{
			PairingKey:   "***",
			PairingIndex: v.PairingIndex,
		}
	default:
		return r
	}
}

// ---------------------------------------------------------------------------
// Result types — shared between CLI and shell for structured output
// ---------------------------------------------------------------------------

// GPResult holds the result of a GP APDU send.
type GPResult struct {
	SW   uint16 `json:"-"`
	Data []byte `json:"-"`

	SWStr   string `json:"sw"`
	DataHex string `json:"data"`
}

func (r GPResult) Format(_ bool) string {
	return fmt.Sprintf("SW: 0x%04x\nResponse: 0x%s\n", r.SW, hex.EncodeToString(r.Data))
}

// KeycardInfoResult holds keycard applet info (for the "info" CLI/shell command).
type KeycardInfoResult struct {
	Keycard KeycardInfo `json:"keycard"`
}

func (r *KeycardInfoResult) Format(_ bool) string {
	var w strings.Builder
	kc := r.Keycard
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
	return w.String()
}

// CashInfoResult holds cash applet info (for the "cash-info" CLI/shell command).
type CashInfoResult struct {
	Cash CashInfo `json:"cash"`
}

func (r *CashInfoResult) Format(_ bool) string {
	var w strings.Builder
	w.WriteString("Cash Applet:\n")
	cash := r.Cash
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
	return w.String()
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
	PINRetries           int      `json:"pin_retries"`
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

func (r AppStatusResult) Format(_ bool) string {
	return fmt.Sprintf("PIN retry count: %d\nPUK retry count: %d\nKey initialized: %v\nKey path: %s\n",
		r.PinRetryCount, r.PUKRetryCount, r.KeyInitialized, r.KeyPath)
}

// PairingResult holds pairing information.
type PairingResult struct {
	PairingKey   string `json:"pairing_key"`
	PairingIndex int    `json:"pairing_index"`
}

func (r PairingResult) Format(showSecrets bool) string {
	key := r.PairingKey
	if !showSecrets {
		key = "***"
	}
	return fmt.Sprintf("Pairing key: %s\nPairing index: %d\n", key, r.PairingIndex)
}

// KeyGenerateResult — "generate-key"
type KeyGenerateResult struct {
	KeyUID string `json:"key_uid"`
}

func (r KeyGenerateResult) Format(_ bool) string {
	return fmt.Sprintf("Key generated. UID: %s\n", r.KeyUID)
}

// KeyLoadResult — "load-seed"
type KeyLoadResult struct {
	KeyID string `json:"key_id"`
}

func (r KeyLoadResult) Format(_ bool) string {
	return fmt.Sprintf("Seed loaded. Key ID: %s\n", r.KeyID)
}

// InitResult — "init" (no "Card initialized." prefix)
type InitResult struct {
	Pin             string `json:"pin"`
	Puk             string `json:"puk"`
	PairingPassword string `json:"pairing_password,omitempty"`
}

func (r InitResult) Format(showSecrets bool) string {
	var w strings.Builder
	if showSecrets {
		w.WriteString(fmt.Sprintf("PIN: %s\n", r.Pin))
		w.WriteString(fmt.Sprintf("PUK: %s\n", r.Puk))
	} else {
		w.WriteString("PIN: ***\n")
		w.WriteString("PUK: ***\n")
	}
	if r.PairingPassword != "" {
		if showSecrets {
			w.WriteString(fmt.Sprintf("Pairing password: %s\n", r.PairingPassword))
		} else {
			w.WriteString("Pairing password: ***\n")
		}
	}
	return w.String()
}

// GPStatusResult — "gp-get-status"
type GPStatusResult struct {
	Lifecycle string `json:"lifecycle"`
}

func (r GPStatusResult) Format(_ bool) string {
	return fmt.Sprintf("Card status: %s\n", r.Lifecycle)
}

// ActionResult — simple confirmation messages
type ActionResult struct {
	Message string `json:"message"`
}

func (r ActionResult) Format(_ bool) string {
	return r.Message + "\n"
}

// UnpairResult — "unpair" (includes index)
type UnpairResult struct {
	Index int `json:"index"`
}

func (r UnpairResult) Format(_ bool) string {
	return fmt.Sprintf("Unpaired (index: %d)\n", r.Index)
}

// StoreDataResult — "store-data"
type StoreDataResult struct {
	Type  string `json:"type"`
	Bytes int    `json:"bytes"`
}

func (r StoreDataResult) Format(_ bool) string {
	return fmt.Sprintf("Data stored (%s, %d bytes)\n", r.Type, r.Bytes)
}

// SetNDEFResult — "set-ndef"
type SetNDEFResult struct {
	Bytes int `json:"bytes"`
}

func (r SetNDEFResult) Format(_ bool) string {
	return fmt.Sprintf("NDEF set (%d bytes)\n", r.Bytes)
}

// SetSecretsResult — "keycard-set-secrets" (shell-only)
type SetSecretsResult struct {
	Pin             string `json:"pin"`
	Puk             string `json:"puk"`
	PairingPassword string `json:"pairing_password"`
}

func (r SetSecretsResult) Format(showSecrets bool) string {
	pin := r.Pin
	puk := r.Puk
	pairing := r.PairingPassword
	if !showSecrets {
		pin = "***"
		puk = "***"
		pairing = "***"
	}
	return fmt.Sprintf("Secrets set (PIN: %s, PUK: %s, Pairing: %s)\n",
		pin, puk, pairing)
}

// SetPairingResult — "keycard-set-pairing" (shell-only)
type SetPairingResult struct {
	PairingKey   string `json:"pairing_key"`
	PairingIndex int    `json:"pairing_index"`
}

func (r SetPairingResult) Format(showSecrets bool) string {
	key := r.PairingKey
	if !showSecrets {
		key = "***"
	}
	return fmt.Sprintf("Pairing set (key: %s, index: %d)\n",
		key, r.PairingIndex)
}

// LEEKeyResult — "export-lee-key"
type LEEKeyResult struct {
	Key  string `json:"key"`
	Path string `json:"path"`
}

func (r LEEKeyResult) Format(_ bool) string {
	return fmt.Sprintf("LEE key: %s\n", r.Key)
}

// BIP85KeyResult — "export-bip85"
type BIP85KeyResult struct {
	Key  string `json:"key"`
	Path string `json:"path"`
}

func (r BIP85KeyResult) Format(_ bool) string {
	return fmt.Sprintf("BIP85 key: %s\n", r.Key)
}

// ExportedKeyResult holds exported key data.
type ExportedKeyResult struct {
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key"`
	ChainCode  string `json:"chain_code,omitempty"`
	Address    string `json:"address,omitempty"`
	Path       string `json:"path,omitempty"`
}

func (r ExportedKeyResult) Format(_ bool) string {
	var w strings.Builder
	if r.PrivateKey != "" {
		w.WriteString(fmt.Sprintf("Private key: %s\n", r.PrivateKey))
	}
	w.WriteString(fmt.Sprintf("Public key: %s\n", r.PublicKey))
	if r.ChainCode != "" {
		w.WriteString(fmt.Sprintf("Chain code: %s\n", r.ChainCode))
	}
	if r.Address != "" {
		w.WriteString(fmt.Sprintf("Address: %s\n", r.Address))
	}
	if r.Path != "" {
		w.WriteString(fmt.Sprintf("Path: %s\n", r.Path))
	}
	return w.String()
}

// SignatureResult holds signature data.
type SignatureResult struct {
	R    string `json:"signature_r"`
	S    string `json:"signature_s"`
	V    int    `json:"signature_v"`
	Path string `json:"path,omitempty"`
	File string `json:"file,omitempty"`
}

func (r SignatureResult) Format(_ bool) string {
	var w strings.Builder
	w.WriteString(fmt.Sprintf("Signature R: %s\n", r.R))
	w.WriteString(fmt.Sprintf("Signature S: %s\n", r.S))
	w.WriteString(fmt.Sprintf("Signature V: %d\n", r.V))
	if r.Path != "" {
		w.WriteString(fmt.Sprintf("Path: %s\n", r.Path))
	}
	if r.File != "" {
		w.WriteString(fmt.Sprintf("File: %s\n", r.File))
	}
	return w.String()
}

// DataResult holds stored/retrieved data.
type DataResult struct {
	Type  string `json:"type"`
	Data  string `json:"data,omitempty"`
	Bytes int    `json:"bytes,omitempty"`
}

func (r DataResult) Format(_ bool) string {
	return fmt.Sprintf("Data (%s): %s\n", r.Type, r.Data)
}

// ChallengeResult holds a random challenge.
type ChallengeResult struct {
	Challenge string `json:"challenge"`
}

func (r ChallengeResult) Format(_ bool) string {
	return fmt.Sprintf("Challenge: %s\n", r.Challenge)
}

// NameResult holds card display name.
type NameResult struct {
	Name string `json:"name"`
}

func (r NameResult) Format(_ bool) string {
	return fmt.Sprintf("Card name: %s\n", r.Name)
}

// IdentifyResult holds card identification result.
type IdentifyResult struct {
	Identified bool   `json:"identified"`
	PublicKey  string `json:"public_key"`
}

func (r IdentifyResult) Format(_ bool) string {
	return fmt.Sprintf("Identification OK (public key: %s)\n", r.PublicKey)
}

// SecureChannelVersionResult holds the secure channel version.
type SecureChannelVersionResult struct {
	Version string `json:"secure_channel_version"`
}

func (r SecureChannelVersionResult) Format(_ bool) string {
	return fmt.Sprintf("Secure channel version: %s\n", r.Version)
}

// GenerateMnemonicResult holds the result of generating a mnemonic phrase.
type GenerateMnemonicResult struct {
	Phrase string `json:"phrase"`
	Words  int    `json:"words"`
	KeyID  string `json:"key_id,omitempty"` // set when mnemonic is also loaded onto the card
}

func (r GenerateMnemonicResult) Format(showSecrets bool) string {
	line := fmt.Sprintf("Mnemonic (%d words): %s\n", r.Words, r.Phrase)
	if r.KeyID != "" {
		line += fmt.Sprintf("Key ID: %s\n", r.KeyID)
	}
	return line
}

// LoadIdentResult holds the result of loading an identity certificate.
type LoadIdentResult struct {
	Bytes int `json:"bytes"`
}

func (r LoadIdentResult) Format(_ bool) string {
	return fmt.Sprintf("Identity certificate loaded (%d bytes)\n", r.Bytes)
}

// ---------------------------------------------------------------------------
// Helper: build SignatureResult from a types.Signature
// ---------------------------------------------------------------------------

func newSignatureResult(sig *types.Signature) SignatureResult {
	return SignatureResult{
		R: "0x" + hex.EncodeToString(sig.R()),
		S: "0x" + hex.EncodeToString(sig.S()),
		V: int(sig.V()),
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
	var channel interface {
		Send(*apdu.Command) (*apdu.Response, error)
	}
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

// doKeycardInit initializes the card. Handles V1 vs V2 automatically.
func doKeycardInit(kc *keycard.CommandSet, pin, puk, pairingPass, altPin string, pinRetries, pukRetries uint8) error {
	if internal.IsSecureChannelV2(kc) {
		return kc.InitWithOptionsV2(pin, altPin, puk, pinRetries, pukRetries)
	}

	return kc.InitWithOptions(pin, altPin, puk, pairingPass, pinRetries, pukRetries)
}

// doKeycardGetStatus returns application and key path status.
// On applet >= 4.0, GetStatusKeyPath is not supported so keyStatus will be nil.
func doKeycardGetStatus(kc *keycard.CommandSet) (*types.ApplicationStatus, *types.ApplicationStatus, error) {
	appStatus, err := kc.GetStatusApplication()
	if err != nil {
		return nil, nil, err
	}
	if internal.IsAppletV4Plus(kc) {
		return appStatus, nil, nil
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
	result := AppStatusResult{
		PinRetryCount:  appStatus.PinRetryCount,
		PUKRetryCount:  appStatus.PUKRetryCount,
		KeyInitialized: appStatus.KeyInitialized,
	}
	if keyStatus != nil {
		result.KeyPath = keyStatus.Path
	}
	return result, nil
}

// doKeycardInfoKeycard builds keycard applet info only.
func doKeycardInfoKeycard(kc *keycard.CommandSet, selectErr error) (*KeycardInfoResult, error) {
	info := kc.AppInfo()

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

	return result, nil
}

// doKeycardInfoCash builds cash applet info only.
func doKeycardInfoCash(cashKC *keycard.CashCommandSet) (*CashInfoResult, error) {
	cashInfo := cashKC.CashApplicationInfo

	result := &CashInfoResult{}

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

// doKeycardPair pairs with the card using the given pairing password (applet < 4.0 only).
func doKeycardPair(kc *keycard.CommandSet, pairingPass string) (*types.Pairing, error) {
	if err := kc.Pair(pairingPass); err != nil {
		return nil, err
	}
	return kc.Pairing(), nil
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

// doKeycardGenerateMnemonic generates a mnemonic phrase using the card's RNG.
// words controls the number of words: must be 12, 15, 18, 21, or 24
// (corresponding to checksumSize 4, 5, 6, 7, 8 respectively).
// When save is true, the mnemonic's binary seed is also loaded onto the card
// and the key ID is returned.
func doKeycardGenerateMnemonic(kc *keycard.CommandSet, words int, save bool) (*types.Mnemonic, []byte, error) {
	if err := validateWordCount(words); err != nil {
		return nil, nil, err
	}
	checksumSize := words / 3
	indexes, err := kc.GenerateMnemonic(checksumSize)
	if err != nil {
		return nil, nil, err
	}
	int16Indexes := make([]int16, len(indexes))
	for i, v := range indexes {
		int16Indexes[i] = int16(v)
	}
	mnemonic, err := types.MnemonicFromIndices(int16Indexes)
	if err != nil {
		return nil, nil, err
	}
	if save {
		seed := mnemonic.ToBinarySeed()
		keyID, err := kc.LoadSeed(seed)
		if err != nil {
			return nil, nil, err
		}
		return mnemonic, keyID, nil
	}
	return mnemonic, nil, nil
}

// validateWordCount validates that the word count is a valid BIP39 size.
func validateWordCount(words int) error {
	switch words {
	case 12, 15, 18, 21, 24:
		return nil
	default:
		return fmt.Errorf("invalid word count: %d (must be 12, 15, 18, 21, or 24)", words)
	}
}

// doKeycardExportBIP85 exports a BIP85 derived key with validated path and length.
// The path must start with m/83696968' (the BIP85 commitment prefix).
func doKeycardExportBIP85(kc *keycard.CommandSet, path string, length int) ([]byte, error) {
	if length < 1 || length > 255 {
		return nil, fmt.Errorf("--length must be between 1 and 255 bytes, got %d", length)
	}
	if !strings.HasPrefix(path, "m/83696968'") {
		return nil, fmt.Errorf("invalid BIP85 path: must start with m/83696968'")
	}
	return kc.ExportBIP85(path, uint8(length))
}

// doKeycardGetChallenge retrieves a random challenge from the card with
// validated length (1-255 bytes).
func doKeycardGetChallenge(kc *keycard.CommandSet, length int) ([]byte, error) {
	if length < 1 || length > 255 {
		return nil, fmt.Errorf("--length must be between 1 and 255 bytes, got %d", length)
	}
	return kc.GetChallenge(uint8(length))
}

// doKeycardExportKey exports a key with the given P2 parameter.
func doKeycardExportKey(kc *keycard.CommandSet, path string, current bool, p2 uint8) (*types.ExportedKey, error) {
	if path == "" {
		path = "."
	}
	return kc.ExportKeyWithP2(true, current, p2, path)
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
	if len(data) > MaxStoreDataLen {
		return fmt.Errorf("data too large: %d bytes (maximum supported is %d)", len(data), MaxStoreDataLen)
	}
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

// doKeycardIdentify performs card identification (applet < 4.0 only).
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

// doCashSign signs data with the Cash applet.
func doCashSign(cashKC *keycard.CashCommandSet, data []byte) (*types.Signature, error) {
	return cashKC.Sign(data)
}

// ---------------------------------------------------------------------------
// Shell context
// ---------------------------------------------------------------------------

// shellCtx holds the card channels and session state for shell commands.
type shellCtx struct {
	ch          types.Channel
	kc          *keycard.CommandSet
	cashKC      *keycard.CashCommandSet
	identKC     *keycard.IdentCommandSet
	gp          *globalplatform.CommandSet
	secrets     *keycard.Secrets
	write       func(string)
	showSecrets bool
}

// shellOutput holds both typed result and formatted text for a shell command.
type shellOutput struct {
	Result Result // typed result (implements Format())
	Text   string // for text output
}

// newShellOutput creates a shellOutput from a typed result.
func newShellOutput(r Result, showSecrets bool) *shellOutput {
	return &shellOutput{Result: r, Text: r.Format(showSecrets)}
}

// shellFn is the signature for a registered shell command.
type shellFn = func(ctx *shellCtx, args []string) (*shellOutput, error)

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
