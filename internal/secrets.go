package internal

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const defaultSecretsFile = ".keycard/secrets"

// Secrets holds resolved card credentials.
type Secrets struct {
	Pin         string
	Puk         string
	PairingPass string
}

// ResolveSecrets resolves secrets in priority order:
// 1. CLI flags
// 2. Environment variables
// 3. Secrets file
// 4. Interactive prompt (only if interactive is true and stdin is a TTY)
func ResolveSecrets(pinFlag, pukFlag, pairingFlag, secretsFile string, interactive bool) (*Secrets, error) {
	secrets := &Secrets{}

	// 1. CLI flags
	if pinFlag != "" {
		secrets.Pin = pinFlag
	}
	if pukFlag != "" {
		secrets.Puk = pukFlag
	}
	if pairingFlag != "" {
		secrets.PairingPass = pairingFlag
	}

	// 2. Environment variables
	if secrets.Pin == "" {
		if v := os.Getenv("KEYCARD_PIN"); v != "" {
			secrets.Pin = v
		}
	}
	if secrets.Puk == "" {
		if v := os.Getenv("KEYCARD_PUK"); v != "" {
			secrets.Puk = v
		}
	}
	if secrets.PairingPass == "" {
		if v := os.Getenv("KEYCARD_PAIRING_PASSWORD"); v != "" {
			secrets.PairingPass = v
		}
	}

	// 3. Secrets file
	if secretsFile == "" {
		// Default to ~/.keycard/secrets if it exists
		if home, err := os.UserHomeDir(); err == nil {
			defaultPath := filepath.Join(home, defaultSecretsFile)
			if _, err := os.Stat(defaultPath); err == nil {
				secretsFile = defaultPath
			}
		}
	}

	if secretsFile != "" {
		if err := loadSecretsFile(secretsFile, secrets); err != nil {
			return nil, fmt.Errorf("error loading secrets file %s: %w", secretsFile, err)
		}
	}

	// 4. Interactive prompt
	if interactive && isTTY() {
		if secrets.Pin == "" {
			secrets.Pin = promptSecret("PIN")
		}
		if secrets.Puk == "" {
			secrets.Puk = promptSecret("PUK")
		}
		if secrets.PairingPass == "" {
			secrets.PairingPass = promptSecret("Pairing password")
		}
	}

	return secrets, nil
}

// WriteSecretsFile writes secrets to a file in INI-style format.
// The file is created with restrictive permissions (0600).
func WriteSecretsFile(path string, secrets *Secrets) error {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("error getting home directory: %w", err)
		}
		path = filepath.Join(home, defaultSecretsFile)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("error creating secrets directory: %w", err)
	}

	var lines []string
	if secrets.Pin != "" {
		lines = append(lines, fmt.Sprintf("pin=%s", secrets.Pin))
	}
	if secrets.Puk != "" {
		lines = append(lines, fmt.Sprintf("puk=%s", secrets.Puk))
	}
	if secrets.PairingPass != "" {
		lines = append(lines, fmt.Sprintf("pairing-password=%s", secrets.PairingPass))
	}

	content := strings.Join(lines, "\n") + "\n"

	return os.WriteFile(path, []byte(content), 0600)
}

func loadSecretsFile(path string, secrets *Secrets) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch key {
		case "pin":
			if secrets.Pin == "" {
				secrets.Pin = value
			}
		case "puk":
			if secrets.Puk == "" {
				secrets.Puk = value
			}
		case "pairing-password", "pairing_password", "pairingpass":
			if secrets.PairingPass == "" {
				secrets.PairingPass = value
			}
		}
	}

	return scanner.Err()
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func promptSecret(label string) string {
	fmt.Printf("%s: ", label)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

// DefaultSecretsFilePath returns the default secrets file path (~/.keycard/secrets).
func DefaultSecretsFilePath() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(u.HomeDir, defaultSecretsFile), nil
}
