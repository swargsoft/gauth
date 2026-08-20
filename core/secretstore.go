package core

import "os"

// SecretStore seals/opens sensitive values (refresh tokens) using local
// AES-256-GCM envelope encryption. This protects against casual
// inspection of the SQLite file in isolation (e.g. a backup or support
// bundle); it is NOT equivalent to an OS credential vault — anyone with
// code execution as this OS user can also read the master key file
// directly. See SECURITY.md.
type SecretStore struct {
	masterKey string
}

func NewSecretStore(masterKey string) *SecretStore {
	return &SecretStore{masterKey: masterKey}
}

func (s *SecretStore) Seal(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	return EncryptWithKey(value, s.masterKey)
}

func (s *SecretStore) Open(blob string) (string, error) {
	if blob == "" {
		return "", nil
	}
	return DecryptWithKey(blob, s.masterKey)
}

// LoadOrCreateMasterKey reads the local master key from path, generating
// and persisting one (0600) on first run.
func LoadOrCreateMasterKey(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		return string(trimTrailingNewline(data)), nil
	}
	key := GenerateMasterKey()
	if err := os.WriteFile(path, []byte(key), 0600); err != nil {
		return "", err
	}
	return key, nil
}

func trimTrailingNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
