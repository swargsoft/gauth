package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("gauth: failed to read random bytes: " + err.Error())
	}
	return b
}

// GenerateState returns a CSPRNG, single-use OAuth CSRF state token.
func GenerateState() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(32))
}

// GenerateAttemptID returns a short random identifier correlating the
// authorization request, callback, and token exchange of one OAuth
// attempt in the logs. It grants no access and is safe to log.
func GenerateAttemptID() string {
	return hex.EncodeToString(randomBytes(6)) // 12 hex chars
}

// GenerateCodeVerifier returns a PKCE code_verifier per RFC 7636:
// 43-128 chars from the unreserved character set. 64 random bytes ->
// ~86 chars, comfortably in range.
func GenerateCodeVerifier() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(64))
}

// CodeChallengeS256 computes the RFC 7636 S256 code_challenge:
// BASE64URL(SHA256(ASCII(code_verifier))).
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SHA256Hex hashes a value for at-rest storage — only the hash of the
// OAuth state is ever persisted, never the raw token.
func SHA256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// TimingSafeEqual does a constant-time comparison, safe for secrets of
// attacker-controlled length (used to check the optional API key).
func TimingSafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// GenerateMasterKey returns a random 256-bit key, base64-encoded, for
// local envelope encryption of refresh tokens at rest (see SecretStore).
func GenerateMasterKey() string {
	return base64.StdEncoding.EncodeToString(randomBytes(32))
}

// EncryptWithKey encrypts plaintext with AES-256-GCM. Returns
// base64(nonce || ciphertext+tag).
func EncryptWithKey(plaintext, masterKeyB64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		return "", fmt.Errorf("invalid master key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := randomBytes(gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWithKey reverses EncryptWithKey.
func DecryptWithKey(blobB64, masterKeyB64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		return "", fmt.Errorf("invalid master key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(blobB64)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (wrong key or tampered data): %w", err)
	}
	return string(plaintext), nil
}
