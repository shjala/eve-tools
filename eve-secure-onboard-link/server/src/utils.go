package main

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"net/http"

	"github.com/google/go-tpm/legacy/tpm2"
)

func handleHTTPError(w http.ResponseWriter, httpCode int, format string, a ...any) string {
	err := fmt.Sprintf(format, a...)
	http.Error(w, err, httpCode)
	return err
}

func generateJWTSecret() ([]byte, error) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	return secret, err
}

func getDigest(alg tpm2.Algorithm, data []byte) ([]byte, crypto.Hash, error) {
	hash, err := alg.Hash()
	if err != nil {
		return nil, crypto.Hash(0), fmt.Errorf("failed to get hash algorithm for AIK: %w", err)
	}
	hasher := hash.New()
	hasher.Write(data)
	return hasher.Sum(nil), hash, nil
}
