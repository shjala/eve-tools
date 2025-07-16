package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/lf-edge/eve-tools/eve-activate-cred/common"
)

type Device struct {
	deviceID string
	// If credentialActivated is true, it means we can trust the AIK to be used in csr
	credentialActivated bool
	cred                []byte
	ek                  *tpm2.Public
	aik                 *tpm2.Public
	certifiedKeys       []crypto.PublicKey
}

var (
	devices         = make(map[string]*Device)
	jwtSharedSecret []byte

	srvCaCert     *x509.Certificate
	srvCaKey      crypto.PrivateKey
	serverTlsCert tls.Certificate
	caCertPool    *x509.CertPool
)

func Initialize() error {
	// Generate a JWT shared secret
	var err error
	jwtSharedSecret, err = generateJWTSecret()
	if err != nil {
		return fmt.Errorf("failed to generate JWT secret: %w", err)
	}

	// generate a self-signed CA certificate
	caKey, caCert, err := generateSelfSignedCA()
	if err != nil {
		return fmt.Errorf("failed to generate CA: %w", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})
	if caCertPEM == nil {
		return fmt.Errorf("failed to encode CA certificate to PEM")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	if keyPEM == nil {
		return fmt.Errorf("failed to encode CA private key to PEM")
	}

	serverTlsCert, err = tls.X509KeyPair(caCertPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to create TLS certificate: %w", err)
	}
	caCertPool = x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return fmt.Errorf("failed to append CA certificate to cert pool")
	}

	srvCaKey = caKey
	srvCaCert = caCert
	return nil
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/activate-cred-param", handleAcParam)
	mux.HandleFunc("/activate-cred", requireAuth(handleAcActive))
	mux.HandleFunc("/certificates", requireAuth(handleRequestCsr))
	mux.HandleFunc("/key-certification", requireAuth(handleKeyCertification))
	mux.HandleFunc("/secure", handleSecureRequest)

	if err := Initialize(); err != nil {
		log.Fatalf("failed to initialize: %v", err)
	}

	// Set up TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTlsCert},
		// don't be strict on the client certs, but request them,
		// "/secure" endpoint requires it.
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12,
	}
	server := &http.Server{
		Addr:      common.ServerPort,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	log.Printf("Server starting on port %s...\n", common.ServerPort)
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
