package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve-tools/eve-activate-cred/common"
)

func generateCsr(deviceID string, keyHandle tpmutil.Handle) ([]byte, error) {
	tpmSigner, sigAlg, err := getTpmSigner(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM signer: %w", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   deviceID,
			Organization: []string{"Example Org"},
		},
		SignatureAlgorithm: sigAlg,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, tpmSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	return csrPEM, nil
}

func submitCsrForCertificate(token string, devId string, signingKey tpmutil.Handle) ([]byte, error) {
	crs, err := generateCsr(devId, signingKey)
	if err != nil {
		return nil, fmt.Errorf("error generating CSR: %w", err)
	}

	clientCertPEM, err := postData(serverURL+"/certificates", crs, token, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("error posting CSR to server: %w", err)
	}
	clientCertDER, err := pemToDER(clientCertPEM)
	if err != nil {
		return nil, fmt.Errorf("error converting PEM to DER: %w", err)
	}

	return clientCertDER, nil
}

func initiateAikActivationWithVerifier() (*common.AcParamRes, error) {
	acParam, err := getActivateCredParams()
	if err != nil {
		return nil, fmt.Errorf("error getting activate credential parameters: %w", err)
	}

	// initiate the trust process by sending the AC parameters to the server
	out, err := postData(serverURL+"/activate-cred-param", acParam, "", nil, 0)
	if err != nil {
		return nil, fmt.Errorf("error posting activate credential parameters: %w", err)
	}

	// We recived the credential from the server, now we need to activate it
	// to prove the device identity and establish trust in AIK
	response := common.AcParamRes{}
	err = json.Unmarshal(out, &response)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling activate credential response: %w", err)
	}

	return &response, nil
}
