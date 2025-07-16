package main

import (
	"fmt"
	"log"

	"github.com/lf-edge/eve-tools/eve-activate-cred/common"
	vcom "github.com/lf-edge/eve/pkg/pillar/vcom/go-api"
)

const serverURL = "https://localhost" + common.ServerPort

func main() {
	fmt.Println("[1] Establishing trust in Attestation Identity Key (AIK)...")
	acParam, err := initiateAikActivationWithVerifier()
	if err != nil {
		log.Fatalf("error initiating AIK activation: %v", err)
	}
	fmt.Printf("\tReceived device ID: %s\n", acParam.DeviceID)
	fmt.Printf("\tReceived token: %s...\n", acParam.Token[:16])

	fmt.Println("[2] Proving TPM holds the EK and can decrypt credential...")
	err = completeAikActivationWithVerifier(acParam.Token, acParam.Cred)
	if err != nil {
		log.Fatalf("error completing AIK activation: %v", err)
	}
	fmt.Println("[3] Activation completed successfully, verifier now trusts the AIK.")

	fmt.Println("[4] Proving signing key is certified by the AIK...")
	err = proveKeyCertificationWithVerifier(vcom.TpmEcdhHandle, acParam.Token)
	if err != nil {
		log.Fatalf("error proving key certification: %v", err)
	}
	fmt.Println("[5] Key certification completed successfully, verifier now trusts the signing key.")

	fmt.Println("[6] Submitting CSR for certificate...")
	clientCertDER, err := submitCsrForCertificate(acParam.Token, acParam.DeviceID, vcom.TpmEcdhHandle)
	if err != nil {
		log.Fatalf("error submitting CSR for certificate: %v", err)
	}
	fmt.Println("[7] CSR submitted successfully, received signed client certificate.")

	fmt.Println("[8] Accessing secure endpoint with client certificate...")
	out, err := postData(serverURL+"/secure", nil, "", clientCertDER, vcom.TpmEcdhHandle)
	if err != nil {
		log.Fatalf("error posting CSR to server: %v", err)
	}
	fmt.Printf("\tReceived data from server: \"%s\"\n", string(out))
	fmt.Println("[9] Secure endpoint accessed successfully, client certificate is valid.")
	fmt.Println("[10] All operations completed successfully.")
}
