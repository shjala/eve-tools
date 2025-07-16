package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-tpm/tpmutil"
	vcom "github.com/lf-edge/eve/pkg/pillar/vcom/go-api"
	"google.golang.org/protobuf/proto"
)

func getActivateCredParams() ([]byte, error) {
	paramsRequest := vcom.TpmRequestActivateCredParams{
		Index: uint32(vcom.TpmAIKHandle),
	}
	out, err := proto.Marshal(&paramsRequest)
	if err != nil {
		return nil, fmt.Errorf("error when marshalling request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/activatecredparams", bytes.NewBuffer(out))
	if err != nil {
		return nil, fmt.Errorf("error when creating request: %w", err)
	}
	signResp, err := getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("error when sending request: %w", err)
	}
	defer signResp.Body.Close()

	if signResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status code 200, got %d", signResp.StatusCode)
	}

	body, err := io.ReadAll(signResp.Body)
	if err != nil {
		return nil, fmt.Errorf("error when reading response body: %w", err)
	}

	var tpmRespACParams vcom.TpmResponseActivateCredParams
	err = proto.Unmarshal(body, &tpmRespACParams)
	if err != nil {
		return nil, fmt.Errorf("error when unmarshalling response body: %w", err)
	}

	return body, nil
}

func completeAikActivationWithVerifier(token string, cred []byte) error {
	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/activatecred", bytes.NewBuffer(cred))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	credResp, err := getClient().Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer credResp.Body.Close()
	if credResp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code 200, got %d", credResp.StatusCode)
	}
	body, err := io.ReadAll(credResp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	var tpmResp vcom.TpmResponseActivatedCred
	err = proto.Unmarshal(body, &tpmResp)
	if err != nil {
		return fmt.Errorf("error unmarshalling response body: %w", err)
	} else {
		fmt.Printf("\tRecovered credential: %x\n", tpmResp.Secret)
	}
	_, err = postData(serverURL+"/activate-cred", body, token, nil, 0)
	if err != nil {
		return fmt.Errorf("error posting activate credential parameters: %w", err)
	}

	return nil
}

func proveKeyCertificationWithVerifier(signingKey tpmutil.Handle, token string) error {
	request := vcom.TpmRequestCertify{
		Index: uint32(signingKey),
	}
	out, err := proto.Marshal(&request)
	if err != nil {
		return fmt.Errorf("error when marshalling request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/certifykey", bytes.NewBuffer(out))
	if err != nil {
		return fmt.Errorf("error when creating request: %w", err)
	}
	resp, err := getClient().Do(req)
	if err != nil {
		return fmt.Errorf("error when sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error when reading response body: %w", err)
	}

	// send the certification data to the server to establish trust in the new key
	_, err = postData(serverURL+"/key-certification", body, token, nil, 0)
	if err != nil {
		return fmt.Errorf("error posting activate credential parameters: %w", err)
	}

	return nil
}
