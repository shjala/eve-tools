package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	vcom "github.com/lf-edge/eve/pkg/pillar/vcom/go-api"
	"google.golang.org/protobuf/proto"
)

func verfiyCredentialActivation(data []byte, cred []byte) error {
	var tpmResp vcom.TpmResponseActivatedCred
	err := proto.Unmarshal(data, &tpmResp)
	if err != nil {
		return fmt.Errorf("error unmarshalling response body: %w", err)
	}

	// Verify the credential
	if !bytes.Equal(tpmResp.Secret, cred) {
		return fmt.Errorf("credential verification failed")
	} else {
		fmt.Printf("\tRecovered credential: %x\n", tpmResp.Secret)
		fmt.Println("\tRecovered credential matches the device credential")
	}

	return nil
}

func verifyActivateCredParameters(data []byte) ([]byte, []byte, *tpm2.Public, *tpm2.Public, error) {
	// get EK public key, AIK name and AIK public key from the request body
	ekPub, name, aikPub, err := decodeAcParam(data)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to decode activate credential parameters: %w", err)
	}

	// Verify the AIK claims holds and get the generated credential
	cred, credPlain, err := verifyAIKClaims(name, aikPub, ekPub)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to verify AIK claims: %w", err)
	}

	return cred, credPlain, ekPub, aikPub, nil
}

func decodeAcParam(body []byte) (*tpm2.Public, *tpm2.Name, *tpm2.Public, error) {
	var tpmRespACParams vcom.TpmResponseActivateCredParams
	err := proto.Unmarshal(body, &tpmRespACParams)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmarshal request body: %w", err)
	}

	// decode back EK pub to a format we can work with
	ekPub, err := tpm2.DecodePublic(tpmRespACParams.Ek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode EK public key: %w", err)
	}

	// decode back AIK name to a format we can work with
	name, err := tpm2.DecodeName(bytes.NewBuffer(tpmRespACParams.AikName))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode AIK name: %w", err)
	}
	aikPub, err := tpm2.DecodePublic(tpmRespACParams.AikPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode AIK public key: %w", err)
	}

	return &ekPub, name, &aikPub, nil
}

func verifyAIKClaims(name *tpm2.Name, aikPub *tpm2.Public, ekPub *tpm2.Public) ([]byte, []byte, error) {
	// Verify the name matches the AIK
	nameHash, err := name.Digest.Alg.Hash()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get AIK name hash algorithm: %w", err)
	}
	p, err := aikPub.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode AIK public key: %w", err)
	}
	aikPubHash := nameHash.New()
	aikPubHash.Write(p)
	aikPubDigest := aikPubHash.Sum(nil)
	if !bytes.Equal(name.Digest.Value, aikPubDigest) {
		return nil, nil, fmt.Errorf("AIK name does not match AIK public key")
	} else {
		fmt.Println("\tAIK name matches AIK public key")
	}

	// Verify the AIK is a restricted signing key
	if (aikPub.Attributes&tpm2.FlagFixedTPM) != tpm2.FlagFixedTPM ||
		(aikPub.Attributes&tpm2.FlagRestricted) != tpm2.FlagRestricted ||
		(aikPub.Attributes&tpm2.FlagFixedParent) != tpm2.FlagFixedParent ||
		(aikPub.Attributes&tpm2.FlagSensitiveDataOrigin) != tpm2.FlagSensitiveDataOrigin {
		return nil, nil, fmt.Errorf("AIK public key is not a restricted signing key")
	} else {
		fmt.Println("\tAIK meets the required attributes and is a restricted signing key")
	}

	// generate credential
	out, credPlain, err := generateCredential(ekPub, name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate credential: %w", err)
	}

	return out, credPlain, nil
}

func generateCredential(ekPub *tpm2.Public, aikName *tpm2.Name) ([]byte, []byte, error) {
	tpmCredential := make([]byte, 32)
	if _, err := rand.Read(tpmCredential); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random credential: %w", err)
	}
	encKey, err := ekPub.Key()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get EK public key: %w", err)
	}
	symBlockSize := int(ekPub.RSAParameters.Symmetric.KeyBits) / 8
	credBlob, encryptedSecret, err := credactivation.Generate(aikName.Digest, encKey, symBlockSize, tpmCredential)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate credential: %w", err)
	} else {
		fmt.Printf("\tCredential generated : %x\n", tpmCredential)
	}

	credGen := vcom.TpmRequestGeneratedCred{
		Cred:     credBlob,
		Secret:   encryptedSecret,
		AikIndex: uint32(vcom.TpmAIKHandle),
	}
	out, err := proto.Marshal(&credGen)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal generated credential: %w", err)
	}

	return out, tpmCredential, nil
}

func verifyKeyCertification(data []byte, deviceID string) (crypto.PublicKey, error) {
	var tpmResp vcom.TpmResponseCertify
	err := proto.Unmarshal(data, &tpmResp)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response body: %w", err)
	}
	sigDecoded, err := tpm2.DecodeSignature(bytes.NewBuffer(tpmResp.Sig))
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %w", err)
	}

	// we rely on trusted AIK public key, not anything client provided
	pubKey := devices[deviceID].aik
	if pubKey == nil {
		return nil, fmt.Errorf("AIK public key not found for device %s", deviceID)
	}
	// Verify the attestation payload is signed by the device AIK
	if pubKey.RSAParameters != nil {
		if sigDecoded.RSA == nil || sigDecoded.RSA.Signature == nil {
			return nil, fmt.Errorf("signature is not RSA type")
		}
		attestHash, alg, err := getDigest(pubKey.RSAParameters.Sign.Hash, tpmResp.Attest)
		if err != nil {
			return nil, fmt.Errorf("failed to get digest: %w", err)
		}
		cryptoPub, err := pubKey.Key()
		if err != nil {
			return nil, fmt.Errorf("failed to get AIK public key: %w", err)
		}
		if err := rsa.VerifyPKCS1v15(cryptoPub.(*rsa.PublicKey), alg, attestHash[:], sigDecoded.RSA.Signature); err != nil {
			return nil, fmt.Errorf("failed to verify AIK signature: %w", err)
		} else {
			fmt.Println("\tKey certification payload signature verified successfully")
		}
	} else if pubKey.ECCParameters != nil {
		if sigDecoded.ECC == nil || sigDecoded.ECC.R == nil || sigDecoded.ECC.S == nil {
			return nil, fmt.Errorf("signature is not ECDSA type")
		}
		attestHash, _, err := getDigest(pubKey.ECCParameters.Sign.Hash, tpmResp.Attest)
		if err != nil {
			return nil, fmt.Errorf("failed to get digest: %w", err)
		}
		cryptoPub, err := pubKey.Key()
		if err != nil {
			return nil, fmt.Errorf("failed to get AIK public key: %w", err)
		}
		if !ecdsa.Verify(cryptoPub.(*ecdsa.PublicKey), attestHash[:], sigDecoded.ECC.R, sigDecoded.ECC.S) {
			return nil, fmt.Errorf("failed to verify AIK signature: %w", err)
		} else {
			fmt.Println("\tKey certification payload signature verified successfully")
		}
	} else {
		return nil, fmt.Errorf("unsupported AIK public key type: %T", pubKey)
	}

	// make sure the attestation data is valid
	attest, err := tpm2.DecodeAttestationData(tpmResp.Attest)
	if err != nil {
		return nil, fmt.Errorf("error decoding attestation data: %w", err)
	}
	if attest.Type != tpm2.TagAttestCertify {
		return nil, fmt.Errorf("unexpected attestation type: %v", attest.Type)
	}

	// decode the certified key public key and verify it matches the attestation data
	objectKeyPub, err := tpm2.DecodePublic(tpmResp.Public)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	objectName, err := objectKeyPub.Name()
	if err != nil {
		return nil, fmt.Errorf("failed to get object name: %w", err)
	}
	nameHash, err := objectName.Digest.Alg.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to get object name hash algorithm: %w", err)
	}
	p, err := objectKeyPub.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode object public key: %w", err)
	}
	objectNameHash := nameHash.New()
	objectNameHash.Write(p)
	objectNameDigest := objectNameHash.Sum(nil)
	if !bytes.Equal(attest.AttestedCertifyInfo.Name.Digest.Value, objectNameDigest) {
		return nil, fmt.Errorf("attestation name does not match object public key")
	} else {
		fmt.Println("\tAttestation name matches object public key")
	}

	// check certified key attributes, can be strict as you need,
	// e.g. FlagFixedTPM, FlagFixedParent, etc.
	if (objectKeyPub.Attributes&tpm2.FlagSign) != tpm2.FlagSign ||
		(objectKeyPub.Attributes&tpm2.FlagSensitiveDataOrigin) != tpm2.FlagSensitiveDataOrigin {
		return nil, fmt.Errorf("object public key is not a signing key")
	}

	// if everthing is fine, return the object public key
	objectPubKey, err := objectKeyPub.Key()
	if err != nil {
		return nil, fmt.Errorf("failed to get object public key: %w", err)
	}

	return objectPubKey, nil
}
