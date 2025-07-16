package common

const (
	ServerPort = ":9191"
)

type AcParamRes struct {
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
	Cred     []byte `json:"cred"`
}

type Csr struct {
	CertificateSigningRequest []byte `json:"csr"`
}
