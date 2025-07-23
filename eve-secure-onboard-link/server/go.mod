module main

go 1.23.0

toolchain go1.23.11

replace github.com/lf-edge/eve/pkg/pillar => /home/shah/shah-dev/eve/pkg/pillar

replace github.com/lf-edge/eve-tools/eve-activate-cred/common => ../common

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/google/go-tpm v0.9.5
	github.com/lf-edge/eve-tools/eve-activate-cred/common v0.0.0-00010101000000-000000000000
	github.com/lf-edge/eve/pkg/pillar v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/eriknordmark/ipinfo v0.0.0-20230728132417-2d8f4da903d7 // indirect
	github.com/gabriel-vasile/mimetype v1.4.2 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.15.5 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-containerregistry v0.14.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/lf-edge/eve-api/go v0.0.0-20250626182814-c725ece2f435 // indirect
	github.com/lf-edge/eve/pkg/kube/cnirpc v0.0.0-20240315102754-0f6d1f182e0d // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/satori/go.uuid v1.2.1-0.20180404165556-75cca531ea76 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/api v0.29.3 // indirect
	k8s.io/apimachinery v0.29.3 // indirect
	k8s.io/klog/v2 v2.110.1 // indirect
	k8s.io/utils v0.0.0-20230726121419-3b25d923346b // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
)
