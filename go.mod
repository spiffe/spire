module github.com/spiffe/spire

go 1.16

require (
	cloud.google.com/go v0.80.0
	cloud.google.com/go/storage v1.10.0
	github.com/Azure/azure-sdk-for-go v44.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.0
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.0
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.0 // indirect
	// version 1.14
	github.com/GoogleCloudPlatform/cloudsql-proxy v0.0.0-20190405210948-c70a36b8193f
	github.com/InVisionApp/go-health v2.1.0+incompatible
	github.com/InVisionApp/go-logger v1.0.1
	github.com/Microsoft/go-winio v0.4.14 // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/andres-erbsen/clock v0.0.0-20160526145045-9e14626cd129
	github.com/armon/go-metrics v0.3.2
	github.com/aws/aws-sdk-go v1.28.9
	github.com/aws/aws-sdk-go-v2 v1.2.0
	github.com/aws/aws-sdk-go-v2/config v1.1.1
	github.com/aws/aws-sdk-go-v2/credentials v1.1.1
	github.com/aws/aws-sdk-go-v2/service/kms v1.1.1
	github.com/blang/semver v3.5.1+incompatible
	github.com/cenkalti/backoff/v3 v3.0.0
	github.com/containerd/containerd v1.3.2 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.4.2-0.20191008235115-448db5a783a0
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/envoyproxy/go-control-plane v0.9.9-0.20201210154907-fd9021fe5dad
	github.com/go-logr/logr v0.1.0
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/go-sql-driver/mysql v1.5.0
	github.com/gofrs/uuid v3.2.0+incompatible
	github.com/golang/mock v1.5.0
	github.com/golang/protobuf v1.5.1
	github.com/google/go-cmp v0.5.5
	github.com/google/go-tpm v0.3.2
	github.com/google/go-tpm-tools v0.2.1
	github.com/hashicorp/go-hclog v0.15.0
	github.com/hashicorp/go-plugin v1.4.0
	github.com/hashicorp/golang-lru v0.5.1
	github.com/hashicorp/hcl v1.0.1-0.20190430135223-99e2f22d1c94
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/imdario/mergo v0.3.8
	github.com/imkira/go-observer v1.0.3
	github.com/jhump/protoreflect v1.6.1 // indirect
	github.com/jinzhu/gorm v1.9.9
	github.com/lib/pq v1.8.0
	github.com/mattn/go-sqlite3 v1.14.6
	github.com/mitchellh/cli v1.0.0
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/prometheus/client_golang v1.7.1
	github.com/shirou/gopsutil v2.18.12+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.6
	github.com/spiffe/spire-api-sdk v1.0.0
	github.com/spiffe/spire-plugin-sdk v1.0.0
	github.com/stretchr/testify v1.7.0
	github.com/uber-go/tally v3.3.12+incompatible
	github.com/zeebo/errs v1.2.2
	go.uber.org/atomic v1.5.0
	go.uber.org/goleak v0.10.0
	go.uber.org/multierr v1.4.0 // indirect
	go.uber.org/zap v1.13.0 // indirect
	golang.org/x/crypto v0.0.0-20210314154223-e6e6c4f2bb5b
	golang.org/x/net v0.0.0-20210316092652-d523dce5a7f4
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210320140829-1e4c9ba3b0c4
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	google.golang.org/api v0.42.0
	google.golang.org/genproto v0.0.0-20210323160006-e668133fea6a
	google.golang.org/grpc v1.36.1
	google.golang.org/protobuf v1.26.0
	gopkg.in/square/go-jose.v2 v2.4.1
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gotest.tools v2.2.0+incompatible
	k8s.io/api v0.18.2
	k8s.io/apimachinery v0.18.2
	k8s.io/client-go v0.18.2
	k8s.io/kube-aggregator v0.18.2
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
	sigs.k8s.io/controller-runtime v0.6.0
)
