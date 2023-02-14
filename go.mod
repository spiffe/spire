module github.com/spiffe/spire

go 1.19

require (
	cloud.google.com/go/iam v0.9.0
	cloud.google.com/go/kms v1.7.0
	cloud.google.com/go/secretmanager v1.9.0
	cloud.google.com/go/security v1.10.0
	cloud.google.com/go/storage v1.28.1
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.2.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.2.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork v1.1.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.0.0
	github.com/GoogleCloudPlatform/cloudsql-proxy v1.33.1
	github.com/Microsoft/go-winio v0.6.0
	github.com/andres-erbsen/clock v0.0.0-20160526145045-9e14626cd129
	github.com/armon/go-metrics v0.4.1
	github.com/aws/aws-sdk-go-v2 v1.17.3
	github.com/aws/aws-sdk-go-v2/config v1.18.2
	github.com/aws/aws-sdk-go-v2/credentials v1.13.2
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.19
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.19.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.77.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.18.16
	github.com/aws/aws-sdk-go-v2/service/kms v1.19.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.17.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.17.4
	github.com/blang/semver/v4 v4.0.0
	github.com/cenkalti/backoff/v3 v3.2.2
	github.com/docker/docker v20.10.22+incompatible
	github.com/envoyproxy/go-control-plane v0.10.2-0.20220325020618-49ff273808a1
	github.com/go-logr/logr v1.2.3
	github.com/go-sql-driver/mysql v1.7.0
	github.com/gofrs/uuid v4.3.1+incompatible
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.9
	github.com/google/go-tpm v0.3.3
	github.com/google/go-tpm-tools v0.3.10
	github.com/googleapis/gax-go/v2 v2.7.0
	github.com/gorilla/handlers v1.5.1
	github.com/hashicorp/go-hclog v1.4.0
	github.com/hashicorp/go-plugin v1.4.6
	github.com/hashicorp/hcl v1.0.1-0.20190430135223-99e2f22d1c94
	github.com/hashicorp/vault/api v1.8.2
	github.com/hashicorp/vault/sdk v0.6.2
	github.com/imdario/mergo v0.3.13
	github.com/imkira/go-observer v1.0.3
	github.com/jinzhu/gorm v1.9.16
	github.com/lib/pq v1.10.7
	github.com/mattn/go-sqlite3 v1.14.16
	github.com/mitchellh/cli v1.1.5
	github.com/open-policy-agent/opa v0.47.4
	github.com/prometheus/client_golang v1.14.0
	github.com/shirou/gopsutil/v3 v3.22.12
	github.com/sirupsen/logrus v1.9.0
	github.com/spiffe/go-spiffe/v2 v2.0.1-0.20220414143532-2ed460a8b9d3
	github.com/spiffe/spire-api-sdk v1.2.5-0.20221020001527-5895a0279944
	github.com/spiffe/spire-plugin-sdk v1.4.1-0.20220912221658-c42ab2d657f6
	github.com/stretchr/testify v1.8.1
	github.com/uber-go/tally/v4 v4.1.4
	github.com/zeebo/errs v1.3.0
	golang.org/x/crypto v0.4.0
	golang.org/x/net v0.7.0
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.5.0
	golang.org/x/time v0.3.0
	google.golang.org/api v0.105.0
	google.golang.org/genproto v0.0.0-20221206210731-b1a01be3a5f6
	google.golang.org/grpc v1.51.0
	google.golang.org/protobuf v1.28.1
	gopkg.in/square/go-jose.v2 v2.6.0
	k8s.io/api v0.26.0
	k8s.io/apimachinery v0.26.0
	k8s.io/client-go v0.26.0
	k8s.io/kube-aggregator v0.26.0
	k8s.io/utils v0.0.0-20221128185143-99ec85e7a448
	sigs.k8s.io/controller-runtime v0.14.1
)

require (
	cloud.google.com/go v0.107.0 // indirect
	cloud.google.com/go/compute v1.13.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.2 // indirect
	cloud.google.com/go/longrunning v0.3.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.0.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v0.7.0 // indirect
	github.com/DataDog/datadog-go v3.2.0+incompatible // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.1 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/agnivade/levenshtein v1.1.1 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.13.8 // indirect
	github.com/aws/smithy-go v1.13.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bgentry/speakeasy v0.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cncf/xds/go v0.0.0-20211130200136-a8f946100490 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/emicklei/go-restful/v3 v3.9.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v0.6.2 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-logr/zapr v1.2.3 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-sev-guest v0.4.1 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.6 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.1 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/go-uuid v1.0.2 // indirect
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/jhump/protoreflect v1.9.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2 // indirect
	github.com/mitchellh/copystructure v1.0.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oklog/run v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799 // indirect
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/pierrec/lz4 v2.5.2+incompatible // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/posener/complete v1.2.3 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tchap/go-patricia/v2 v2.3.1 // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/twmb/murmur3 v1.1.6 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.1.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/mod v0.6.0 // indirect
	golang.org/x/oauth2 v0.0.0-20221014153046-6fdb5e3db783 // indirect
	golang.org/x/term v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	golang.org/x/tools v0.2.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	gomodules.xyz/jsonpatch/v2 v2.2.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiextensions-apiserver v0.26.0 // indirect
	k8s.io/component-base v0.26.0 // indirect
	k8s.io/klog/v2 v2.80.1 // indirect
	k8s.io/kube-openapi v0.0.0-20221012153701-172d655c2280 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
