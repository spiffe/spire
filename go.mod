module github.com/spiffe/spire

go 1.12

replace github.com/spiffe/spire/proto/spire => ./proto/spire

require (
	bazil.org/fuse v0.0.0-20180421153158-65cc252bf669 // indirect
	github.com/Azure/azure-sdk-for-go v30.1.0+incompatible
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Azure/go-autorest/autorest v0.2.0
	github.com/Azure/go-autorest/autorest/azure/auth v0.1.0
	github.com/Azure/go-autorest/autorest/to v0.2.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.1.0 // indirect
	// version 1.14
	github.com/GoogleCloudPlatform/cloudsql-proxy v0.0.0-20190405210948-c70a36b8193f
	github.com/Microsoft/go-winio v0.4.12 // indirect
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/andres-erbsen/clock v0.0.0-20160526145045-9e14626cd129
	github.com/armon/go-metrics v0.0.0-20190430140413-ec5e00d3c878
	github.com/aws/aws-sdk-go v1.20.3
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v0.7.3-0.20190312165151-258edd715d46
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.3.3 // indirect
	github.com/envoyproxy/go-control-plane v0.8.0
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/go-sql-driver/mysql v1.4.1
	github.com/gofrs/uuid v3.2.0+incompatible
	github.com/gogo/googleapis v1.2.0
	github.com/gogo/protobuf v1.2.1
	github.com/golang/mock v1.3.1
	github.com/golang/protobuf v1.3.1
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/googleapis/gnostic v0.3.0 // indirect
	github.com/gorilla/mux v1.7.2 // indirect
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.0
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/go-plugin v1.0.1
	github.com/hashicorp/hcl v1.0.0
	github.com/imdario/mergo v0.3.7
	github.com/imkira/go-observer v1.0.3
	github.com/jinzhu/gorm v1.9.9
	github.com/mitchellh/cli v1.0.0
	github.com/morikuni/aec v0.0.0-20170113033406-39771216ff4c // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/prometheus/client_golang v1.0.0
	github.com/shirou/gopsutil v2.18.12+incompatible
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/pflag v1.0.3 // indirect
	github.com/spiffe/go-spiffe v0.0.0-20190518123159-37d000f27824
	github.com/spiffe/spire/proto/spire v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.3.0
	github.com/zeebo/errs v1.2.0
	go.uber.org/atomic v1.4.0
	go.uber.org/goleak v0.10.0
	golang.org/x/crypto v0.0.0-20190617133340-57b3e21c3d56
	golang.org/x/net v0.0.0-20190613194153-d28f0bde5980
	golang.org/x/sys v0.0.0-20190618155005-516e3c20635f
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	golang.org/x/tools v0.0.0-20190618163018-fdf1049a943a
	google.golang.org/api v0.6.0
	google.golang.org/grpc v1.21.1
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/square/go-jose.v2 v2.3.1
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gotest.tools v2.2.0+incompatible
	k8s.io/api v0.0.0-20190222213804-5cb15d344471
	k8s.io/apimachinery v0.0.0-20190221213512-86fb29eff628
	k8s.io/client-go v10.0.0+incompatible
	k8s.io/klog v0.2.0 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)
