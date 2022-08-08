/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

// KeyUsage specifies valid usage contexts for keys.
// See: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
//
//	https://tools.ietf.org/html/rfc5280#section-4.2.1.12
//
// Valid KeyUsage values are as follows:
// "signing",
// "digital signature",
// "content commitment",
// "key encipherment",
// "key agreement",
// "data encipherment",
// "cert sign",
// "crl sign",
// "encipher only",
// "decipher only",
// "any",
// "server auth",
// "client auth",
// "code signing",
// "email protection",
// "s/mime",
// "ipsec end system",
// "ipsec tunnel",
// "ipsec user",
// "timestamping",
// "ocsp signing",
// "microsoft sgc",
// "netscape sgc"
type KeyUsage string

const (
	UsageSigning           KeyUsage = "signing"
	UsageDigitalSignature  KeyUsage = "digital signature"
	UsageContentCommitment KeyUsage = "content commitment"
	UsageKeyEncipherment   KeyUsage = "key encipherment"
	UsageKeyAgreement      KeyUsage = "key agreement"
	UsageDataEncipherment  KeyUsage = "data encipherment"
	UsageCertSign          KeyUsage = "cert sign"
	UsageCRLSign           KeyUsage = "crl sign"
	UsageEncipherOnly      KeyUsage = "encipher only"
	UsageDecipherOnly      KeyUsage = "decipher only"
	UsageAny               KeyUsage = "any"
	UsageServerAuth        KeyUsage = "server auth"
	UsageClientAuth        KeyUsage = "client auth"
	UsageCodeSigning       KeyUsage = "code signing"
	UsageEmailProtection   KeyUsage = "email protection"
	UsageSMIME             KeyUsage = "s/mime"
	UsageIPsecEndSystem    KeyUsage = "ipsec end system"
	UsageIPsecTunnel       KeyUsage = "ipsec tunnel"
	UsageIPsecUser         KeyUsage = "ipsec user"
	UsageTimestamping      KeyUsage = "timestamping"
	UsageOCSPSigning       KeyUsage = "ocsp signing"
	UsageMicrosoftSGC      KeyUsage = "microsoft sgc"
	UsageNetscapeSGC       KeyUsage = "netscape sgc"
)
