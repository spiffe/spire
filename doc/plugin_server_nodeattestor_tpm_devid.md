# Server plugin: NodeAttestor "tpm_devid"

*Must be used in conjunction with the agent-side tpm_devid plugin*

The `tpm_devid` plugin attests nodes that own a TPM
and that have been provisioned with a DevID certificate through an out-of-band 
mechanism. 

The plugin issues two challenges to the agent:

1. A proof-of-possession challenge: This is required to verify the node is in 
possession of the private key that corresponds to the DevID certificate. 
Additionally, the server verifies that the DevID certificate  is rooted to
a trusted set of CAs.

2. A proof-of-residency challenge: This is required to prove that the DevID 
key pair was generated and resides in a TPM. Additionally, the server verifies 
that the TPM belongs to a trusted vendor by verifying that the endorsement 
certificate is rooted to a trusted set of CAs.


The SPIFFE ID produced by the plugin is based on the certificate fingerprint,
where the fingerprint is defined as the SHA1 hash of the ASN.1 DER encoding of
the identity certificate. 

The SPIFFE ID has the form:

```
spiffe://<trust domain>/spire/agent/tpm_devid/<fingerprint>
```


| Configuration 			| Description | Default                 |
| -------------------------	| ----------- | ----------------------- |
| `devid_bundle_path` 		| The path to the trusted CA bundle on disk for the DevID certificate. The file must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification. | |
| `endorsement_bundle_path` | The path to the trusted CA bundle on disk for the endorsement certificate. The file must contain one or more PEM blocks forming the set of trusted root CA's for chain-of-trust verification. | |


A sample configuration:

```
	NodeAttestor "tpm_devid" {
		plugin_data {
			devid_bundle_path = "/opt/spire/conf/server/devid-cacert.pem"
			endorsement_bundle_path = "/opt/spire/conf/server/endorsement-cacert.pem"
		}
	}
```

## Selectors

| Selector                  	| Example															| Description						|
| ---------------------------- 	| -----------------------------------------------------------------	| ---------------------------------	|
| Fingerprint					|`tpm_devid:fingerprint:9ba51e2643bea24e91d24bdec3a1aaf8e967b6e5`	| The certificate SHA1 fingerprint as a hex string.|
| Certificate serial number		|`tpm_devid:certificate:serialnumber:835861456985135479204994168`	| The certificate serial number.	| 
| Subject common name			|`tpm_devid:certificate:subject:cn:example.org`						| The subject's common name.		|
| Subject common name			|`tpm_devid:certificate:subject:cn:example.org`						| The subject's common name.		|
| Subject serial number			|`tpm_devid:certificate:subject:serialnumber:2b3fac84e7c7a70bac8`	| The subject's serial number. DevIDs certificates should populate this attribute with the device’s unique serial number.|
| Subject country 				|`tpm_devid:certificate:subject:c:US`								| The subject's country.			|
| Subject state or province		|`tpm_devid:certificate:subject:st:CA`								| The subject's state or province.	|
| Subject organization 			|`tpm_devid:certificate:subject:o:spiffe`							| The subject's organization.		|
| Subject organizational unit	|`tpm_devid:certificate:subject:ou:spire`							| The subject's organizational unit.|
| Issuer common name			|`tpm_devid:certificate:issuer:cn:example.org`						| The issuer's common name.			|
| Issuer common name			|`tpm_devid:certificate:issuer:cn:example.org`						| The issuer's common name.			|
| Issuer serial number			|`tpm_devid:certificate:issuer:serialnumber:2b3fac84e7c7a70bac8`	| The issuer's serial number.		|
| Issuer country 				|`tpm_devid:certificate:issuer:c:US`								| The issuer's country.				|
| Issuer state or province		|`tpm_devid:certificate:issuer:st:CA`								| The issuer's state or province.	|
| Issuer organization 			|`tpm_devid:certificate:issuer:o:spiffe`							| The issuer's organization.		|
| Issuer organizational unit	|`tpm_devid:certificate:issuer:ou:spire`							| The issuer's organizational unit.	|
