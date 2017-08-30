pluginName = "ca" //needs to match the name used in plugin serverConfig

pluginCmd = "../../plugin/server/upstreamca-memory/upstreamca-memory"
pluginChecksum = ""
enabled = true
pluginType = "UpstreamCA"
pluginData {
  "trust_domain": "localhost",
  "key_size": 2048,
  "ttl": "1h",
  "key_file_path": "_test_data/key.pem"
  "cert_file_path": "_test_data/cert.pem"
  "cert_subject": {
    "Country": ["US"],
    "Organization": ["SPIFFE"],
    "Province": "California",
  }
}
