pluginName = "upstream_ca" //needs to match the name used in plugin serverConfig

pluginCmd = "../../plugin/server/upstreamca-memory/upstreamca-memory"
pluginChecksum = ""
enabled = true
pluginType = "UpstreamCA"
pluginData {
  trust_domain = "example.org"
  ttl = "1h"
  key_file_path = "../../plugin/server/upstreamca-memory/pkg/_test_data/keys/private_key.pem"
  cert_file_path = "../../plugin/server/upstreamca-memory/pkg/_test_data/keys/cert.pem"
}
