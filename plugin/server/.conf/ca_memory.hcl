pluginName = "ca" //needs to match the name used in plugin serverConfig

pluginCmd = "../../plugin/server/ca-memory/ca-memory"
pluginChecksum = ""
enabled = true
pluginType = "ControlPlaneCa"
pluginData {
  "trust_domain": "localhost",
  "key_size": 2048,
  "ttl": 3600000000000, // one hour
  "cert_subject": {
    "Country": ["US"],
    "Organization": ["SPIFFE"],
    "Province": "California",
  }
}
