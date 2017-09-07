pluginName = "join_token" //needs to match the name used in plugin serverConfig

pluginCmd = "../../plugin/server/nodeattestor-jointoken/nodeattestor-jointoken"
pluginChecksum = ""
enabled = true
pluginType = "NodeAttestor" //needs to match the handshake
pluginData {
	join_tokens = {
		"NOT-A-SECRET"= 60,
		"THIS-IS-NOT-A-SECRET"= 180,
		"I-AM-NOT-A-SECRET"= 600
	}
	trust_domain = "localhost"
}
