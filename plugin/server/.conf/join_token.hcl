pluginName = "join_token" //needs to match the name used in plugin serverConfig

pluginCmd = "../node_attestor/join_token/join_token"
pluginChecksum = "7d4570a061d4d2a556d26a11c6cb7641e5ce1523a2a47ea4c73b2ede973afa0a"
enabled = true
pluginType = "NodeAttestor" //needs to match the handshake
pluginData {
	join_tokens = {
		"NOT-A-SECRET": 60,
		"THIS-IS-NOT-A-SECRET": 180,
		"I-AM-NOT-A-SECRET": 600
	}
}
