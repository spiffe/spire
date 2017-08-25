pluginName = "join_token" //needs to match the name used in plugin serverConfig

pluginCmd = "plugin/agent/nodeattestor-jointoken/nodeattestor-jointoken"
pluginChecksum = ""
enabled = true
pluginType = "NodeAttestor" //needs to match the handshake
pluginData {
	join_token = "NOT-A-SECRET"
}
