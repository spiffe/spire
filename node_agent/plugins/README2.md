#How to create a Plugin
Each of the directories at this level represent a plugin type. 
1. Create a sub-directory under the plugin type directory for each plugin you want to create.
2. Create a <pluginName>.hcl config file in a \<config> directory specified by the env variable:
        
        PLUGIN_CONFIG_PATH
3. The handshake magic key and value are dynamically generated and hence should match the Plugins Interface Name.
        
        WorkloadAttestor defined in node-agent/plugins/workload_attestor/interface.go
4. The PluginName must match the in both the .hcl config file and the ServerConfig's PluginMap key.
        
        plugin.Serve(&plugin.ServeConfig{
            		HandshakeConfig: workloadattestor.Handshake,
            		Plugins: map[string]plugin.Plugin{
            			"<PLUGINNAME>": workloadattestor.WorkloadAttestorPlugin{WorkloadAttestorImpl: &SecretFilePlugin{}},
            		},
            		GRPCServer: plugin.DefaultGRPCServer,
            	})
            
