pluginName = //Should be unique and match the ServerConfigs{ Plugins: PluginMap } key.
pluginCmd = // Path to the plugin implementation binary
pluginChecksum = // Hash of the plugin's binary generated using shasum -a 256 <binaryfile>
enabled = // Plugin will be loaded if this is true
pluginType = // Should match the plugin types interface Name
pluginData {
// string passed to the plugins config method.
}
