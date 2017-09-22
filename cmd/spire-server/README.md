# SPIRE Server  
SPIRE Server is responsible for validating and signing all CSRs in the SPIFFE trust domain. Validation is performed through platform-specific Attestation plugins, as well as policy enforcement backed by the SPIRE Server datastore.



## Getting started
[Build SPIRE](../README.md)

_**Binary is Not Available Yet**_
Get the latest binary for [OS X](https://get.spiffe.io/osx/spire-server), [Windows](https://get.spiffe.io/windows/spire-server.exe), 
or [Linux](https://get.spiffe.io/linux/spire-server) and place it in your `$PATH` similar to 
<code>
`wget -O /usr/local/bin/spire-server https://get.spiffe.io/osx/spire-server && chmod 755 /usr/local/bin/spire-server`


SPIRE Server configuration:
The following details the configurations for the spire server.
The configurations can be set through a .hcl file or passed as cmdline args, the cmdline configurations takes precedence.

 |Configuration          | Description                                                          |
 |-----------------------|----------------------------------------------------------------------|
 |BaseSpiffeIDTTL        |  TTL that defines how long the generated Base SVID is valid          |
 |BindAddress            |  The GRPC Address where the SPIRE Service is set to listen           |
 |BindPort               |  The GRPC port where the SPIRE Service is set to listen              |
 |BindHTTPPort           |  The HTTP port where the SPIRE Service is set to listen              |
 |LogFile                |  Sets the path to log file                                           |
 |LogLevel               |  Sets the logging level DEBUG|INFO|WARN|ERROR>                       |
 |PluginDir              |  Directory where the plugin configuration are stored                 |
 |TrustDomain            |  SPIFFE trustDomain of the SPIRE Agent                               |


[default configuration file](./.conf/default_server_config.hcl) 
```
BaseSpiffeIDTTL = 999999
BindAddress = "127.0.0.1"
BindPort = "8081"
BindHTTPPort = "8080"
LogLevel = "INFO"
PluginDir = "../../plugin/server/.conf"
TrustDomain = "example.org"
```

SPIRE Server commands:

 |Command                   | Action                                                           |
 |--------------------------|------------------------------------------------------------------|
 |`spire-server run`        |  Starts the SPIRE Server                                         |
 |`spire-server plugin-info`|  Lists all currently enabled SPIRE server plugins' information   |
