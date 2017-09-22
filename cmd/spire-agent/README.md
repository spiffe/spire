# SPIRE Agent  
SPIRE Agent runs on every node and is responsible for requesting certificates from the spire server, attesting the validity of local workloads, and providing them SVIDs.

## Getting started
[Build SPIRE](../README.md)

_**Binary is Not Available Yet**_
Get the latest binary for [OS X](https://get.spiffe.io/osx/spire-agent), [Windows](https://get.spiffe.io/windows/spire-agent.exe), 
or [Linux](https://get.spiffe.io/linux/spire-agent) and place it in your `$PATH` similar to 
<code>
`wget -O /usr/local/bin/spire-agent https://get.spiffe.io/osx/spire-agent && chmod 755 /usr/local/bin/spire-agent`


SPIRE Agent configuration:
The following details the configurations for the spire agent.
The configurations can be set through .hcl file or passed as cmdline args, the cmdline configurations takes precedence.

 |Configuration          | Description                                                          |
 |-----------------------|----------------------------------------------------------------------|
 |BindAddress            |  The GRPC Address where the WORKLOAD API Service is set to listen    |
 |BindPort               |  The GRPC port where the WORKLOAD API Service is set to listen       |
 |DataDir                |  Directory where the runtime data will be stored                     |
 |LogFile                |  Sets the path to log file                                           |
 |LogLevel               |  Sets the logging level DEBUG|INFO|WARN|ERROR>                       |
 |PluginDir              |  Directory where the plugin configuration are stored                 |
 |ServerAddress          |  The GRPC Address where the SPIRE Server is running                  |
 |ServerPort             |  The GRPC port of the SPIRE Service                                  |
 |SocketPath             |  Sets the path where the socketfile will be generated                |
 |TrustBundlePath        |  Path to trusted CA Cert bundle                                      |
 |TrustDomain            |  SPIFFE trustDomain of the SPIRE Agent                               |


[default configuration file](./.conf/default_agent_config.hcl) 

```
BindAddress = "127.0.0.1"
BindPort = "8088"
DataDir = "."
LogLevel = "INFO"
PluginDir = "../../plugin/agent/.conf"
ServerAddress = "127.0.0.1"
ServerPort = "8081"
SocketPath ="../agent.sock"
TrustBundlePath = ".conf/carootcert.pem"
TrustDomain = "example.org"
```


SPIRE Agent commands:

 |Command                   | Action                                                           |
 |--------------------------|------------------------------------------------------------------|
 |`spire-agent run    `     |  Starts the SPIRE Agent                                          |
 |`spire-agent plugin-info` |  Lists all currently enabled SPIRE agent plugins' information    |
