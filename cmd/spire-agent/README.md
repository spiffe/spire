# SPIRE Agent  

SPIRE Agent runs on every node and is responsible for requesting certificates from the spire server,
attesting the validity of local workloads, and providing them SVIDs.

### SPIRE Agent configuration

The following details the configurations for the spire agent. The configurations can be set through
.conf file or passed as command line args, the command line configurations takes precedence.

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


[default configuration file](/conf/agent/default_agent_config.conf)

```
BindAddress = "127.0.0.1"
BindPort = "8088"
DataDir = "."
LogLevel = "INFO"
PluginDir = "conf/plugin/agent"
ServerAddress = "127.0.0.1"
ServerPort = "8081"
SocketPath ="/tmp/agent.sock"
TrustBundlePath = "conf/agent/carootcert.pem"
TrustDomain = "example.org"
```


### SPIRE Agent commands

 |Command                   | Action                                                           |
 |--------------------------|------------------------------------------------------------------|
 |`spire-agent run`         |  Starts the SPIRE Agent                                          |
