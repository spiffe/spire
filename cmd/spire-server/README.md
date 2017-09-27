# SPIRE Server  

SPIRE Server is responsible for validating and signing all CSRs in the SPIFFE trust domain.
Validation is performed through platform-specific Attestation plugins, as well as policy enforcement
backed by the SPIRE Server datastore.

### SPIRE Server configuration

The following details the configurations for the spire server. The configurations can be set through
a .conf file or passed as command line args, the command line configurations takes precedence.

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

[default configuration file](/conf/server/default_server_config.conf)

```
BaseSpiffeIDTTL = 999999
BindAddress = "127.0.0.1"
BindPort = "8081"
BindHTTPPort = "8080"
LogLevel = "INFO"
PluginDir = "conf/plugin/server/"
TrustDomain = "example.org"
```

### SPIRE Server commands

 |Command                   | Action                                                           |
 |--------------------------|------------------------------------------------------------------|
 |`spire-server run`        |  Starts the SPIRE Server                                         |
