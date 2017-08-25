# SPIRE Server  
SPIRE Server is responsible for validating and signing all CSRs in the SPIFFE trust domain. Validation is performed through platform-specific Attestation plugins, as well as policy enforcement backed by the SPIRE Server datastore.



## Getting started
[Build the SRI](../README.md#building-the-sri)

_**Binary is Not Available Yet**_
Get the latest binary for [OS X](https://get.spiffe.io/osx/controlplane), [Windows](https://get.spiffe.io/windows/controlplane.exe), 
or [Linux](https://get.spiffe.io/linux/controlplane) and place it in your `$PATH` similar to 
<code>
`wget -O /usr/local/bin/controlplane https://get.spiffe.io/osx/controlplane && chmod 755 /usr/local/bin/controlplane`

Set `SPIRE_SERVER_CONFIG` enivironment variable to point to the server config file. 
Ser `SPIRE_PLUGIN_CONFIG_DIR` enivironment variable to point to the plugin configurations directory.


SPIRE-SERVER configuration:


 |Configuration          | Description                                                          |
 |-----------------------|----------------------------------------------------------------------|
 |trustDomain            |  SPIFFE trustDomain of the SPIRE Server                              |
 |nodeAPIGRPCPort        |  The GRPC port where the NodeAPI Service is set to listen            |
 |registrationAPIGRPCPort|  The GRPC port where the RegistrationAPI Service is set to listen    |
 |nodeAPIHTTPPort        |  The HTTP port where the NodeAPI Service is set to listen            |
 |registrationAPIHTTPPort|  The HTTP port where the RegistrationAPI Service is set to listen    |
 |logFile                |  Sets the path to log file                                           |
 |logLevel               |  Sets the logging level DEBUG|INFO|WARN|ERROR>                      |


[default configuration file](../.conf/default_server_config.hcl) 


SPIRE-SERVER commands:

 |Command                   | Action                                                           |
 |--------------------------|------------------------------------------------------------------|
 |`spire-server server`     |  Starts the SPIRE Server                                         |
 |`spire-server plugin-info`|  Lists all currently enabled SPIRE server plugins' information   |
 |`spire-server stop`       |  Stops the SPIRE Server                                          |
