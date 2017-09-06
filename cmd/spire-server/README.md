# SPIRE Server  
SPIRE Server is responsible for validating and signing all CSRs in the SPIFFE trust domain. Validation is performed through platform-specific Attestation plugins, as well as policy enforcement backed by the SPIRE Server datastore.



## Getting started
[Build SPIRE](../README.md)

_**Binary is Not Available Yet**_
Get the latest binary for [OS X](https://get.spiffe.io/osx/controlplane), [Windows](https://get.spiffe.io/windows/controlplane.exe), 
or [Linux](https://get.spiffe.io/linux/controlplane) and place it in your `$PATH` similar to 
<code>
`wget -O /usr/local/bin/controlplane https://get.spiffe.io/osx/controlplane && chmod 755 /usr/local/bin/controlplane`

SPIRE-SERVER command line options

|Environment variable      | Description                                                |
|--------------------------|------------------------------------------------------------|
| `-conf`    |  Path to the spire-server config file                      |


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
 |logLevel               |  Sets the logging level DEBUG|INFO|WARN|ERROR>                      |
 |serverHTTPAddr         |  |
 |serverGRPCAddr         |  |


[default configuration file](/conf/server/server.hcl) 

```
logFile = "spire-server.log"//<PATH_TO_LOG_FILE>
logLevel = "DEBUG" //one of <DEBUG|INFO|WARN|ERROR> 
nodeAPIGRPCPort = "8086" 
registrationAPIGRPCPort ="8087"
nodeAPIHTTPPort = "8088"
registrationAPIHTTPPort ="8089"
trustDomain = "spiffe://"
```

