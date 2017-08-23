# Control Plane  
Control plane is responsible for validating and signing all CSRs in the SPIFFE trust domain. Validation is performed through platform-specific Attestation plugins, as well as policy enforcement backed by the Control Plane datastore.



## Getting started
[Build the SRI](../README.md#building-the-sri)

_**Binary is Not Available Yet**_
Get the latest binary for [OS X](https://get.spiffe.io/osx/controlplane), [Windows](https://get.spiffe.io/windows/controlplane.exe), 
or [Linux](https://get.spiffe.io/linux/controlplane) and place it in your `$PATH` similar to `wget -O /usr/local/bin/controlplane https://get.spiffe.io/osx/controlplane && chmod 755 /usr/local/bin/controlplane`. 


Set the env variable `CP_CONFIG_PATH` to point to the hcl config file. 
The config file should contain the following configuration:
````
 trustDomain = "" //The SPIFFE trustDomain of the Control Plane.
 nodeAPIGRPCPort = "8086" //The GRPC port where the NodeAPI Service is set to listen
 registrationAPIGRPCPort= "8086" //The GRPC port where the RegistrationAPI Service is set to listen
 nodeAPIHTTPPort = "8086" //The HTTP port where the NodeAPI Service is set to listen
 registrationAPIHTTPPort= "8086" //The HTTP port where the RegistrationAPI Service is set to listen
 logFile = "../log/controlplane.log" // Specifies path to log file
 logLevel = "DEBUG" //Specifies log level one of (DEBUG|INFO|WARN|ERROR)

````
To Start the Control Plane run the command:

`control_plane server`

To list all the active plugin-info run:

`control_plane plugin-info`

To stop the control plan run:

`control_plane stop`

