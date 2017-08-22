# Control Plane  
Control plane is responsible for validating and signing all CSRs in the SPIFFE trust domain. Validation is performed through platform-specific Attestation plugins, as well as policy enforcement backed by the Control Plane datastore.



## Getting started (WIP)

Grab the latest binary for [OS X](https://get.spiffe.io/osx/controlplane), [Windows](https://get.spiffe.io/windows/controlplane.exe), 
or [Linux](https://get.spiffe.io/linux/controlplane) and place it somewhere in your `$PATH` with something like `wget -O /usr/local/bin/controlplane https://get.spiffe.io/osx/controlplane && chmod 755 /usr/local/bin/controlplane`. 
First lets see what our options are.

    controlplane --help

Control 