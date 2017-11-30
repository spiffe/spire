
## Overview

This walkthrough will guide you through steps to install and configure SPIRE Server and SPIRE Agent for AWS IID based attestation.
Follow instructions [ here ] (https://github.com/spiffe/spiffe-example/blob/master/ec2/README.md) for a basic demo VPC and EC2 setup.

###Installing SPIRE Server/Agent:
Both SPIRE Server and SPIRE Agent binaries are bundled in the same distribution and can be found [ here ](https://github.com/spiffe/spire/releases/latest).
Download and extract the SPIRE distribution into ~/opt directory:

        mkdir ~/opt
        wget https://github.com/spiffe/spire/releases/download/<release_version>/spire-<release_version>-linux-x86_64-glibc.tar.gz
        tar -C ~/opt -xzf spire-<release_version>-linux-x86_64-glibc.tar.gz

###Installing aws IID attestor plugin on SPIRE server:
    1.  Download and extract go binary into /usr/local:

            wget https://redirector.gvt1.com/edgedl/go/go1.9.2.linux-amd64.tar.gz
            sudo tar -C /usr/local -xzf go1.9.2.linux-amd64.tar.gz

    2.  Create directories for GOPATH and GOBIN:

            mkdir $HOME/go
            mkdir $HOME/go/bin

    3. Set $GOPATH, $GOBIN and append $PATH environment variables:

            export PATH=$PATH:/usr/local/go/bin
            export GOPATH=$HOME/go
            export GOBIN=$HOME/go/bin
            export PATH=$PATH:$GOBIN

    4. Install git:

            sudo apt-get install git

    5. Install server IID attestor plugin using go install. The plugin binaries are installed in $GOBIN directory

            go install github.com/spiffe/aws-iid-attestor/server



###Configuring SPIRE Server plugin:
Remove join-token attestor config and create AWS IID attestor config:

        rm ~/opt/spire-<version>/conf/server/plugin/join-token.conf
        echo 'pluginName = "aws_iid_attestor"
pluginCmd = "~/go/bin/server"
pluginChecksum = ""
enabled = true
pluginType = "NodeAttestor"
pluginData {
    access_id = "<aws_access_key_id>"
    secret = "<aws_access_secret_key>"
    trust_domain = "example.org"
}' > ~/opt/spire-<version>/conf/server/plugin/aws-iid-attestor.conf

###Configure and start SPIRE server
Set `BindAddress= "<internal-ip>"` in ~/opt/spire-<version>/conf/server/server.conf to the internal/private IP of the server.

     cd ~/opt/spire-<version>/
     ./spire-server run



###Installing aws IID attestor plugin on SPIRE agent:
Follow the same steps 1 thru 4 from Installing aws IID attestor plugin on SPIRE server above.

5. Install agent IID attestor plugin using go install. The plugin binaries are installed in $GOBIN directory

         go install github.com/spiffe/aws-iid-attestor/agent


###Configuring SPIRE Agent plugin:
 Remove join-token attestor config and create AWS IID attestor config:

         rm ~/opt/spire-<version>/conf/agent/plugin/join-token.conf
         echo 'pluginName = "aws_iid_attestor"

pluginCmd = "~/go/bin/agent"
pluginChecksum = ""
enabled = true
pluginType = "NodeAttestor"
pluginData {
	trust_domain = "example.org"
}' > ~/opt/spire-<version>/conf/agent/plugin/aws-iid-attestor.conf


###Configure and start SPIRE agent
Set `ServerAddress= "<internal-ip>"` in ~/opt/spire-<version>/conf/agent/agent.conf to the internal/private IP of the server.

     cd ~/opt/spire-<version>/
     ./spire-server run

