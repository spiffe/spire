# Nested rotation Suite

## Description

This suite sets a very low TTLs and ensures that workload SVIDs are valid
across many SVID and SPIRE server CA rotation periods using nested servers.
Integration test is configured to work with 3 layers for server/agents:

                         root-server
                              |  
                         root-agent
                        /           \
         intermediateA-server   intermediateA-server      
                |                       |
         intermediateA-agent    intermediateA-agent    
                |                       |
           leafA-server            leafA-server  
                |                       |
           leafA-agent             leafA-agent             

Test steps:

- Fetch an X509-SVID from `intermediateA-agent` and validate it them on `intermediateB-agent`
- Fetch an X509-SVID from `leafA-agent` and validate it on `leafB-agent`
- Fetch a JWT-SVID from `intermediateA-agent` and validate it on `intermediateB-agent`
- Fetch a JWT-SVID from `leafA-agent` and validate it on `leafB-agent` 
