# YAML Configuration Suite

## Description

This suite verifies that SPIRE Server and SPIRE Agent can be configured with
YAML configuration files:

- The server starts from a YAML configuration that uses the YAML forms of
  `database_type` and the federation bundle endpoint profile, and a YAML
  `plugin_data_file`
- An agent configured in YAML, with an anchor shared by two plugins, attests
  with a join token and fetches an X509-SVID
- Both refuse a YAML configuration that does not set `experimental.enable_yaml_config`
