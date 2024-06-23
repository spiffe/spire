# SPIRE Agent ID Migration Guide

This guide outlines the steps required to update your SPIRE agent IDs to conform to the enforced ID shape.

<!-- todo(matteus): mention first version which enforced the shape -->

Before vX.Y.Z, SPIRE did not enforce a specific format for agent IDs. However, for improved debuggability, auditability, and security, it was recommended to follow this format:

```
spiffe://<trustdomain>/spire/agent/<nodeattestor>/<unique per-agent suffix>
Example:
```

Now SPIRE enforces that agent IDs reside in the agent namespace (`spiffe://<trustdomain>/spire/agent`), like in the following concrete example:

```
spiffe://example.org/spire/agent/join_token/21B6D625-CCF3-49E1-8E7C-812B3F55B3CB
```


<!-- ------------------------------------------------------------------- -->

## Why this Update?

Following the recommended format provides several benefits:

1. Easier Debugging and Auditing: The format clearly identifies the node attestor that generated the ID and aids in log analysis.

2. Reduced Misconfiguration Risk: Validating requested IDs against the format helps prevent accidental workload assignment of agent IDs.

3. Improved Clarity: The format provides a clear picture of the ID's origin at a glance.


## Impact

SPIRE enforces the recommended format for agent IDs starting with version vX.Y.Z. 

<!-- todo(matteus): mention first version which enforced the shape -->
<!-- todo(matteus): is the following plan still valid?

From Andrew:
-------------------
Warn on the undesired ID usage (this is already merged and will ship in 1.2.1. Since this was not in place for 1.2.0, we cannot change it through 1.3.x)

-> Beginning with 1.4.0 (THIS HAS CHANGED, RIGHT?), disallow newly attested nodes which do not conform to the expected ID shape. Existing agents will still continue to operate successfully. As part of this change, we will also introduce a warning for existing IDs that are non-conformant.


-> In 1.5.0 (or a later minor version), we will start denying agent authorization for agents with non-conformant IDs.
-------------------
-->


### Starting at v1.2.1


- SPIRE **warns** about the registration of SPIRE agents with the not recommended agent ID shape.
- SPIRE continues to allow the registration of IDs of any shape.

### From v1.4.0 to v1.4.99

- SPIRE will **disallow newly attested nodes** which do not conform to the expected ID shape.
- SPIRE **will allow existing agents** to continue to operate with non-conformant ID shapes.


### After v1.5.0

- SPIRE will deny agent authorization for agents with non-conformant IDs.


## Migration Steps

### Identify Non-Conforming Agent IDs:

Use one or combine the following options to identify agent IDs that don't follow the recommended format:

- SPIRE CLI ([spire-server entry update](https://github.com/spiffe/spire/blob/main/doc/spire_server.md#spire-server-entry-update))
- SPIRE server logs
- [Agent configuration](https://github.com/spiffe/spire/tree/main/doc)

<!-- todo(matteus): which are other methods that may be available? -->

### Update Node Attestor Configuration (if applicable):

If your node attestor generates non-conforming IDs, update its configuration to adhere to the recommended format.

Refer to your node attestor's documentation for specific configuration instructions.


### Re-Register Agents (if necessary):

If the non-conforming IDs are already registered with the SPIRE server, you might need to re-register the agents with conforming IDs.
This step depends on your specific deployment and the node attestor's behavior.


<!-- todo(matteus): here I also thought of `spire-server entry update` command... -->

### Upgrade SPIRE (Optional):

While not strictly necessary for migration, upgrading your SPIRE server to version vX.Y.X benefits from the enforced agent ID format.

For more information about how to upgrade SPIRE, refer to the [Managing Upgrades/Downgrades](https://github.com/spiffe/spire/blob/main/doc/upgrading.md) documentation.
