# Authorization policy engine

The authorization decisions in SPIRE are determined by a policy engine which
bases its decision on a rego policy and databindings with Open Policy Agent
(OPA). 

This is a sample configuration of the policy.

```
server {
    policy_engine = {
        file_provider = {
            policy_path = "./conf/server/policy.rego"
            permissions_path = "./conf/server/permissions.json"
        }
    }
}
```

If the policy engine configuration is not set, it defaults to the default SPIRE
authorization policy, which has the following ruleset as expressed in
this [rego policy](/conf/server/policy.rego) and [permissions data
binding](/conf/server/permissions.json). These encode the following behavior:


| API                                                           | Authorized if (OR)      |
| ------------------------------------------------------------- | ----------------------- |
| /spire.api.server.svid.v1.SVID/MintX509SVID                   | local, admin            |
| /spire.api.server.svid.v1.SVID/MintJWTSVID                    | local, admin            |
| /spire.api.server.svid.v1.SVID/BatchNewX509SVID               | agent                   |
| /spire.api.server.svid.v1.SVID/NewJWTSVID                     | agent                   |
| /spire.api.server.svid.v1.SVID/NewDownstreamX509CA            | downstream              |
| /spire.api.server.bundle.v1.Bundle/GetBundle                  | any                     |
| /spire.api.server.bundle.v1.Bundle/AppendBundle               | local, admin            |
| /spire.api.server.bundle.v1.Bundle/PublishJWTAuthority        | downstream              |
| /spire.api.server.bundle.v1.Bundle/CountBundles               | local, admin            |
| /spire.api.server.bundle.v1.Bundle/ListFederatedBundles       | local, admin            |
| /spire.api.server.bundle.v1.Bundle/GetFederatedBundle         | local, admin, agent     |
| /spire.api.server.bundle.v1.Bundle/BatchCreateFederatedBundle | local, admin            |
| /spire.api.server.bundle.v1.Bundle/BatchUpdateFederatedBundle | local, admin            |
| /spire.api.server.bundle.v1.Bundle/BatchSetFederatedBundle    | local, admin            |
| /spire.api.server.bundle.v1.Bundle/BatchDeleteFederatedBundle | local, admin            |
| /spire.api.server.debug.v1.Debug/GetInfo                      | local                   |
| /spire.api.server.entry.v1.Entry/CountEntries                 | local, admin            |
| /spire.api.server.entry.v1.Entry/ListEntries                  | local, admin            |
| /spire.api.server.entry.v1.Entry/GetEntry                     | local, admin            |
| /spire.api.server.entry.v1.Entry/BatchCreateEntry             | local, admin            |
| /spire.api.server.entry.v1.Entry/BatchUpdateEntry             | local, admin            |
| /spire.api.server.entry.v1.Entry/BatchDeleteEntry             | local, admin            |
| /spire.api.server.entry.v1.Entry/GetAuthorizedEntries         | agent                   |
| /spire.api.server.agent.v1.Agent/CountAgents                  | local, admin            |
| /spire.api.server.agent.v1.Agent/ListAgents                   | local, admin            |
| /spire.api.server.agent.v1.Agent/GetAgent                     | local, admin            |
| /spire.api.server.agent.v1.Agent/DeleteAgent                  | local, admin            |
| /spire.api.server.agent.v1.Agent/BanAgent                     | local, admin            |
| /spire.api.server.agent.v1.Agent/AttestAgent                  | any                     |
| /spire.api.server.agent.v1.Agent/RenewAgent                   | agent                   |
| /spire.api.server.agent.v1.Agent/CreateJoinToken              | local, admin            |
| /grpc.health.v1.Health/Check                                  | local                   |
| /grpc.health.v1.Health/Watch                                  | local                   |

If multiple are specified in the authorized column, it is an disjunction of the
listed options. Where the options are:
- local: local caller through UNIX socket
- admin: caller has an admin SPIFFE ID
- downstream: caller has a downstream SPIFFE ID
- agent: caller is an agent

# Details of the policy engine

The policy engine is based on the [Open Policy Agent
(OPA)](https://www.openpolicyagent.org/). This is configured via two
compomnents, the rego policy, and the permissions (or databindings in terms of
OPA). 

- The rego policy is a rego policy file defining how to authorize the API calls.
- The permissions (or databindings) is a JSON blob that defines additional data
  that can be used in the rego policy.

In general there is an overlap in terms of which aspects of the policy can be
part of the rego and databindings. However, the general rule is "How it is done"
is part of the rego policy, and the "What does this apply to" is part of the
permissions/databindings file.

## Rego policy

The rego policy defines the evaluation of the input and data going into the
policy engine and how the result is defined. The main element of the policy is
defining the result which is what is used in the SPIRE server for the 
authorization decision.

This is defined by the result object:
```
result = {
  "allow": true/false,
  "allow_if_admin": true/false,
  "allow_if_local": true/false,
  "allow_if_downstream": true/false,
  "allow_if_agent": true/false,
}
```

The fields of the result are the following:
- `allow`: a boolean that if true, will authorize the call
- `allow_if_local`: a boolean that if true, will authorize the call only if the
  caller is a local UNIX socket call
- `allow_if_admin`:a boolean that if true, will authorize the call only if the
  caller is a SPIFFE ID with the Admin flag set
- `allow_if_downstream`: a boolean that if true, will authorize the call 
  only if the caller is a SPIFFE ID that is downstream

The inputs that are passed into the policy are:
- `input`: the input from the SPIRE server for the authorization call
- `data`: the databinding from the databinding file (permissions file)

| input field   | Description | Example |
| ------------- | ----------- | ------- |
| caller        | The SPIFFE ID (if available) of the caller | spiffe://example.org/workload1 |
| full_method   | The full method name of the API call | /spire.api.server.svid.v1.SVID/MintJWTSVID |
| req           | The API call request body (not available on client or bidirectional streaming RPC calls) | { "filter": {} } |

The request (`req`) is the marshalled JSON object from the [SPIRE
api sdk](https://github.com/spiffe/spire-api-sdk/). Note that it is not
available on client or bidirectional streaming RPC API calls.

## Permissions file (databinding)

The permissions file consists of a JSON blob which represents the data that is
used in the evaluation of the policy. This is generally free-form and can be
used in the rego policy in any way. Data in this JSON blob is pre-compiled into
the policy evaluation on the policy engine evaluation. Therefore, there it is
recommended to put as much data as possible in the databinding so that it can be
optimized by the policy engine.

These data objects can be accessed via the `data` field in the rego policy. For
example, if the data object is

```
{
    "apis": [
        { "full_method": "/spire.api.server.svid.v1.SVID/MintJWTSVID" },
        { "full_method": "/spire.api.server.bundle.v1.Bundle/GetFederatedBundle"},
        { "full_method": "/spire.api.server.svid.v1.SVID/BatchNewX509SVID"}
    ]
}
```

can be used in the policy in rego to say that if the input's full method is
equal to one of the objects defined in the `apis` fields' `full_method` 
sub-field, then `allow` should be set to true.
```
allow = true {
    input.full_method == data.apis[_].full_method
}
```

### Default configurations

Here are the default set of rego policy and permissions/databindings. These are
what is required to carry out the default authorization decisions as highlighted
at the start of this documentcisions as highlighted at the start of this
document.

#### Default policy.rego

The default rego policy is located [here](/pkg/server/policy/policy.rego).

#### Default permissions.json (databindings)

The default permissions.json is located [here](/pkg/server/policy/permissions.json).

The default permissions file contains a field called "apis".
This field has a list of APIs that is current being configured with the rego
policy.

The fields of each object are as follows:

| field             | Description | Example |
| ----------------- | ----------- | ------- |
| full_method       | The full method name of the API call | /spire.api.server.svid.v1.SVID/MintJWTSVID |
| allow_any         | if true, sets result.allow to true | |
| allow_local       | if true, sets result.allow_if_local to true | |
| allow_admin       | if true, sets result.allow_if_admin to true | |
| allow_downstream  | if true, sets result.allow_if_downstream to true | |
| allow_agent       | if true, sets result.allow_if_agent to true | |

# Extending the policy

This section contains examples of how the authorization policy can be extended.

## Example 1: Entry creation namespacing restrictions

In this example, we want to ensure that entries created are namespaced, so we
can create namespaces within the trust domain to determine the type of entires
that can be created by each client. This would be a scenario of having two
departments where one would not be able to create entries for the other.

This can be defined by creating some additional objects in the data binding:

```
{
    "entry_create_namespaces": [
        {
            "user": "spiffe://example.org/schedulers/finance",
            "path_namespace": "/finance"
        },
        {
            "user": "spiffe://example.org/schedulers/hr",
            "path_namespace": "/hr"
        }
    ]
}
```

The rego policy can then be updated to compare against the dataset of namespaces
of users and path prefixes to compare against the entry create input request.
```
check_entry_create_namespace {
    input.full_method == "/spire.api.server.entry.v1.Entry/BatchCreateEntry"

    # caller has the registrar role
    b = data.entry_create_namespaces[_]
    b.user == input.caller

    # spiffe id to be registered is in correct namespace
    re_match(b.path_namespace, input.req.entries[_].spiffe_id.path)
}

check_entry_create_namespace {
    input.full_method != "/spire.api.server.entry.v1.Entry/BatchCreateEntry"
}
```

The rego policy can then be updated to check for this, an example of an allow
clause would look like the following. Note that it is important to check to see
how this fits in with the other parts of the rego policy.

```
# Any allow check
allow = true {
    check_entry_create_admin_flag
}
```

## Example 2: Disallow admin flag in entry creation

In this second example, we want to restrict it so that we prevent any entries
created with an admin flag... This can be done by modifying the rego policy
allow clauses with the following check:

```
check_entry_create_admin_flag {
    input.full_method == "/spire.api.server.entry.v1.Entry/BatchCreateEntry"
    admin_entries := { entry | entry := input.req.entries[_]; entry.admin == true}
    count(admin_entries) == 0
}

check_entry_create_admin_flag {
    input.full_method != "/spire.api.server.entry.v1.Entry/BatchCreateEntry"
}
```
This sets `check_entry_create_admin_flag` to true if the full method is not for
entry creation or if it is, that there are no entires that contain the admin
flag.

The rego policy can then be updated to check for this, an example of an allow
clause would look like the following. Note that it is important to check to see
how this fits in with the other parts of the rego policy.
```
# Any allow check
allow = true {
    check_entry_create_admin_flag
}
```
