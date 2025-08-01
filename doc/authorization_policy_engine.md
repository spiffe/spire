# Authorization policy engine

**Warning**: Use of custom authorization policies is experimental and can
result in security degradation if not configured correctly. Please refer to
[this section](#extending-the-policy) for more details on extending the default
policy.

The authorization decisions in SPIRE are determined by a policy engine which
bases its decision on a rego policy and databindings with Open Policy Agent
(OPA).

This is a sample configuration of the policy.

```hcl
server {
    experimental {
        auth_opa_policy_engine {
            local {
                rego_path = "./conf/server/policy.rego"
                policy_data_path = "./conf/server/policy_data.json"
            }
        }
    }
}
```

If the policy engine configuration is not set, it defaults to the [default SPIRE
authorization policy](#default-configurations).

## Details of the policy engine

The policy engine is based on the [Open Policy Agent
(OPA)](https://www.openpolicyagent.org/). This is configured via two
components, the rego policy, and the policy data path (or databindings as
referred to in OPA).

- The rego policy is a rego policy file defining how to authorize the API calls.
- The policy data (or databindings) is a JSON blob that defines additional data
  that can be used in the rego policy.

In general there is an overlap in terms of which aspects of the policy can be
part of the rego and databindings. However, the general rule is "How it is done"
is part of the rego policy, and the "What does this apply to" is part of the
databindings file.

### Rego policy

The rego policy defines how input to the policy engine is evaluated to produce the result used by SPIRE server for authorization decisions.

This is defined by the result object:

```rego
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
- `allow_if_admin`: a boolean that if true, will authorize the call only if the
  caller is a SPIFFE ID with the Admin flag set
- `allow_if_downstream`: a boolean that if true, will authorize the call
  only if the caller is a SPIFFE ID that is downstream
- `allow_if_agent`: a boolean that is true, will authorize the call only if the
  caller is an agent.

The results are evaluated by the following semantics where `isX()` is an
evaluation of whether the caller has property `X`.

```rego
admit_request = 
    allow || (allow_if_local && isLocal()) || (allow_if_admin && isAdmin()) ||
    (allow_if_downstream && isDownstream()) || (allow_if_agent && isAgent())
```

The inputs that are passed into the policy are:

- `input`: the input from the SPIRE server for the authorization call
- `data`: the databinding from the policy data file

| input field | Description                                                                                                                      | Example                                    |
|-------------|----------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------|
| caller      | The SPIFFE ID (if available) of the caller                                                                                       | spiffe://example.org/workload1             |
| full_method | The full method name of the API call based on the [SPIRE API](https://github.com/spiffe/spire-api-sdk/tree/main/proto/spire/api) | /spire.api.server.svid.v1.SVID/MintJWTSVID |
| req         | The API call request body (not available on client or bidirectional streaming RPC calls)                                         | { "filter": {} }                           |

The request (`req`) is the marshalled JSON object from the [SPIRE
api sdk](https://github.com/spiffe/spire-api-sdk/). Note that it is not
available on client or bidirectional streaming RPC API calls.

### Policy data file (databinding)

The policy data file consists of a JSON blob which represents the data that is
used in the evaluation of the policy. This is generally free-form and can be
used in the rego policy in any way. Data in this JSON blob is pre-compiled into
the policy evaluation on the policy engine evaluation. Therefore, there it is
recommended to put as much data as possible in the databinding so that it can be
optimized by the policy engine.

These data objects can be accessed via the `data` field in the rego policy. For
example, a JSON data object may look like this:

```rego
{
    "apis": [
        { "full_method": "/spire.api.server.svid.v1.SVID/MintJWTSVID" },
        { "full_method": "/spire.api.server.bundle.v1.Bundle/GetFederatedBundle"},
        { "full_method": "/spire.api.server.svid.v1.SVID/BatchNewX509SVID"}
    ]
}
```

With the example data object above, we could construct a policy in rego to
check that if the input's full method is equal to one of the objects defined in
the `apis` fields' `full_method` sub-field, then `allow` should be set to true.

```rego
allow = true {
    input.full_method == data.apis[_].full_method
}
```

#### Default configurations

Here are the default rego policy and policy data values. These are
what is required to carry out the default SPIRE authorization decisions.

##### Default policy.rego

The default rego policy is located [here](/pkg/server/authpolicy/policy.rego).

##### Default policy\_data.json (databindings)

The default policy\_data.json is located
[here](/pkg/server/authpolicy/policy_data.json).

The default policy data file contains a field called "apis".
This field has a list of APIs that is current being configured with the rego
policy.

The fields of each object are as follows:

| field            | Description                                      | Example                                    |
|------------------|--------------------------------------------------|--------------------------------------------|
| full_method      | The full method name of the API call             | /spire.api.server.svid.v1.SVID/MintJWTSVID |
| allow_any        | if true, sets result.allow to true               |                                            |
| allow_local      | if true, sets result.allow_if_local to true      |                                            |
| allow_admin      | if true, sets result.allow_if_admin to true      |                                            |
| allow_downstream | if true, sets result.allow_if_downstream to true |                                            |
| allow_agent      | if true, sets result.allow_if_agent to true      |                                            |

## Extending the policy

This section contains examples of how the authorization policy can be extended.

### OPA Warning

It is important when implementing custom policies that one understands the
evaluation semantics and details of OPA rego. An example of subtleties of OPA
rego policy is the evaluation of a variable is taken as a logical OR of all
the clauses. Therefore, creating an additional rule that sets  `allow = false`
will not be an effective addition to the policy.

It is recommended to familiarize yourself with the
[OPA rego language](https://www.openpolicyagent.org/docs/latest/) before
implementing custom policies.

### Example 1a: Entry creation namespacing restrictions

In this example, we want to ensure that entries created are namespaced, so we
can create namespaces within the trust domain to determine the type of entries
that can be created by each client. This would be a scenario of having two
departments where one would not be able to create entries for the other.

Note that this example is specifically for calls through the TCP endpoint, where
the user corresponds to the SPIFFE ID in the x509 certificate presented during
invocation of the API.

This can be defined by creating some additional objects in the data binding:

```rego
{
    "entry_create_namespaces": [
        {
            "user": "spiffe://example.org/schedulers/finance",
            "path_namespace": "^/finance"
        },
        {
            "user": "spiffe://example.org/schedulers/hr",
            "path_namespace": "^/hr"
        }
    ]
}
```

The rego policy can then be updated to compare against the dataset of namespaces
of users and path prefixes to compare against the entry create input request.

```rego
check_entry_create_namespace {
    input.full_method == "/spire.api.server.entry.v1.Entry/BatchCreateEntry"

    # caller has the registrar role
    b = data.entry_create_namespaces[_]
    b.user == input.caller

    # spiffe id to be registered is in correct namespace
    re_match(b.path_namespace, input.req.entries[_].spiffe_id.path)
}
```

The rego policy can then be updated to check for this, an example of an allow
clause would look like the following. Note that it is important to check to see
how this fits in with the other parts of the rego policy.

```rego
# Any allow check
allow = true {
    check_entry_create_namespace
}
```

### Example 1b: Sub-department namespacing with exclusions

Building on top of the previous example, let's say we want to have sub
departments, having schedulers for a subset of paths within the trust domain.
This can be done by building on top of the previous example, with the addition
of an exclusion list.

In this example, we have two schedulers:

- `schedulers/finance` is able to create paths starting with  `/finance`
- `schedulers/finance/EMEA` is able to create paths starting with `/finance/EMEA`
- `schedulers/finance` should not be able to create paths starting with
  `/finance/EMEA`

To do this, we can use the same policy as the above, adding on an exclusion
list. We will use the following policy data:

```rego
{
    "entry_create_namespaces": [
        {
            "user": "spiffe://example.org/schedulers/finance",
            "path_namespace": "^/finance",
            "path_exclusions": [
                "^/finance/EMEA"
            ]
        },
        {
            "user": "spiffe://example.org/schedulers/finance/EMEA",
            "path_namespace": "^/finance/EMEA"
        }
    ]
}
```

We can then add a couple lines to check for the exclusion list:

```rego
check_entry_create_namespace {
    input.full_method == "/spire.api.server.entry.v1.Entry/BatchCreateEntry"

    # caller has the registrar role
    b = data.entry_create_namespaces[_]
    b.user == input.caller

    # spiffe id to be registered is in correct namespace
    re_match(b.path_namespace, input.req.entries[_].spiffe_id.path)

    # check if the spiffe id to be registered doesn't hit an exclusion
    exclusions := b.path_exclusions
    exclusion_matches := { entry | entry := input.req.entries[_]; re_match(exclusions[_], entry.spiffe_id.path)}
    count(exclusion_matches) == 0
}

check_entry_create_namespace {
    input.full_method != "/spire.api.server.entry.v1.Entry/BatchCreateEntry"
}
```

This will result in the desired boolean outcome to be stored in
`check_entry_create_namespace`.

### Example 2: Disallow admin flag in entry creation

In this second example, we want to restrict it so that we prevent any entries
created with an admin flag. This can be done by modifying the rego policy
allow clauses with the following check:

```rego
check_entry_create_admin_flag {
    input.full_method == "/spire.api.server.entry.v1.Entry/BatchCreateEntry"
    admin_entries := { entry | entry := input.req.entries[_]; entry.admin == true}
    count(admin_entries) == 0
}
```

This sets `check_entry_create_admin_flag` to true if the full method is not for
entry creation or if it is, that there are no entries that contain the admin
flag.

The rego policy can then be updated to check for this, an example of an allow
clause would look like the following. Note that it is important to check to see
how this fits in with the other parts of the rego policy.

```rego
# Any allow check
allow = true {
    check_entry_create_admin_flag
}
```

### Example 3a: Restrict calls from local UNIX socket

In this example, we want to restrict deletion of entries. For the first part of
this example, we will fully lock down the ability to delete entries.

This can be easily done by leveraging the set of default rules. In the default
policy data file, there are general allow restrictions for APIs. For example,
for the batch deletion of entries, here is the excerpt:

```rego
{
    "full_method": "/spire.api.server.entry.v1.Entry/BatchDeleteEntry",
    "allow_admin": true,
    "allow_local": true
}
```

If we want to disallow deletion of entries from the local or from admin users,
we can easily do this by deleting the `allow*` lines, resulting in:

```rego
{
    "full_method": "/spire.api.server.entry.v1.Entry/BatchDeleteEntry",
}
```

### Example 3b: Allow deletion from specific user

In this example, we want to now relax our previous restriction by allowing a
single SPIFFE ID to perform deletions via the TCP endpoint.

We can first define the data binding to provide the list of users able to delete
entries:

```rego
{
    "entry_delete_users": [
        "spiffe://example.org/finance/super-admin-deleter",
        "spiffe://example.org/hr/super-admin-deleter"
    ]
}
```

We can then define the following rego policy to check the calls to the entry
delete endpoint, and add checks that the caller SPIFFE ID is in the list of
users defined.

```rego
check_entry_delete_users {
    input.full_method == "/spire.api.server.entry.v1.Entry/BatchDeleteEntry"

    # caller has the registrar role
    input.caller == data.entry_delete_users[_]
}
```

The rego policy can then be updated to check for this, an example of an allow
clause would look like the following. Note that it is important to check to see
how this fits in with the other parts of the rego policy.

```rego
# Any allow check
allow = true {
    check_entry_delete_users
}
```
