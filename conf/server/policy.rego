package spire

default allow = false

allow {
    role_name == "registrar"

    # caller has the registrar role
    b = data.bindings[_]
    b.role = role_name
    b.user = input.caller

    # role has permission
    r = data.roles[_]
    r.name = role_name
    r.full_method = input.full_method

    # spiffe id to be registered is in correct namespace
    re_match(b.namespace, input.req.spiffe_id)
}
