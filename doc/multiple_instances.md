# Running Multiple SPIRE Instances

Systemd (and other init systems) can run multiple instances of the same service using a template unit. To make it easier to target a particular instance of `spire-agent` or `spire-server`, the CLI supports environment-variable socket templates and an -instance` flag.

Environment variables

- `SPIRE_AGENT_PUBLIC_SOCKET_TEMPLATE` — template for agent public/workload socket, use `%i` for the instance name.
- `SPIRE_AGENT_PRIVATE_SOCKET_TEMPLATE` — template for agent private/admin socket, use `%i` for the instance name.
- `SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE` — template for server private API socket, use `%i` for the instance name.

Defaulting and precedence

When one of the above env vars is set and the `-instance` flag is omitted, the CLI will ignore the variables entirely.

Examples

```bash
export SPIRE_AGENT_PUBLIC_SOCKET_TEMPLATE=/var/run/spire/agent/sockets/%i/public/spiffe.sock
spire-agent -instance a api watch           # uses instance "a"

export SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE=/var/run/spire/server/sockets/%i/private/api.sock
spire-server agent list -instance b         # uses instance "b"
```

Notes

- This feature aims to simplify using systemd template units such as `spire-agent@.service` and `spire-server@.service`.
