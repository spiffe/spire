# Running Multiple SPIRE Instances

Systemd (and other init systems) can run multiple instances of the same service using a template unit. To make it easier to target a particular instance of `spire-agent` or `spire-server`, the CLI supports environment-variable socket templates and a short `-i` flag.

Environment variables

- `SPIFFE_PUBLIC_SOCKET_TEMPLATE` — template for agent public/workload socket, use `%i` for the instance name.
- `SPIRE_AGENT_PRIVATE_SOCKET_TEMPLATE` — template for agent private/admin socket, use `%i` for the instance name.
- `SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE` — template for server private API socket, use `%i` for the instance name.

Defaulting and precedence

When one of the above env vars is set and the `-i` flag is omitted, the CLI will default the instance name to `main` and substitute it into the template. If you explicitly pass a `-socketPath`/`-socket_path` value, that value takes precedence over the environment template substitution.

Examples

```bash
export SPIFFE_PUBLIC_SOCKET_TEMPLATE=/var/run/spire/agent/sockets/%i/public/spiffe.sock
spire-agent -i a api watch           # uses instance "a"
spire-agent api watch                # uses instance "main" (because env var is set)

export SPIRE_SERVER_PRIVATE_SOCKET_TEMPLATE=/var/run/spire/server/sockets/%i/private/api.sock
spire-server agent list              # uses instance "main" if -i omitted
```

Notes

- The `-i` flag is a short alias for specifying the instance name on the CLI. When omitted and a relevant template env var is present, the CLI assumes instance mode and uses `main` unless `-i` is provided.
- This feature aims to simplify using systemd template units such as `spire-agent@.service` and `spire-server@.service`.
