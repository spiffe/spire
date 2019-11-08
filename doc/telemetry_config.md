## Telemetry configuration

If telemetry is desired, it may be configured by using a dedicated `telemetry { ... }` section. The following metrics collectors are currently supported:
- Prometheus
- Statsd
- DogStatsd
- M3

You may use all, some, or none. The following collectors support multiple declarations in the event that you want to send metrics to more than one collector:

- Statsd
- DogStatsd
- M3

Additionally, an in-memory telemetry sink will also be running. To disable this, set the `DisableInMem` flag to `true`.

### Telemetry configuration syntax

| Configuration          | Type          | Description  | Default |
| ----------------       | ------------- | ------------ | ------- |
| `DisableInMem`         | `bool`        | True to disable in-memory metrics. | `false` |
| `Prometheus`           | `Prometheus`  | Prometheus configuration           | |
| `DogStatsd`            | `[]DogStatsd` | List of DogStatsd configurations   | |
| `Statsd`               | `[]Statsd`    | List of Statsd configurations      | |
| `M3`                   | `[]M3`        | List of M3 configurations          | |

#### `Prometheus`

| Configuration    | Type          | Description |
| ---------------- | ------------- | ----------- |
| `host`           | `string`      | Prometheus server host |
| `port`           | `int`         | Prometheus server port |

#### `DogStatsd`
| Configuration    | Type          | Description |
| ---------------- | ------------- | ----------- |
| `address`        | `string`      | DogStatsd address |

#### `Statsd`
| Configuration    | Type          | Description |
| ---------------- | ------------- | ----------- |
| `address`        | `string`      | Statsd address |

#### `M3`
| Configuration    | Type          | Description |
| ---------------- | ------------- | ----------- |
| `address`        | `string`      | M3 address |
| `env`            | `string`      | M3 environment, e.g. `production`, `staging` |

Here is a sample configuration:

```hcl
telemetry {
        DisableInMem = true

        Prometheus {
                port = 9988
        }

        DogStatsd = [
            { address = "localhost:8125" },
        ]

        Statsd = [
            { address = "localhost:1337" },
            { address = "collector.example.org:8125" },
        ]

        M3 = [
            { address = "localhost:9000" env = "prod" },
        ]
}
```