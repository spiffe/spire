# Telemetry configuration

If telemetry is desired, it may be configured by using a dedicated `telemetry { ... }` section. The following metrics collectors are currently supported:

- Prometheus
- Statsd
- DogStatsd
- M3
- In-Memory

You may use all, some, or none of the collectors. The following collectors support multiple declarations in the event that you want to send metrics to more than one collector:

- Statsd
- DogStatsd
- M3

## Telemetry configuration syntax

| Configuration         | Type          | Description                                                   | Default                  |
|-----------------------|---------------|---------------------------------------------------------------|--------------------------|
| `InMem`               | `InMem`       | In-memory configuration                                       | running                  |
| `Prometheus`          | `Prometheus`  | Prometheus configuration                                      |                          |
| `DogStatsd`           | `[]DogStatsd` | List of DogStatsd configurations                              |                          |
| `Statsd`              | `[]Statsd`    | List of Statsd configurations                                 |                          |
| `M3`                  | `[]M3`        | List of M3 configurations                                     |                          |
| `MetricPrefix`        | `string`      | Prefix to add to all emitted metrics                          | spire_server/spire_agent |
| `EnableHostnameLabel` | `bool`        | Enable adding hostname to labels                              | true                     |
| `AllowedPrefixes`     | `[]string`    | A list of metric prefixes to allow, with '.' as the separator |                          |
| `AllowedPrefixes`     | `[]string`    | A list of metric prefixes to allow, with '.' as the separator |                          |
| `BlockedPrefixes`     | `[]string`    | A list of metric prefixes to block, with '.' as the separator |                          |
| `AllowedLabels`       | `[]string`    | A list of metric labels to allow, with '.' as the separator   |                          |
| `BlockedLabels`       | `[]string`    | A list of metric labels to block, with '.' as the separator   |                          |

### `Prometheus`

| Configuration | Type     | Description               |
|---------------|----------|---------------------------|
| `host`        | `string` | Prometheus exporter listen address |
| `port`        | `int`    | Prometheus exporter listen port    |

### `DogStatsd`

| Configuration | Type     | Description       |
|---------------|----------|-------------------|
| `address`     | `string` | DogStatsd address |

### `Statsd`

| Configuration | Type     | Description    |
|---------------|----------|----------------|
| `address`     | `string` | Statsd address |

### `M3`

| Configuration | Type     | Description                                  |
|---------------|----------|----------------------------------------------|
| `address`     | `string` | M3 address                                   |
| `env`         | `string` | M3 environment, e.g. `production`, `staging` |

Here is a sample configuration:

```hcl
telemetry {
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

        InMem {}

        AllowedLabels = []
        BlockedLabels = []
        AllowedPrefixes = []
        BlockedPrefixes = []
}
```

## Supported metrics

See the [Telemetry document](telemetry.md) for a list of all the supported metrics.
