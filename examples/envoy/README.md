# Envoy SDS Example

## Build

```
$ ./build.sh
```

## Run

```
$ docker-compose up -d
```

## Start Web and Echo Servers

```
$ ./1-start-services.sh
```

## Start SPIRE Agents 

```
$ ./2-start-spire-agents.sh
```

## Create Workload Registration Entries

```
$ ./3-create-registration-entries.sh
```

## Interact with Web Server

Open up a browser to http://localhost:8080 to test out:

- Direct connection between Web and Echo servers
- mTLS connection between Web and Echo servers via Envoy
- TLS connection between Web and Echo servers via Envoy

**NOTE** It may take a 30 seconds or so for Envoy to reconnect to upstream
after the registration entries are created.
