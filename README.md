# Reverse-SOXY

A minimal, encrypted SOCKS5 tunnel for securely forwarding traffic between a **Proxy** and an **Agent** (optionally using a **Relay** server). Uses AES-CTR + HMAC to authenticate and encrypt the tunnel, plus SOCKS5 on the Proxy side.

## Features

- **Proxy mode**: exposes a local SOCKS5 endpoint and listens for agent connections on a tunnel port.
- **Agent mode**: dials into the proxy over a secure, authenticated, AES-CTR tunnel.
- **Relay mode**: starts a relay server. Useful when the Proxy cannot expose a public port.
- **Proxy via Relay**: registers a Proxy behind NAT with the Relay, then starts the SOCKS5 front-end.
- **Agent via Relay**: dials into the Relay on behalf of the Agent, establishing a secure tunnel via the relay.
- Graceful shutdown (SIGINT/SIGTERM) and automatic reconnect/backoff.
- Simple YAML configuration override.

## Releases

Packages can be downloaded from the [releases](https://github.com/lonepie/reverse-soxy/releases) page.

## Docker

For instructions on building and running the application in Docker, see [README.docker.md](README.docker.md).

## Building

To build the project, you can use either Go or Make. Follow the instructions below:

### Using Go

```bash
# Clone the repository
git clone https://github.com/lonepie/reverse-soxy.git
cd reverse-soxy

# Go 1.20+
go build -o build/reverse-soxy ./cmd/reverse-soxy
```

### Using Make

```bash
# Clone the repository
git clone https://github.com/lonepie/reverse-soxy.git
cd reverse-soxy

# Build using Make
make
```

## Usage

### Proxy mode

Starts the SOCKS5 proxy front-end and listens for agent connections.

```bash
./reverse-soxy \
  --proxy-listen-addr 127.0.0.1:1080 \
  --tunnel-listen-port 9000 \
  --secret mySharedSecret
```

### Agent mode

Dials into the proxy over the encrypted tunnel.

```bash
./reverse-soxy \
  --tunnel-addr proxy.host:9000 \
  --secret mySharedSecret
```

### Relay mode

Starts a public relay server on a VPS. Useful when the Proxy cannot expose a public port.

```bash
./reverse-soxy \
  --mode relay \
  --relay-listen-port 9000 \
  --secret mySharedSecret
```

### Proxy via Relay

Registers a Proxy behind NAT with the Relay, then starts the SOCKS5 front-end.

```bash
./reverse-soxy \
  --mode proxy \
  --register \
  --relay-addr vps.example.com:9000 \
  --secret mySharedSecret
```

### Agent via Relay

Dials into the Relay on behalf of the Agent, establishing a secure tunnel via the VPS.

```bash
./reverse-soxy \
  --mode agent \
  --relay-addr vps.example.com:9000 \
  --secret mySharedSecret
```

## Connection Flows

### Direct Proxy <--> Agent

```mermaid
flowchart LR
    Client([Client App]) <--> Proxy([Proxy]) <--> Agent([Agent]) <--> Remote([Remote Host])
    Client -- "SOCKS5" --> Proxy
    Proxy -- "AES-CTR + HMAC" --> Agent
    Agent -- "TCP" --> Remote
```

### Via Relay

```mermaid
flowchart LR
    Client([Client App]) <--> Proxy([Proxy]) <--> Relay([Relay Server]) <--> Agent([Agent]) <--> Remote([Remote Host])
    Client -- "SOCKS5" --> Proxy
    Proxy -- "AES-CTR + HMAC" --> Relay
    Relay -- "AES-CTR + HMAC" --> Agent
    Agent -- "TCP" --> Remote
```

### Common flags

| Flag                  | Description                                                   |
|-----------------------|---------------------------------------------------------------|
| `--proxy-listen-addr` | Local address for SOCKS5 listener (default `127.0.0.1:1080`). |
| `--tunnel-listen-port`| Port to listen on for agents in proxy mode (default `9000`).  |
| `--tunnel-addr`       | Address to dial in agent mode (e.g. `host:port`).            |
| `--secret`            | Shared secret for HMAC/AES handshake (required).             |
| `--config`            | Path to YAML config file (optional).                         |
| `--debug`             | Enable debug-level logging.                                   |
| `--mode`              | Component mode: `proxy` (default), `agent`, or `relay`.       |
| `--relay-listen-port` | Port for proxy registrations and agent tunnels (relay mode).  |
| `--relay-addr`        | Relay server address for registration or agent dialing.       |
| `--register`          | In proxy mode, register the proxy with the relay.            |

## Configuration file (YAML)

```yaml
socks_listen_addr: 127.0.0.1:1080
# Equivalent to --proxy-listen-addr

tunnel_listen_port: 9000
# Equivalent to --tunnel-listen-port

tunnel_addr: proxy.host:9000
# Used in agent mode if set
```

## Security

- Uses AES-CTR with separate IVs for encrypt/decrypt and fresh IVs per connection.
- Performs an HMAC-SHA256 challenge/response handshake to authenticate peers and block replay attempts.
- High-entropy ciphertext; no plaintext leaks over the tunnel.
- Provide a high-entropy shared secret (at least 32 random bytes) and rotate it periodically.
- Relay registrations and agent attachments complete a pre-tunnel HMAC challenge so only trusted peers can bind to the relay.

## License

MIT License. See [LICENSE](LICENSE).
