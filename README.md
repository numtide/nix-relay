# nix-relay

OIDC-authenticated Nix remote build relay. Allows GitHub Actions runners to use
remote Nix builders without SSH keys -- authentication uses GitHub's native OIDC
tokens instead.

## How it works

```
GHA runner                          Build farm
----------                          ----------
nix build                           nix-relay
  |                                   |
  v                                   v
ssh-ng store                        axum WebSocket server
  |                                   |
  v                                   v
nix-relay-client (bridge script)    validates OIDC JWT
  |                                   |
  v                                   v
websocat (stdin/stdout <-> WS)  <-> spawns nix-daemon --stdio
                                    bridges WS <-> daemon stdin/stdout
```

No changes to Nix are needed. The `ssh-ng://localhost?remote-program=...`
pattern with `fakeSSH` (triggered when host=`localhost`) directly execs the
specified program, bypassing SSH entirely.

## Server

### Configuration

Create a config file based on `config.example.toml`:

```toml
[server]
listen = "0.0.0.0:8080"
shutdown_grace_secs = 30

[auth]
issuer = "https://token.actions.githubusercontent.com"
audience = "api://nix-relay"
allowed_org = "myorg"
jwks_cache_ttl_secs = 3600

[daemon]
nix_daemon_path = "nix-daemon"
extra_args = ["--stdio"]
timeout_secs = 3600
max_connections = 32
```

All values can be overridden via environment variables:

| Variable | Config key |
|----------|-----------|
| `NIX_RELAY_LISTEN` | `server.listen` |
| `NIX_RELAY_SHUTDOWN_GRACE_SECS` | `server.shutdown_grace_secs` |
| `NIX_RELAY_ISSUER` | `auth.issuer` |
| `NIX_RELAY_AUDIENCE` | `auth.audience` |
| `NIX_RELAY_ALLOWED_ORG` | `auth.allowed_org` |
| `NIX_RELAY_JWKS_CACHE_TTL_SECS` | `auth.jwks_cache_ttl_secs` |
| `NIX_RELAY_DAEMON_PATH` | `daemon.nix_daemon_path` |
| `NIX_RELAY_TIMEOUT_SECS` | `daemon.timeout_secs` |
| `NIX_RELAY_MAX_CONNECTIONS` | `daemon.max_connections` |

### Running

```bash
# With config file
nix-relay config.toml

# With env vars
NIX_RELAY_ALLOWED_ORG=myorg NIX_RELAY_LISTEN=0.0.0.0:8080 nix-relay

# Config file path via env
NIX_RELAY_CONFIG=config.toml nix-relay
```

### Building

```bash
# With Nix
nix build

# With cargo (inside dev shell)
nix develop -c cargo build --release
```

## Client

The `client/nix-relay-client` script bridges Nix's stdin/stdout protocol to the
relay's WebSocket endpoint using `websocat`. It automatically detects the CI
environment and obtains an OIDC token.

Token resolution order:

1. `NIX_RELAY_TOKEN` env var (explicit, works with any provider)
2. GitHub Actions OIDC (detected via `ACTIONS_ID_TOKEN_REQUEST_URL`)
3. GitLab CI OIDC (detected via `GITLAB_OIDC_TOKEN` or `CI_JOB_JWT_V2`)
4. CircleCI OIDC (detected via `CIRCLE_OIDC_TOKEN_V2`)

Requirements: `curl`, `jq`, `websocat`

### GitHub Actions usage

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: cachix/install-nix-action@v30
      - run: |
          nix build \
            --builders 'ssh-ng://localhost?remote-program=nix-relay-client x86_64-linux' \
            --max-jobs 0 -L
        env:
          NIX_RELAY_URL: wss://build.example.com/relay
```

### GitLab CI usage

```yaml
build:
  image: nixos/nix
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: api://nix-relay
  variables:
    NIX_RELAY_URL: wss://build.example.com/relay
  script:
    - nix build
        --builders 'ssh-ng://localhost?remote-program=nix-relay-client x86_64-linux'
        --max-jobs 0 -L
```

### Manual usage

```bash
NIX_RELAY_URL=wss://build.example.com/relay \
NIX_RELAY_TOKEN="<jwt>" \
nix build \
  --builders 'ssh-ng://localhost?remote-program=./client/nix-relay-client x86_64-linux' \
  --max-jobs 0
```

## NixOS deployment

Add the flake as an input and import the NixOS module:

```nix
# flake.nix
{
  inputs.nix-relay.url = "git+https://git.ntd.one/anthropic/nix-relay";

  outputs = { nixpkgs, nix-relay, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        nix-relay.nixosModules.nix-relay
        {
          services.nix-relay = {
            enable = true;
            openFirewall = true;
            settings = {
              auth.allowed_org = "myorg";
            };
          };
        }
      ];
    };
  };
}
```

The `settings` attribute maps directly to the TOML config structure.
Sensible defaults are provided for all fields except `auth.allowed_org`,
which must be set. The `daemon.nix_daemon_path` defaults to the system's
`nix-daemon` from `config.nix.package`.

## Security

- JWT validation: signature, issuer, audience, expiration
- Organization check via `repository_owner` claim
- Bearer token passed in `Authorization` header (never in URL)
- TLS termination expected at reverse proxy (nginx/caddy)
- `nix-daemon --stdio` runs as `Trusted` by default; consider `--force-untrusted`
  with the `daemon-trust-override` experimental feature for production

## Development

```bash
nix develop
cargo test
cargo clippy -- -D warnings
cargo fmt --check
shellcheck client/nix-relay-client
```
