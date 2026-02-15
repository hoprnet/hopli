# Hopli

`hopli` is a CLI for common HOPR operator workflows:

- identity file creation and maintenance
- node funding (native and HOPR tokens)
- Safe + module setup and migration
- winning-probability contract operations

## Build

Prerequisites:

- Rust toolchain from `rust-toolchain.toml` (currently `1.91`)
- access to an RPC endpoint for your target network

Build:

```bash
cargo build --release
```

Run:

```bash
cargo run -- --help
# or after build:
./target/release/hopli --help
```

## Configuration

### Network and contracts

On-chain commands require:

- `--network` (network key, for example `anvil-localhost`)
- `--provider-url` (RPC endpoint)

Optional:

- `--contracts-root` (directory containing `contracts-addresses.json`)
- If omitted, embedded contract config from `hopr-bindings` is used.

You can also set:

```bash
export HOPLI_CONTRACTS_ROOT=/path/to/contracts
```

### Identity input

Commands that operate on identities accept either:

- `--identity-directory` (optionally `--identity-prefix`)
- `--identity-from-path`

For `identity create`, use `--identity-directory`.

### Secrets and passwords

Supported environment variables:

- `IDENTITY_PASSWORD`
- `NEW_IDENTITY_PASSWORD`
- `PRIVATE_KEY`
- `MANAGER_PRIVATE_KEY`

Equivalent CLI flags are available (`--password-path`, `--new-password-path`, `--private-key`, `--manager-private-key`).

## Commands

Get top-level help:

```bash
hopli --help
```

Subcommands:

- `hopli identity` (`id`)
- `hopli faucet`
- `hopli safe-module` (`sm`)
- `hopli win-prob` (`wp`)

Use `--help` at any level for details, for example:

```bash
hopli safe-module create --help
```

## Common Workflows

### 1. Identity lifecycle

Create two identities:

```bash
hopli identity create \
  --identity-directory ./identities \
  --identity-prefix node_ \
  --number 2 \
  --password-path ./secrets/identity.pwd
```

Read addresses and peer IDs:

```bash
hopli identity read \
  --identity-directory ./identities \
  --identity-prefix node_ \
  --password-path ./secrets/identity.pwd
```

Rotate identity password:

```bash
hopli identity update \
  --identity-directory ./identities \
  --identity-prefix node_ \
  --password-path ./secrets/identity.pwd \
  --new-password-path ./secrets/identity-new.pwd
```

Convert peer ID/public key:

```bash
hopli identity convert-peer --peer-or-key 16Uiu2HAm...
```

### 2. Faucet funding

Fund identities and/or explicit addresses:

```bash
hopli faucet \
  --network anvil-localhost \
  --provider-url http://127.0.0.1:8545 \
  --identity-directory ./identities \
  --identity-prefix node_ \
  --password-path ./secrets/identity.pwd \
  --address 0x0123...,0x0456... \
  --hopr-amount 10 \
  --native-amount 0.1 \
  --private-key <PRIVATE_KEY>
```

### 3. Safe module create/move/migrate

Create safe + module setup:

```bash
hopli safe-module create \
  --network anvil-localhost \
  --provider-url http://127.0.0.1:8545 \
  --identity-directory ./identities \
  --password-path ./secrets/identity.pwd \
  --admin-address 0xAdmin1...,0xAdmin2... \
  --threshold 1 \
  --allowance 10 \
  --hopr-amount 10 \
  --native-amount 0.1 \
  --private-key <PRIVATE_KEY> \
  --manager-private-key <MANAGER_PRIVATE_KEY>
```

Migrate existing safe/module to another network config:

```bash
hopli safe-module migrate \
  --network anvil-localhost2 \
  --provider-url http://127.0.0.1:8545 \
  --safe-address 0xSafe... \
  --module-address 0xModule... \
  --identity-directory ./identities \
  --password-path ./secrets/identity.pwd \
  --private-key <PRIVATE_KEY>
```

Move nodes to a new safe/module pair:

```bash
hopli safe-module move \
  --network anvil-localhost \
  --provider-url http://127.0.0.1:8545 \
  --old-module-address 0xOldModule... \
  --new-safe-address 0xNewSafe... \
  --new-module-address 0xNewModule... \
  --node-address 0xNode1...,0xNode2... \
  --private-key <PRIVATE_KEY> \
  --manager-private-key <MANAGER_PRIVATE_KEY>
```

### 4. Winning probability

Set:

```bash
hopli win-prob set \
  --network anvil-localhost \
  --provider-url http://127.0.0.1:8545 \
  --winning-probability 0.5 \
  --private-key <PRIVATE_KEY>
```

Get:

```bash
hopli win-prob get \
  --network anvil-localhost \
  --provider-url http://127.0.0.1:8545
```

Convert from `f64` to contract encoding:

```bash
hopli win-prob convert --winning-probability 0.5
```

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
cargo test
```

## License

GPL-3.0-only. See `LICENSE`.
