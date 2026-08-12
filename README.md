# Hopli

[![codecov](https://codecov.io/gh/hoprnet/hopli/branch/main/graph/badge.svg)](https://codecov.io/gh/hoprnet/hopli)

`hopli` is a CLI for common HOPR operator workflows:

- identity file creation and maintenance
- node funding (native and HOPR tokens)
- Safe + module setup and migration
- service registry entries and service types
- winning-probability contract operations

## Build

Prerequisites:

- Rust toolchain from `rust-toolchain.toml`
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

The `contracts-addresses.json` schema now includes a `service_registry` address for every network.
A `--contracts-root` or `HOPLI_CONTRACTS_ROOT` that points at a contracts checkout from before the
service registry therefore fails to load, with a deserialization error naming the missing field.
Point it at a current checkout, add the field (the zero address means "not deployed on this
network"), or drop the flag and use the embedded configuration.

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

Equivalent CLI flags are available (`--password-path`, `--new-password-path`, `--private-key`).

## Commands

Get top-level help:

```bash
hopli --help
```

Subcommands:

- `hopli identity` (`id`)
- `hopli faucet`
- `hopli safe-module` (`sm`)
- `hopli service` (`svc`)
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
  --private-key <PRIVATE_KEY>
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

Inspect a safe — owners/threshold, attached modules, linked nodes, and which known network the on-chain setup matches:

```bash
hopli safe-module check-safe \
  --provider-url https://gnosis-rpc.example/ \
  --safe-address 0xSafe...
```

No `--network` flag is required; check-safe reads the chain id from the RPC and tries to match the module's targets against every known network configuration.

Add an existing node identity to an already-deployed safe/module pair:

```bash
hopli safe-module add-node \
  --network anvil-localhost \
  --provider-url http://127.0.0.1:8545 \
  --safe-address 0xSafe... \
  --module-address 0xModule... \
  --identity-from-path ./identities/node.id \
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
  --private-key <PRIVATE_KEY>
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

### 5. Service registry

Entry writes go through the Safe bound to the node, because the registry only accepts that Safe as
the sender. `--private-key` is therefore the key of a Safe **owner**, not of the node, and
`--safe-address` is only needed when the binding cannot be read from the node-safe registry.
Registering and updating cost the service type's burn in wxHOPR, which the Safe must hold; `hopli`
puts an approval for exactly that burn in front of the call, in the same Safe transaction.

Register a node under a service type:

```bash
hopli service register \
  --network anvil-localhost \
  --provider-url http://127.0.0.1:8545 \
  --service-type gvpn:exit \
  --node-address 0xNode... \
  --metadata '{"endpoint":"https://exit.example"}' \
  --private-key <SAFE_OWNER_PRIVATE_KEY>
```

Replace the metadata of an entry, reading it from a file (the only way to pass bytes that are not
valid UTF-8):

```bash
hopli service update \
  --network anvil-localhost \
  --provider-url http://127.0.0.1:8545 \
  --service-type gvpn:exit \
  --node-address 0xNode... \
  --metadata-file ./metadata.json \
  --private-key <SAFE_OWNER_PRIVATE_KEY>
```

Remove an entry. This is free and never gated by the type's policy:

```bash
hopli service deregister \
  --network anvil-localhost \
  --provider-url http://127.0.0.1:8545 \
  --service-type gvpn:exit \
  --node-address 0xNode... \
  --private-key <SAFE_OWNER_PRIVATE_KEY>
```

Read a single entry, list the entries of a type, or list the registered types. Both list commands
read every page at one block, because the registry's list order changes as entries are removed:

```bash
hopli service get   --network anvil-localhost --provider-url http://127.0.0.1:8545 \
  --service-type gvpn:exit --node-address 0xNode...
hopli service list  --network anvil-localhost --provider-url http://127.0.0.1:8545 \
  --service-type gvpn:exit
hopli service types --network anvil-localhost --provider-url http://127.0.0.1:8545
```

Claim a service type. The caller pays the global registration fee and becomes the type owner:

```bash
hopli service register-type \
  --network anvil-localhost \
  --provider-url http://127.0.0.1:8545 \
  --service-type gvpn:exit \
  --registration-burn 1 \
  --update-burn 0.5 \
  --private-key <PRIVATE_KEY>
```

As the type owner, change the requirement contract or the burns:

```bash
hopli service set-requirement --service-type gvpn:exit --requirement 0xGate... ...
hopli service set-registration-burn --service-type gvpn:exit --amount 2 ...
hopli service set-update-burn --service-type gvpn:exit --amount 1 ...
```

Hand the type to another owner. Transfers are irreversible, so abandoning a type needs the
explicit `--abandon` flag rather than a zero `--new-owner`:

```bash
hopli service transfer-type-ownership --service-type gvpn:exit --new-owner 0xNewOwner... ...
hopli service transfer-type-ownership --service-type gvpn:exit --abandon ...
```

Manager and admin operations:

```bash
hopli service set-fee --amount 5 ...
hopli service set-node-safe-registry --node-safe-registry 0xNew... \
  --probe-node 0xNode... --expected-safe 0xSafe... ...
hopli service recover-tokens --token 0xToken... --recipient 0xTo... ...
```

Commands fail with a "contract not deployed" error on networks where `service_registry` is the
zero address.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features
cargo test
```

## License

GPL-3.0-only. See `LICENSE`.
