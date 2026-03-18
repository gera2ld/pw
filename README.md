# pw - Minimalist CLI Secret Manager

pw is a local-first, cross-platform, and Git-friendly secret manager.

## Features

- **Metadata privacy**: Randomized filenames (nanoids) prevent metadata leakage in cloud backups
- **Per-entry Git granularity**: Each secret is a standalone encrypted file
- **Variable expansion**: Supports `$xxx` substitution within secrets
- **Zero-leakage**: Plaintext never hits the disk (piped through memory)

## Prerequisites

- **[age](https://github.com/FiloSottile/age)**: Encryption tool

## Quick Start

```bash
# Initialize recipients (add your age public key)
pw rcp add age1...

# Create a secret
pw edit my-api
# Opens editor with default __id: my-api
# Add your secrets:
# __id: my-api
# _base_url: https://api.example.com
# API_KEY: secret123
# ENDPOINT: $_base_url/v1

# Run command with secrets injected
pw run my-api -- env

# List all secrets
pw ls

# Show a secret
pw show my-api
```

## Data Schema

Secrets are YAML files with optional raw payload:

```yaml
__id: my-secret
_key: local-only (not exported)
SECRET_KEY: value
---
<Optional raw payload: SSH keys, certificates, etc.>
```

### Naming Conventions

- `__xxx` (Internal): Reserved for tool metadata (e.g., `__id`). Not injected.
- `_xxx` (Local): Private variables for expansion, not injected.
- `xxx` (Export): Standard environment variables, injected during `run`.

## Usage

| Command | Usage | Description |
| :--- | :--- | :--- |
| `ls` | `pw ls` | List all indexed `__id`s |
| `show` | `pw show <id>` | Decrypt and print full content |
| `edit` | `pw edit <id>` | Edit via `$EDITOR` |
| `run` | `pw run <id1> <id2> -- <cmd>` | Inject merged secrets and execute |
| `mv` | `pw mv <id> <new_id>` | Rename a secret |
| `rm` | `pw rm <id>` | Delete a secret |
| `reindex` | `pw reindex` | Rebuild index |
| `rcp` | `pw rcp <ls/add/rm>` | Manage age recipients |
| `import` | `pw import <dir>` | Import secrets (with `--conflict` option) |
| `export` | `pw export` | Export to `vault-export/` |

## Configuration

Default locations (can be overridden with env vars):

- `PW_ROOT`: Vault root (default: `.`)
- `PW_IDENTITIES`: Age identity file (default: `./identities`)
- `PW_DEBUG`: Enable debug logging

## Storage

```
.
├── vault/
│   ├── index.dat.age    # Encrypted index mapping nanoids to IDs
│   └── <nanoid>.age      # Individual secret files
└── identities          # Age private key
```

All data is encrypted with `age` and Git-friendly.
