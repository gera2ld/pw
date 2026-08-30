# pw - Minimalist CLI Secret Manager

pw is a local-first, cross-platform, and Git-friendly secret manager.

## Features

- **Metadata privacy**: Randomized filenames (nanoids) prevent metadata leakage in cloud backups
- **Per-entry Git granularity**: Each secret is a standalone encrypted file
- **Variable expansion**: Local variables can be referenced as `$var`, `${var}`, or `{{._var}}`
- **Zero-leakage**: Plaintext never hits the disk (piped through memory)

## Prerequisites

- **[age](https://github.com/FiloSottile/age)**: Encryption tool

## Installation

```bash
curl -sL https://raw.githubusercontent.com/gera2ld/pw/main/install.sh | sh
```

This installs `pw` to `~/.local/bin/pw`. Add that directory to your PATH.

<details>
<summary>Manual install</summary>

1. Download the latest release from GitHub
2. Make it executable: `chmod +x pw`
3. Move to your PATH: `mv pw ~/.local/bin/`

</details>

Install *age* (required dependency):

```bash
mise use -g age
# or: brew install age
# or: go install github.com/FiloSottile/age/cmd/age@latest
```

## Quick Start

```bash
# 1. Generate an age identity (private key)
age-keygen -o ~/.config/pw/identities

# 2. Configure recipients: add your age public key to ~/.config/pw/.pw.yml
#    recipients:
#      - age1...

# Create a secret
pw edit my-api
# Opens editor with default __name: my-api
# Add your secrets:
# __name: my-api
# _base_url: https://api.example.com
# API_KEY: secret123
# ENDPOINT: '$_base_url/v1'

# Run command with secrets injected
pw run my-api -- env

# List all secrets
pw ls

# Show a secret
pw show my-api
```

> [!WARNING]
> Your identity file is the only way to decrypt your secrets. If you lose it, your data is permanently inaccessible. Back it up securely.

## Data Schema

Secrets are YAML files with optional raw payload:

```yaml
__name: password
_key: local-only (not exported)
SECRET_KEY: value
---
<Optional raw payload: SSH keys, certificates, etc.>
```

`__name` is the secret's relative name (the final segment). The full id
(`folder/subfolder/name`) determines where the file lives on disk — the directory is
mirrored as plaintext folders and only the leaf `.age` file is encrypted. The full id is
reconstructed from the file's location + `__name`.

### Naming Conventions

- `__xxx` (Internal): Reserved for tool metadata (e.g., `__name`). Not injected.
- `_xxx` (Local): Private variables for expansion (reference as `$_xxx`, `${_xxx}`, or `{{._xxx}}`), not injected.
- `xxx` (Export): Standard environment variables, injected during `run`.

## Usage

| Command | Usage | Description |
| :--- | :--- | :--- |
| `ls` | `pw ls` | List all indexed secret ids |
| `show` | `pw show <id>` | Decrypt and print full content |
| `edit` | `pw edit <id>` | Edit via `$EDITOR` |
| `get` | `pw get <id> <key>` | Print a single env var value exactly, or error if missing |
| `run` | `pw run <id1> <id2> -- <cmd>` | Inject merged secrets and execute |
| `mv` | `pw mv <id> <new_id>` | Rename a secret (`--dry-run` shows the move) |
| `rm` | `pw rm [filters...]` | Delete secrets; fuzzy multi-match filters allowed (`--dry-run` lists without deleting) |
| `reindex` | `pw reindex` | Rebuild index |
| `reencrypt` | `pw reencrypt [filters...]` | Re-encrypt secrets with the current per-folder recipients (`--dry-run` lists matches without writing) |
| `import` | `pw import <dir>` | Import secrets (with `--conflict` option) |
| `export` | `pw export` | Export to `vault-export/` |

## Configuration

Default locations (can be overridden with env vars):

- `PW_ROOT`: Vault root (default: `~/.config/pw`)
- `PW_IDENTITIES`: Age identity file (default: `$PW_ROOT/identities`)
- `PW_DATA_DIR`: Directory where secrets are stored (default: `vault`, resolved relative to `$PW_ROOT` unless an absolute path is given)
- `PW_DEBUG`: Enable debug logging

Recipients (age public keys) are configured in `.pw.yml` files. A `.pw.yml` at
`$PW_ROOT` acts as the global default, and any `.pw.yml` inside the data directory
contributes recipients for its folder and all subfolders. Recipients are **unioned**
across the global config, the vault root, and every ancestor folder, with duplicates
removed (so a child folder can *add* recipients but not remove those inherited from
a parent).

```bash
# Configure recipients by editing .pw.yml (no CLI command needed)
cat > $PW_ROOT/.pw.yml <<'EOF'
recipients:
  - age1...
EOF
```

You can also drop a `.pw.yml` next to your secrets to scope recipients per folder:

```
$PW_DATA_DIR/db/.pw.yml   # recipients: [age1...]  (applies to db/ and below)
```

By default each secret's file is named after its readable, lowercased, kebab-case
basename and a unique counter suffix is appended on collision (e.g.
`db/prod/password.age`, `db/prod/password.2.age`). Set `obscure_names: true` in a
`.pw.yml` to instead store files under random lowercase nanoids
(`db/prod/<nanoid>.age`):

```yaml
obscure_names: true
```

The on-disk naming is a cosmetic choice — lookups always go through the encrypted
index, so `pw reindex` will move files between the two layouts to match the current
`obscure_names` setting.

## Key lookup

Commands that take an `<id>` accept the following forms:

- **Exact** — a leading `/` with no wildcards, e.g. `/db/prod/password`.
- **Fuzzy** — without a leading `/`, treated as a subsequence query: the last
  part must match the secret's basename exactly, and the remaining parts must
  appear in order as ancestors (e.g. `prod/password`).
- **Glob** — a filter containing `*`/`?`/`[` is a wildcard pattern. `*` matches
  within a single path segment and **never crosses `/`** (so `server/*` matches
  `/server/x` but not `/server/x/y`, and `git*/*` matches `/gitlab/foo`). A
  leading `/` anchors the pattern at the root and may still carry wildcards
  (e.g. `/server/*`). The `**` segment matches **any number of path segments**,
  spanning across `/` — so `server/**` matches `/server/x`, `/server/x/y`, and
  any deeper descendant.

Single-target commands (`show`, `edit`, `mv`, `run`) throw if a lookup matches
zero or more than one secret. Bulk commands that accept filters (`rm`,
`reencrypt`) allow multiple matches and operate on all of them.

## Storage

Default `~/.config/pw/`:
```
~/.config/pw/
├── .pw.yml              # Global recipient config
├── identities           # Age private key
└── vault/               # $PW_DATA_DIR (default)
    ├── .pw.yml          # Optional per-folder recipient config
    ├── index.dat.age    # Encrypted index mapping file paths to IDs
    ├── password.age      # Top-level secret (readable name, default)
    └── db/
        └── prod/
            └── password.age  # Mirrored from id "db/prod/password"
```

With `obscure_names: true` the leaf files use random nanoids instead
(`db/prod/<nanoid>.age`). Secret ids may contain `/` to organize secrets into folders.
The full id path is mirrored on disk (directories are kept as plaintext; only the leaf
`.age` file is encrypted). The index (`index.dat.age`) is a single encrypted file at the
root of the data directory.

### Migrating existing data

`pw reindex` rebuilds `index.dat.age` and, when the `obscure_names` setting changes,
physically moves files between the readable and obscured layouts:

```bash
pw reindex
```

All data is encrypted with `age` and Git-friendly.
