#!/bin/sh
set -e

# Project-specific values — edit these when reusing the script for another project.
REPO="gera2ld/pw"
BINARY="pw"
DEST="$HOME/.local/bin/pw"

# If GITHUB_TOKEN is set, use it for authenticated requests (private repo support).
if [ -n "$GITHUB_TOKEN" ]; then
  _curl() { curl -fSL -H "Authorization: Bearer $GITHUB_TOKEN" "$@"; }
else
  _curl() { curl -fSL "$@"; }
fi

# Detect the platform and architecture from the running system.
OS="$(uname -s)"
MARCH="$(uname -m)"

case "$OS" in
  Darwin) PLATFORM="darwin" ;;
  Linux)  PLATFORM="linux" ;;
  *) echo "unsupported OS: $OS" >&2; exit 1 ;;
esac

case "$MARCH" in
  arm64|aarch64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="amd64" ;;
  *) echo "unsupported arch: $MARCH" >&2; exit 1 ;;
esac

# The release ships .tar.gz archives only; tar and gzip are required to extract them.
if ! command -v tar >/dev/null 2>&1 || ! command -v gzip >/dev/null 2>&1; then
  echo "error: tar and gzip are required to install pw" >&2
  exit 1
fi

# Download the asset.
ASSET="${BINARY}-${PLATFORM}-${ARCH}"
CHOSEN="${ASSET}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/latest/download"
TMP="/tmp/${CHOSEN}"

mkdir -p "$(dirname "$DEST")"
echo "Downloading ${CHOSEN} from ${REPO}…"
_curl "${BASE_URL}/${CHOSEN}" -o "$TMP"

# Verify the downloaded file's sha256 against version.txt when a hasher is available.
if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1; then
  if _curl "${BASE_URL}/version.txt" -o /tmp/pw-version.txt 2>/dev/null; then
    EXPECTED="$(grep "^${CHOSEN} " /tmp/pw-version.txt | awk '{print $2}')"
    if [ -n "$EXPECTED" ]; then
      if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL="$(sha256sum "$TMP" | awk '{print $1}')"
      else
        ACTUAL="$(shasum -a 256 "$TMP" | awk '{print $1}')"
      fi
      if [ "$ACTUAL" != "$EXPECTED" ]; then
        echo "checksum mismatch: expected $EXPECTED, got $ACTUAL" >&2
        rm -f "$TMP"
        exit 1
      fi
      echo "Checksum verified."
    else
      echo "warning: no checksum for ${CHOSEN} in version.txt, skipping verification" >&2
    fi
  fi
fi

# Extract the archive and install the binary with executable permissions.
tar -xzf "$TMP" -C /tmp
rm -f "$TMP"
TMP="/tmp/${ASSET}"
mv "$TMP" "$DEST"
chmod +x "$DEST"

# Remove the macOS quarantine attribute so the binary runs without a Gatekeeper warning.
if [ "$PLATFORM" = "darwin" ]; then
  xattr -d com.apple.quarantine "$DEST" 2>/dev/null || true
fi

# Report success and print the installed version.
echo "Installed pw to $DEST"
"$DEST" --version || true

