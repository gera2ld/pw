#!/bin/sh

set -e

INSTALL_DIR="${HOME}/.local/bin"
BIN_NAME="pw"
REPO="gera2ld/pw"

mkdir -p "$INSTALL_DIR"

detect_os() {
    case "$(uname -s)" in
        Darwin*) echo "darwin" ;;
        Linux*) echo "linux" ;;
        *) echo "linux" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *) echo "amd64" ;;
    esac
}

get_latest_version() {
    curl -sL "https://github.com/${REPO}/releases/download/latest/version.txt"
}

get_local_version() {
    if [ -x "${INSTALL_DIR}/${BIN_NAME}" ]; then
        "${INSTALL_DIR}/${BIN_NAME}" --version 2>/dev/null || echo ""
    else
        echo ""
    fi
}

OS=$(detect_os)
ARCH=$(detect_arch)
LATEST_VERSION=$(get_latest_version)
LOCAL_VERSION=$(get_local_version)

if [ "$LOCAL_VERSION" = "$LATEST_VERSION" ]; then
    echo "pw ${LATEST_VERSION} is already installed"
    exit 0
fi

if [ -n "$LOCAL_VERSION" ]; then
    echo "Updating pw: ${LOCAL_VERSION} -> ${LATEST_VERSION}"
else
    echo "Installing pw ${LATEST_VERSION}"
fi

URL="https://github.com/${REPO}/releases/download/latest/pw-${OS}-${ARCH}"

if [ "${OS}" = "windows" ]; then
    URL="${URL}.exe"
    DEST="${INSTALL_DIR}/${BIN_NAME}.exe"
else
    DEST="${INSTALL_DIR}/${BIN_NAME}"
fi

echo "Downloading ${URL}"
curl -#L "$URL" -o "$DEST"
chmod 755 "$DEST"

echo "Installed to ${DEST}"

if [ -d "${HOME}/.local/bin" ]; then
    if ! echo "$PATH" | grep -q "${HOME}/.local/bin"; then
        echo "Add to PATH (bash/zsh):"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi
