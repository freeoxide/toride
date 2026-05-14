#!/bin/sh
# toride install script
# Usage: curl -fsSL https://toride.dev/install.sh | sh
# Or:   curl -fsSL https://github.com/hmziqrs/toride/releases/latest/download/install.sh | sh

set -e

REPO="hmziqrs/toride"
INSTALL_DIR="${TORIDE_INSTALL:-/usr/local/bin}"
TMPDIR="${TMPDIR:-/tmp}"

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Detect OS
OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
    echo "toride is only supported on Linux. Detected: $OS"
    exit 1
fi

# Get latest version from GitHub API
echo "Fetching latest release version..."
VERSION="${TORIDE_VERSION:-$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')}"

if [ -z "$VERSION" ]; then
    echo "Failed to determine latest version."
    exit 1
fi

echo "Installing toride ${VERSION} for ${TARGET}..."

FILENAME="toride-${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"

# Download
TMPFILE="${TMPDIR}/toride-${VERSION}.tar.gz"
echo "Downloading ${URL}..."
curl -fsSL "$URL" -o "$TMPFILE"

# Verify SHA256 if checksums file exists
SHAFILE="toride-${VERSION}-sha256sums.txt"
SHAURL="https://github.com/${REPO}/releases/download/${VERSION}/${SHAFILE}"
if curl -fsSL "$SHAURL" -o "${TMPDIR}/${SHAFILE}" 2>/dev/null; then
    EXPECTED="$(grep "${FILENAME}" "${TMPDIR}/${SHAFILE}" | cut -d' ' -f1)"
    ACTUAL="$(sha256sum "$TMPFILE" | cut -d' ' -f1)"
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "SHA256 verification failed!"
        echo "Expected: $EXPECTED"
        echo "Actual:   $ACTUAL"
        rm -f "$TMPFILE" "${TMPDIR}/${SHAFILE}"
        exit 1
    fi
    echo "SHA256 verified."
fi

# Extract and install
cd "$TMPDIR"
tar xzf "$TMPFILE"

if [ ! -f "toride" ]; then
    echo "Binary not found in archive."
    rm -f "$TMPFILE" "${TMPDIR}/${SHAFILE}"
    exit 1
fi

# Install
if [ -w "$INSTALL_DIR" ]; then
    mv toride "${INSTALL_DIR}/toride"
    chmod +x "${INSTALL_DIR}/toride"
else
    echo "Writing to ${INSTALL_DIR} requires root."
    sudo mv toride "${INSTALL_DIR}/toride"
    sudo chmod +x "${INSTALL_DIR}/toride"
fi

# Cleanup
rm -f "$TMPFILE" "${TMPDIR}/${SHAFILE}"

echo ""
echo "toride ${VERSION} installed to ${INSTALL_DIR}/toride"
echo "Run 'toride' to start the setup wizard."
