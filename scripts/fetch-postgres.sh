#!/usr/bin/env bash
#
# fetch-postgres.sh — Download the PostgreSQL binary tarball for embedding.
#
# This script downloads the correct PostgreSQL binary archive from Maven Central
# and places it in internal/embeddedpg/pgcache/ so that `go build` embeds it
# into the TDFLite binary via //go:embed.
#
# Usage:
#   bash scripts/fetch-postgres.sh
#
# After running this script, build with:
#   go build -o tdflite ./cmd/tdflite
#
# The resulting binary will contain the Postgres tarball and will not need
# to download anything on first run.
#
# Environment variables (all optional):
#   PG_VERSION   — PostgreSQL version (default: 16.9.0, must match embeddedpg V16)
#   TARGET_OS    — Override OS detection (darwin, linux)
#   TARGET_ARCH  — Override arch detection (amd64, arm64v8)
#
set -euo pipefail

# --- Configuration -----------------------------------------------------------

PG_VERSION="${PG_VERSION:-16.9.0}"
MAVEN_BASE="https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PGCACHE_DIR="${PROJECT_ROOT}/internal/embeddedpg/pgcache"

# --- Detect OS ----------------------------------------------------------------

if [ -n "${TARGET_OS:-}" ]; then
    OS="${TARGET_OS}"
else
    case "$(uname -s)" in
        Darwin) OS="darwin" ;;
        Linux)  OS="linux" ;;
        *)
            echo "ERROR: Unsupported OS: $(uname -s)" >&2
            exit 1
            ;;
    esac
fi

# --- Detect Architecture ------------------------------------------------------

if [ -n "${TARGET_ARCH:-}" ]; then
    ARCH="${TARGET_ARCH}"
else
    case "$(uname -m)" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64v8" ;;
        arm64)   ARCH="arm64v8" ;;
        *)
            echo "ERROR: Unsupported architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
fi

# --- Construct URLs and paths -------------------------------------------------

ARTIFACT="embedded-postgres-binaries-${OS}-${ARCH}"
JAR_NAME="${ARTIFACT}-${PG_VERSION}.jar"
TXZ_NAME="${ARTIFACT}-${PG_VERSION}.txz"
JAR_URL="${MAVEN_BASE}-${OS}-${ARCH}/${PG_VERSION}/${JAR_NAME}"

echo "PostgreSQL version : ${PG_VERSION}"
echo "OS / Architecture  : ${OS} / ${ARCH}"
echo "Maven URL          : ${JAR_URL}"
echo "Output directory   : ${PGCACHE_DIR}"
echo ""

# --- Check if already present -------------------------------------------------

if [ -f "${PGCACHE_DIR}/${TXZ_NAME}" ]; then
    echo "Already exists: ${PGCACHE_DIR}/${TXZ_NAME}"
    echo "Delete it first if you want to re-download."
    exit 0
fi

# --- Download JAR (which is actually a ZIP) -----------------------------------

TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_WORK}"' EXIT

JAR_PATH="${TMPDIR_WORK}/${JAR_NAME}"

echo "Downloading ${JAR_NAME}..."
curl -fSL --progress-bar -o "${JAR_PATH}" "${JAR_URL}"
echo "Downloaded $(du -h "${JAR_PATH}" | cut -f1) to ${JAR_PATH}"

# --- Extract .txz from JAR (ZIP) ---------------------------------------------

echo "Extracting .txz from JAR..."
# The JAR is a ZIP. The .txz file is inside it. Use unzip to list and extract.
# The .txz filename inside the JAR may vary, so find it dynamically.
TXZ_INSIDE="$(unzip -l "${JAR_PATH}" | grep '\.txz$' | awk '{print $NF}' | head -1)"

if [ -z "${TXZ_INSIDE}" ]; then
    echo "ERROR: No .txz file found inside ${JAR_NAME}" >&2
    echo "JAR contents:" >&2
    unzip -l "${JAR_PATH}" >&2
    exit 1
fi

unzip -o -j "${JAR_PATH}" "${TXZ_INSIDE}" -d "${TMPDIR_WORK}"

# The extracted file might have a different name; rename to match expected format.
EXTRACTED_TXZ="${TMPDIR_WORK}/$(basename "${TXZ_INSIDE}")"

# --- Place in pgcache ---------------------------------------------------------

mkdir -p "${PGCACHE_DIR}"
mv "${EXTRACTED_TXZ}" "${PGCACHE_DIR}/${TXZ_NAME}"

echo ""
echo "Success! Embedded tarball placed at:"
echo "  ${PGCACHE_DIR}/${TXZ_NAME}"
echo ""
echo "Size: $(du -h "${PGCACHE_DIR}/${TXZ_NAME}" | cut -f1)"
echo ""
echo "Now build with:"
echo "  go build -o tdflite ./cmd/tdflite"
