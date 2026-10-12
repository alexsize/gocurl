#!/usr/bin/env bash
# Native Linux tools for the local Ubuntu 24.04 WSL quality gate.
set -euo pipefail

if [[ $(id -u) != 0 || $(uname -m) != x86_64 ]]; then
    printf 'Run this installer as root in x86_64 Ubuntu WSL.\n' >&2
    exit 1
fi

tools_prefix=/opt/gocurl-toolchains
tools_downloads=$(mktemp -d /tmp/gocurl-tools-XXXXXXXX)
go_prefix=$tools_prefix/go1.26.6
node_prefix=$tools_prefix/node-v24.21.0
lint_prefix=$tools_prefix/golangci-lint-2.10.1
pwsh_prefix=$tools_prefix/powershell-7.6.6

install_archive() {
    local url=$1 checksum=$2 directory=$3 strip=$4 executable=$5 archive
    if [[ -x $directory/$executable ]]; then
        return
    fi
    if [[ -e $directory ]]; then
        printf 'Incomplete installation already exists: %s; nothing overwritten.\n' "$directory" >&2
        exit 1
    fi
    archive=$tools_downloads/$(basename "$url")
    curl --fail --silent --show-error --location --retry 3 "$url" --output "$archive"
    printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --status
    install -d "$directory"
    tar --extract --gzip --file "$archive" --directory "$directory" --strip-components="$strip"
    chmod +x "$directory/$executable"
}

link_tool() {
    local target=$1 link=/usr/local/bin/$2
    if [[ -e $link || -L $link ]]; then
        if [[ $(readlink -f "$link") != $(readlink -f "$target") ]]; then
            printf 'Existing tool left intact: %s\n' "$link" >&2
            exit 1
        fi
    else
        ln --symbolic "$target" "$link"
    fi
}

install -d "$tools_prefix" /usr/local/bin
install_archive https://go.dev/dl/go1.26.6.linux-amd64.tar.gz \
    708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89 "$go_prefix" 1 bin/go

node_archive=node-v24.21.0-linux-x64.tar.gz
curl --fail --silent --show-error --location --retry 3 \
    https://nodejs.org/dist/v24.21.0/SHASUMS256.txt --output "$tools_downloads/node-shasums.txt"
node_checksum=$(awk -v archive="$node_archive" '$2 == archive { print $1 }' "$tools_downloads/node-shasums.txt")
[[ $node_checksum =~ ^[0-9a-f]{64}$ ]]
install_archive "https://nodejs.org/dist/v24.21.0/$node_archive" "$node_checksum" "$node_prefix" 1 bin/node

install_archive https://github.com/golangci/golangci-lint/releases/download/v2.10.1/golangci-lint-2.10.1-linux-amd64.tar.gz \
    dfa775874cf0561b404a02a8f4481fc69b28091da95aa697259820d429b09c99 "$lint_prefix" 1 golangci-lint
install_archive https://github.com/PowerShell/PowerShell/releases/download/v7.6.6/powershell-7.6.6-linux-x64.tar.gz \
    ddbc4a2d113bbd46d283cfedcbcd117a70caefd7673f41f2b4e0000badf103bc "$pwsh_prefix" 0 pwsh

link_tool "$go_prefix/bin/go" go
link_tool "$node_prefix/bin/node" node
link_tool "$node_prefix/bin/npm" npm
link_tool "$node_prefix/bin/npx" npx
link_tool "$lint_prefix/golangci-lint" golangci-lint
link_tool "$pwsh_prefix/pwsh" pwsh
export PATH="/usr/local/bin:$PATH"
npm install --prefix "$node_prefix" --global markdownlint-cli@0.49.1
go version
node --version
golangci-lint version
pwsh --version
npx --no-install markdownlint-cli --version
printf 'Downloaded archives retained in %s.\n' "$tools_downloads"
