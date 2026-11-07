#!/bin/sh
# Copies the docs pages the Hub ships as MCP resources (contract §15.10,
# portcullis://docs/<name>) from the docs repo into web/docs/. Run from
# web/ (`go generate ./web`), with PORTCULLIS_DOCS_DIR = a checkout of
# porelli/portcullis-docs (default ../../portcullis-docs). The copies are
# committed: CI and the Docker build embed them as they are, and
# TestDocsCopiesInSync compares them with a checkout when
# PORTCULLIS_DOCS_DIR is set.
set -eu
src="${PORTCULLIS_DOCS_DIR:-../../portcullis-docs}/docs"
dst="$(dirname "$0")"
for f in guides/integration-contracts.md operations/hub.md operations/auth-policies.md \
	operations/groups.md operations/backups.md operations/file-sharing.md operations/ai.md \
	guides/connect-your-ai.md; do
	cp "$src/$f" "$dst/$(basename "$f")"
done
