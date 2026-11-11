// Package web embeds the Hub's single-page UI.
package web

import "embed"

// FS holds index.html (the Hub), people.html (the people listener) and
// the assets the pages load from /static/: directory.js and directory.css
// (both), settings.js, signin.js, folders.js and doctor.js (the Hub only), myapps.js
// and myai.js (its "Connect your AI" card; people.html only), confirm.html (the confirmation page, rendered by
// the Hub on both listeners), confirm.js (its script, both),
// mysignin.html (the Sign-in page, GET /signin on the people listener),
// and the fresh-auth popup: freshauth.js (the opener, myapps.js and confirm.js)
// and freshauth-callback.js (the callback, people.html and index.html).
//
//go:embed index.html people.html directory.js directory.css settings.js signin.js myapps.js myai.js folders.js doctor.js confirm.html confirm.js mysignin.html freshauth.js freshauth-callback.js
var FS embed.FS

// Docs holds the docs pages the Hub ships as read-only MCP resources
// (contract §15.10, portcullis://docs/<name>): committed copies of
// portcullis-docs pages, refreshed by docs/sync.sh (go generate).
// Separate from FS, so /static/ never serves them.
//
//go:generate sh docs/sync.sh
//go:embed docs/*.md
var Docs embed.FS
