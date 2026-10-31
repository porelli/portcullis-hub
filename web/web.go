// Package web embeds the Hub's single-page UI.
package web

import "embed"

// FS holds index.html (and any static assets next to it).
//
//go:embed index.html
var FS embed.FS
