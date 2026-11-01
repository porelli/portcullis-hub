// Package web embeds the Hub's single-page UI.
package web

import "embed"

// FS holds index.html (the Hub), people.html (the people listener) and
// any static assets next to them.
//
//go:embed index.html people.html
var FS embed.FS
