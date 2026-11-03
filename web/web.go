// Package web embeds the Hub's single-page UI.
package web

import "embed"

// FS holds index.html (the Hub), people.html (the people listener) and
// the directory UI assets both pages load from /static/ (directory.js,
// directory.css, settings.js).
//
//go:embed index.html people.html directory.js directory.css settings.js
var FS embed.FS
