// Package web embeds the Hub's single-page UI.
package web

import "embed"

// FS holds index.html (the Hub), people.html (the people listener) and
// the assets the pages load from /static/: directory.js and directory.css
// (both), settings.js, folders.js and doctor.js (the Hub only), myapps.js
// (people.html only).
//
//go:embed index.html people.html directory.js directory.css settings.js myapps.js folders.js doctor.js
var FS embed.FS
