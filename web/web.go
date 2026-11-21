// Package web embeds the Hub's single-page UI.
package web

import "embed"

// FS holds index.html (the Hub), people.html (the people listener) and
// the assets the pages load from /static/: directory.js and directory.css
// (both), settings.js, signin.js, folders.js, doctor.js, usage.js, dns.js, mail.js, mailprovider.js and servers.js (the Hub only), myapps.js
// and myai.js (its "Connect your AI" card; people.html only), confirm.html (the confirmation page, rendered by
// the Hub on both listeners), confirm.js (its script, both),
// mysignin.html (the Sign-in page, GET /signin on the people listener) and
// mysignin.js (its script, also the person's Sign-in tab on people.html),
// impersonation-stop.html (the Stop page, GET /impersonation/stop on the
// people listener) and impersonation.js (the impersonation banner and the
// Stop page's script; people.html, mysignin.html, confirm.html and the Stop page),
// and the fresh-auth popup: freshauth.js (the opener, myapps.js and confirm.js)
// and freshauth-callback.js (the callback, people.html and index.html),
// the Settings subtabs: settingsnav.js and the Marketplace: marketplace.js (Hub only),
// the Access tab: access.js (SSH access, VPN devices, sign-in history; Hub
// listener only), SSH access (contract §18): ssh.js (Access → SSH and
// Settings → SSH, Hub listener only) and myssh.js (the people pages' SSH card, People →
// person and the ssh_access holders' tab),
// the VPN page (vpn.html, vpn.js, vendor/qrcode.js: GET /vpn/ and
// /vpn/assets/ on the people listener, contract §5.1),
// and the Raised-gate logo set (copies of the branding source, pinned by
// sha256 in web_test.go; on both listeners): favicon.svg, favicon.ico,
// apple-touch-icon.png, icon-192.png, icon-512.png, maskable-512.png,
// site.webmanifest and mark.svg (the dark mark in each page's <h1>).
//
//go:embed index.html people.html directory.js directory.css settings.js signin.js myapps.js myai.js folders.js doctor.js usage.js donut.js share.js dns.js mail.js mailprovider.js servers.js access.js settingsnav.js marketplace.js confirm.html confirm.js mysignin.html mysignin.js ssh.js myssh.js impersonation-stop.html impersonation.js freshauth.js freshauth-callback.js vpn.html vpn.js vendor/qrcode.js favicon.svg favicon.ico apple-touch-icon.png icon-192.png icon-512.png maskable-512.png site.webmanifest mark.svg
var FS embed.FS

// Docs holds the docs pages the Hub ships as read-only MCP resources
// (contract §15.10, portcullis://docs/<name>): committed copies of
// portcullis-docs pages, refreshed by docs/sync.sh (go generate).
// Separate from FS, so /static/ never serves them.
//
//go:generate sh docs/sync.sh
//go:embed docs/*.md
var Docs embed.FS
