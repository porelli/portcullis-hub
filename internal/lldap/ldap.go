package lldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// Password changes go over LDAP, not HTTP: LLDAP stores passwords with
// OPAQUE, and its HTTP endpoints (/auth/opaque/register/*) expect the
// client half of the OPAQUE registration (ristretto255 + argon2), which the
// Go standard library can't do. LLDAP's LDAP server implements the RFC 3062
// Password Modify extended operation and runs the OPAQUE registration
// server-side (lldap v0.6.3 crates/ldap/src/password.rs); members of
// lldap_admin may change any user's password that way.

// passwdModifyOID is the RFC 3062 Password Modify extended operation.
const passwdModifyOID = "1.3.6.1.4.1.4203.1.11.1"

// BER tags used below.
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagEnumerated  = 0x0a
	tagSequence    = 0x30

	appBindRequest     = 0x60 // [APPLICATION 0] constructed
	appBindResponse    = 0x61 // [APPLICATION 1] constructed
	appUnbindRequest   = 0x42 // [APPLICATION 2] primitive
	appExtendedRequest = 0x77 // [APPLICATION 23] constructed
	appExtendedResp    = 0x78 // [APPLICATION 24] constructed

	ctxPrim0 = 0x80 // [0] primitive
	ctxPrim1 = 0x81
	ctxPrim2 = 0x82
)

// maxLDAPMessage bounds a response read from the server.
const maxLDAPMessage = 1 << 20

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func tlv(tag byte, val []byte) []byte {
	out := append([]byte{tag}, berLen(len(val))...)
	return append(out, val...)
}

func berInt(n int) []byte {
	// Message IDs and the version are small positive integers.
	var b []byte
	for v := n; ; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
		if v < 0x80 {
			break
		}
	}
	return tlv(tagInteger, b)
}

func message(id int, op []byte) []byte {
	return tlv(tagSequence, append(berInt(id), op...))
}

// bindRequest is a simple bind (LDAPv3).
func bindRequest(id int, dn, password string) []byte {
	body := append(berInt(3), tlv(tagOctetString, []byte(dn))...)
	body = append(body, tlv(ctxPrim0, []byte(password))...)
	return message(id, tlv(appBindRequest, body))
}

// passwdModifyRequest sets userDN's password to newPassword.
func passwdModifyRequest(id int, userDN, newPassword string) []byte {
	val := append(tlv(ctxPrim0, []byte(userDN)), tlv(ctxPrim2, []byte(newPassword))...)
	body := append(tlv(ctxPrim0, []byte(passwdModifyOID)), tlv(ctxPrim1, tlv(tagSequence, val))...)
	return message(id, tlv(appExtendedRequest, body))
}

func unbindRequest(id int) []byte { return message(id, []byte{appUnbindRequest, 0}) }

// readTLV reads one BER element (definite length only).
func readTLV(r *bufio.Reader) (tag byte, val []byte, err error) {
	if tag, err = r.ReadByte(); err != nil {
		return 0, nil, err
	}
	l, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n := int(l)
	if l&0x80 != 0 {
		k := int(l & 0x7f)
		if k == 0 || k > 4 {
			return 0, nil, errors.New("ldap: unsupported BER length")
		}
		n = 0
		for i := 0; i < k; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return 0, nil, err
			}
			n = n<<8 | int(b)
		}
	}
	if n > maxLDAPMessage {
		return 0, nil, errors.New("ldap: response too large")
	}
	val = make([]byte, n)
	if _, err := io.ReadFull(r, val); err != nil {
		return 0, nil, err
	}
	return tag, val, nil
}

// splitTLV parses one element from b and returns the rest.
func splitTLV(b []byte) (tag byte, val, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("ldap: short element")
	}
	tag, l := b[0], int(b[1])
	b = b[2:]
	if l&0x80 != 0 {
		k := l & 0x7f
		if k == 0 || k > 4 || len(b) < k {
			return 0, nil, nil, errors.New("ldap: bad length")
		}
		l = 0
		for i := 0; i < k; i++ {
			l = l<<8 | int(b[i])
		}
		b = b[k:]
	}
	if l > len(b) {
		return 0, nil, nil, errors.New("ldap: truncated element")
	}
	return tag, b[:l], b[l:], nil
}

// ldapResult is the LDAPResult part of a response.
type ldapResult struct {
	Code    int
	Message string
}

// readResponse reads one LDAPMessage and returns its LDAPResult if the
// protocol op has tag wantOp and the message id matches.
func readResponse(r *bufio.Reader, wantID int, wantOp byte) (ldapResult, error) {
	tag, msg, err := readTLV(r)
	if err != nil {
		return ldapResult{}, fmt.Errorf("ldap: read response: %w", err)
	}
	if tag != tagSequence {
		return ldapResult{}, errors.New("ldap: response is not an LDAPMessage")
	}
	tag, idb, rest, err := splitTLV(msg)
	if err != nil || tag != tagInteger {
		return ldapResult{}, errors.New("ldap: bad message id")
	}
	id := 0
	for _, b := range idb {
		id = id<<8 | int(b)
	}
	if id != wantID {
		return ldapResult{}, fmt.Errorf("ldap: unexpected message id %d", id)
	}
	tag, op, _, err := splitTLV(rest)
	if err != nil {
		return ldapResult{}, err
	}
	if tag != wantOp {
		return ldapResult{}, fmt.Errorf("ldap: unexpected response op 0x%02x", tag)
	}
	tag, code, op, err := splitTLV(op)
	if err != nil || tag != tagEnumerated || len(code) == 0 {
		return ldapResult{}, errors.New("ldap: bad result code")
	}
	res := ldapResult{}
	for _, b := range code {
		res.Code = res.Code<<8 | int(b)
	}
	if _, _, op, err = splitTLV(op); err != nil { // matchedDN
		return res, nil
	}
	if tag, diag, _, err := splitTLV(op); err == nil && tag == tagOctetString {
		res.Message = string(diag)
	}
	return res, nil
}

// ResultError is a non-success LDAP result.
type ResultError struct {
	Op      string
	Code    int
	Message string
}

func (e *ResultError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("ldap %s: result %d: %s", e.Op, e.Code, e.Message)
	}
	return fmt.Sprintf("ldap %s: result %d", e.Op, e.Code)
}

// ldapPasswordModify binds as bindDN and sets userDN's password.
func ldapPasswordModify(ctx context.Context, rawURL string, timeout time.Duration, bindDN, bindPassword, userDN, newPassword string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid LLDAP LDAP URL: %w", err)
	}
	host := u.Host
	var conn net.Conn
	d := &net.Dialer{Timeout: timeout}
	switch u.Scheme {
	case "ldap":
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "389")
		}
		conn, err = d.DialContext(ctx, "tcp", host)
	case "ldaps":
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "636")
		}
		td := &tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}}
		conn, err = td.DialContext(ctx, "tcp", host)
	default:
		return fmt.Errorf("LLDAP LDAP URL must be ldap:// or ldaps://, got %q", u.Scheme)
	}
	if err != nil {
		return fmt.Errorf("ldap: connect: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)
	r := bufio.NewReader(conn)

	if _, err := conn.Write(bindRequest(1, bindDN, bindPassword)); err != nil {
		return fmt.Errorf("ldap: bind: %w", err)
	}
	res, err := readResponse(r, 1, appBindResponse)
	if err != nil {
		return err
	}
	if res.Code != 0 {
		// Never echo the server message for binds: keep it short.
		return &ResultError{Op: "bind", Code: res.Code}
	}
	if _, err := conn.Write(passwdModifyRequest(2, userDN, newPassword)); err != nil {
		return fmt.Errorf("ldap: password modify: %w", err)
	}
	res, err = readResponse(r, 2, appExtendedResp)
	if err != nil {
		return err
	}
	conn.Write(unbindRequest(3))
	if res.Code != 0 {
		return &ResultError{Op: "password modify", Code: res.Code, Message: strings.TrimSpace(res.Message)}
	}
	return nil
}
