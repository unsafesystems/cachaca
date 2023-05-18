// Package secure provides a set of functions for setting and getting cookies and headers and ensures that security
// best practices are followed. It supports cookie and http operations on standard http requests, as well as
// *gin.Context, gRPC-web and gRPC metadata.
//
// The package automatically handles the __Host, __Secure and secure flags for cookies.
// It identifies a connection as secure using the following properties (for HTTP):
// - (*http.Request).TLS != nil
// - (*http.Request).URL.Scheme == "https"
// - (*http.Request).Header.Get("X-Forwarded-Proto") == "https"
//
// For gRPC-web, it uses the following properties. Especially AuthInfo will be non-nil if the connection is at least
// TLS protected.
// - metadata.Get("x-forwarded-proto") == "https"
// - peer.AuthInfo.AuthType == "tls"
package secure

import (
	"context"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"google.golang.org/grpc/peer"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/http/httpguts"
	"google.golang.org/grpc/metadata"
)

const (
	HTTPS = "https"
)

// Secure handles setting and getting cookies and tokens and ensures that security best practices are followed.
// Cookie detects from the gin Context if the request is HTTPS and automatically sets the secure flag and
// __Host- prefix. It also enforces SameSite=Strict and http-only on the cookie.
// When a new instance of Cookie is created, secure can be forced optionally e.g. if running behind a reverse
// proxy.

// GetCookie retrieves a cookie with the given key from the request. It strips __Host- and __Secure- prefixes for
// comparison. GetCookie supports *http.Request, *gin.Context and context.Context (for gRPC-web) as input.
func GetCookie(req interface{}, key string) (string, bool) {
	var cookies []*http.Cookie

	switch req := req.(type) {
	case *http.Request:
		cookies = req.Cookies()

	case *gin.Context:
		cookies = req.Request.Cookies()

	case context.Context:
		md, ok := metadata.FromIncomingContext(req)
		if !ok {
			return "", false
		}

		cookies = parseCookies(md.Get("cookie"))
	}

	for _, cookie := range cookies {
		name := strings.TrimPrefix(strings.TrimPrefix(cookie.Name, "__Host-"), "__Secure-")

		if secure(req) {
			if cookie.Name == "__Host-"+key || cookie.Name == "__Secure-"+key {
				return cookie.Value, true
			}
		} else if name == key {
			return cookie.Value, true
		}
	}

	return "", false
}

// SetCookie sets a cookie with the given key and value. It automatically sets the secure flag and __Host- or __Secure-
// prefix if the request is secure. It also enforces SameSite=Strict and http-only on the cookie.
// SetCookie supports http.ResponseWriter, *gin.Context and context.Context (for gRPC-web) as input.
func SetCookie(req interface{}, path string, key string, value string) context.Context {
	if path == "" {
		path = "/"
	}

	cookie := http.Cookie{
		Name:     cookieName(req, key, path),
		Value:    value,
		Path:     path,
		Secure:   secure(req),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	return SetHeader(req, "Set-Cookie", cookie.String())
}

// DeleteCookie deletes a cookie with the given key to the best of its ability. Please note that browsers may interpret
// the cookie differently and may not delete it.
func DeleteCookie(req interface{}, path string, key string) context.Context {
	if path == "" {
		path = "/"
	}

	cookie := http.Cookie{
		Name:     cookieName(req, key, path),
		Value:    "{}", // Couldn't find conclusive information on whether an empty value is allowed
		Path:     path,
		Secure:   secure(req),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0),
	}

	return SetHeader(req, "Set-Cookie", cookie.String())
}

// SetHeader sets a header with the given key and value. It supports http.ResponseWriter, *gin.Context and
// context.Context (for gRPC-web) as input.
func SetHeader(req interface{}, key, val string) context.Context {
	switch req := req.(type) {
	case *gin.Context:
		req.Writer.Header().Add(key, val)

	case http.ResponseWriter:
		req.Header().Add(key, val)

	case context.Context:
		return metadata.AppendToOutgoingContext(req, strings.ToLower(key), val)
	}

	return nil
}

// GetHeader retrieves a header with the given key. It supports http.Request, *gin.Context and context.Context.
func GetHeader(req interface{}, key string) (string, bool) {
	switch req := req.(type) {
	case *gin.Context:
		val := req.Request.Header.Get(key)

		return val, val != ""
	case *http.Request:
		val := req.Header.Get(key)

		return val, val != ""

	case context.Context:
		md, ok := metadata.FromIncomingContext(req)
		if !ok {
			return "", false
		}

		tk := md.Get(strings.ToLower(key))
		if len(tk) != 1 {
			return "", false
		}

		return tk[0], true
	}

	return "", false
}

func secure(req interface{}) bool {
	var hreq *http.Request

	switch req := req.(type) {
	case *http.Request:
		hreq = req
	case *gin.Context:
		hreq = req.Request
	case context.Context:
		return secureGRPC(req)
	default:
		panic("secure: invalid context")
	}

	return hreq.Header.Get("X-Forwarded-Proto") == HTTPS ||
		hreq.TLS != nil ||
		(hreq.URL != nil && hreq.URL.Scheme == HTTPS)
}

func secureGRPC(ctx context.Context) bool {
	p, ok := peer.FromContext(ctx)
	if ok && p.AuthInfo != nil && p.AuthInfo.AuthType() == "tls" {
		return true
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if v := md.Get("x-forwarded-proto"); len(v) > 0 && v[0] == HTTPS {
			return true
		}
	}

	return false
}

func cookieName(req interface{}, key string, path string) string {
	if secure(req) && path == "/" {
		return "__Host-" + key
	}

	if secure(req) {
		return "__Secure-" + key
	}

	return key
}

// Source: https://go.dev/src/net/http/cookie.go
func parseCookies(lines []string) []*http.Cookie {
	if len(lines) == 0 {
		return nil
	}

	cookies := make([]*http.Cookie, 0, len(lines)+strings.Count(lines[0], ";"))

	for _, line := range lines {
		line = textproto.TrimString(line)

		var part string
		for len(line) > 0 { // continue since we have rest
			part, line, _ = strings.Cut(line, ";")

			part = textproto.TrimString(part)
			if part == "" {
				continue
			}

			name, val, _ := strings.Cut(part, "=")

			name = textproto.TrimString(name)
			if !isCookieNameValid(name) {
				continue
			}

			val, ok := parseCookieValue(val, true)
			if !ok {
				continue
			}

			cookies = append(cookies, &http.Cookie{Name: name, Value: val})
		}
	}

	return cookies
}

// Source: https://go.dev/src/net/http/cookie.go
func validCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}

// Source: https://go.dev/src/net/http/cookie.go
func parseCookieValue(raw string, allowDoubleQuote bool) (string, bool) {
	// Strip the quotes, if present.
	if allowDoubleQuote && len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}

	for i := 0; i < len(raw); i++ {
		if !validCookieValueByte(raw[i]) {
			return "", false
		}
	}

	return raw, true
}

// Source: https://go.dev/src/net/http/cookie.go
func isCookieNameValid(raw string) bool {
	if raw == "" {
		return false
	}

	return strings.IndexFunc(raw, isNotToken) < 0
}

func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}
