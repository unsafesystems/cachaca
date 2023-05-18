//nolint
package secure

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestGetHeader(t *testing.T) {
	_, ok := GetHeader("test", "test")
	assert.False(t, ok)
}

func TestSetHeader(t *testing.T) {
	ctx := SetHeader("test", "test", "key")
	assert.Nil(t, ctx)
}

func TestSetCookieHTTP(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)

	// insecure cookie
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	val := uuid.NewString()
	_ = SetCookie(ctx, "", "test", val)
	assert.Equal(t, fmt.Sprintf("test=%s; Path=/; HttpOnly; SameSite=Strict", val), ctx.Writer.Header().Get("Set-Cookie"))

	// secure cookie - tls is set
	ctx, _ = gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx.Request.TLS = &tls.ConnectionState{}
	val = uuid.NewString()
	_ = SetCookie(ctx, "", "test", val)
	assert.Equal(t, fmt.Sprintf("__Host-test=%s; Path=/; HttpOnly; Secure; SameSite=Strict", val), ctx.Writer.Header().Get("Set-Cookie"))

	// secure cookie - X-Forwarded-Proto
	ctx, _ = gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx.Request.Header.Set("X-Forwarded-Proto", "https")
	val = uuid.NewString()
	_ = SetCookie(ctx, "", "test", val)
	assert.Equal(t, fmt.Sprintf("__Host-test=%s; Path=/; HttpOnly; Secure; SameSite=Strict", val), ctx.Writer.Header().Get("Set-Cookie"))

	// secure cookie - URL.Scheme
	ctx, _ = gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx.Request.URL.Scheme = "https"
	val = uuid.NewString()
	_ = SetCookie(ctx, "", "test", val)
	assert.Equal(t, fmt.Sprintf("__Host-test=%s; Path=/; HttpOnly; Secure; SameSite=Strict", val), ctx.Writer.Header().Get("Set-Cookie"))

	// secure cookie - but with a path
	ctx, _ = gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx.Request.TLS = &tls.ConnectionState{}
	val = uuid.NewString()
	_ = SetCookie(ctx, "/test", "test", val)
	assert.Equal(t, fmt.Sprintf("__Secure-test=%s; Path=/test; HttpOnly; Secure; SameSite=Strict", val), ctx.Writer.Header().Get("Set-Cookie"))

	// using a http.ResponseWriter will fail because it doesn't have a Request
	assert.Panics(t, func() {
		w := httptest.NewRecorder()
		_ = SetCookie(w, "", "test", val)
	})
}

func TestGetCookieHTTP(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)

	// insecure cookie
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	val := uuid.NewString()
	ctx.Request.Header.Set("Cookie", "test="+val)
	cookie, ok := GetCookie(ctx, "test")
	assert.True(t, ok)
	assert.Equal(t, val, cookie)

	// same with *http.Request
	cookie, ok = GetCookie(ctx.Request, "test")
	assert.True(t, ok)
	assert.Equal(t, val, cookie)

	// No cookie found
	cookie, ok = GetCookie(ctx, "test2")
	assert.False(t, ok)

	// Cookie with prefixes
	ctx.Request.Header.Set("Cookie", "__Host-test="+val)
	cookie, ok = GetCookie(ctx, "test")
	assert.True(t, ok)
	assert.Equal(t, val, cookie)

	// Cookie with prefixes
	ctx.Request.Header.Set("Cookie", "__Secure-test="+val)
	cookie, ok = GetCookie(ctx, "test")
	assert.True(t, ok)
	assert.Equal(t, val, cookie)

	// Cookie without prefix is not allowed if the context is secure
	ctx.Request.TLS = &tls.ConnectionState{}
	ctx.Request.Header.Set("Cookie", "test="+val)
	cookie, ok = GetCookie(ctx, "test")
	assert.False(t, ok)

	// Because we need the prefix
	ctx.Request.TLS = &tls.ConnectionState{}
	ctx.Request.Header.Set("Cookie", "__Host-test="+val)
	cookie, ok = GetCookie(ctx, "test")
	assert.True(t, ok)
}

func TestGetHeaderHTTP(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)

	// gin header
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx.Request.Header.Set("X-Test", "test")
	header, ok := GetHeader(ctx, "X-Test")
	assert.True(t, ok)
	assert.Equal(t, "test", header)

	// also works with the context directly
	header, ok = GetHeader(ctx.Request, "X-Test")
	assert.True(t, ok)
	assert.Equal(t, "test", header)

	// also works with some malformed header name
	header, ok = GetHeader(ctx.Request, "x-test")
	assert.True(t, ok)
	assert.Equal(t, "test", header)
}

func TestGetHeaderGRPC(t *testing.T) {
	// happy path
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-test", "test"))
	header, ok := GetHeader(ctx, "X-Test")
	assert.True(t, ok)
	assert.Equal(t, "test", header)

	// also works with some malformed header name
	header, ok = GetHeader(ctx, "x-test")
	assert.True(t, ok)
	assert.Equal(t, "test", header)

	// no header
	header, ok = GetHeader(ctx, "x-test2")
	assert.False(t, ok)

	// no metadata
	header, ok = GetHeader(context.Background(), "x-test")
	assert.False(t, ok)

	// malformed header in context
	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("X-Test", "test"))
	header, ok = GetHeader(ctx, "X-Test")
	assert.True(t, ok)
	assert.Equal(t, "test", header)
}

func TestSetHeaderGRPC(t *testing.T) {
	ctx := context.Background()
	ctx = SetHeader(ctx, "X-Test", "test")
	md, ok := metadata.FromOutgoingContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "test", md.Get("x-test")[0])
}

func TestGetCookieGRPC(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("cookie", "__Host-test=test"))
	cookie, ok := GetCookie(ctx, "test")
	assert.True(t, ok)
	assert.Equal(t, "test", cookie)

	// no metadata
	cookie, ok = GetCookie(context.Background(), "test")
	assert.False(t, ok)

	// secure
	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("cookie", "__Host-test=test", "x-forwarded-proto", "https"))
	cookie, ok = GetCookie(ctx, "test")
	assert.True(t, ok)
	assert.Equal(t, "test", cookie)

	// secure but no x-forwarded-proto
	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("cookie", "__Host-test=test"))
	cookie, ok = GetCookie(ctx, "test")
	assert.True(t, ok)
	assert.Equal(t, "test", cookie)

	// non-secure but x-forwarded-proto set
	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("cookie", "test=test", "x-forwarded-proto", "https"))
	cookie, ok = GetCookie(ctx, "test")
	assert.False(t, ok)
	assert.Equal(t, "", cookie)
}

func TestDeleteCookie(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)

	// gin header
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	_ = DeleteCookie(ctx, "", "test")
	assert.Equal(t, "test={}; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict", ctx.Writer.Header().Get("Set-Cookie"))
}
