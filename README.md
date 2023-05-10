# Cachaça
[![codecov](https://codecov.io/github/unsafesystems/cachaca/branch/master/graph/badge.svg?token=PNMZFT2LGU)](https://codecov.io/github/unsafesystems/cachaca)
[![Go Reference](https://pkg.go.dev/badge/github.com/unsafesystems/cachaca.svg)](https://pkg.go.dev/github.com/unsafesystems/cachaca)

Cachaça (Portuguese pronunciation: [kaˈʃasɐ](https://dictionary.cambridge.org/pronunciation/english/cachaca)) is a 
distilled spirit made from fermented sugarcane juice. Also known as pinga, caninha, and other names, it is the most 
popular spirit among distilled alcoholic beverages in Brazil. Outside Brazil, cachaça is used almost exclusively as an 
ingredient in tropical drinks, with the caipirinha being the most famous cocktail. In Brazil, caipirinha is often paired
with the dish feijoada. (Source: [Wikipedia](https://en.wikipedia.org/wiki/Cacha%C3%A7a)).

Cachaca is an opinionated gRPC/gRPC-web/REST/HTTP server. The server is intended to handle the heavy lifting of server
configuration and handling authorization with a pluggable interface.
- gRPC, gRPC-web, REST and HTTP are multiplexed onto a single port
- Authorizer middleware supports modular support for a variety of authorization types
  - mTLS authorizer supports client certificate based authorization
  - OAuth/OIDC authorizer supports interoperability with an IdP
- Consistent logging by forcing all logs through a single [zerolog](https://github.com/rs/zerolog) logger

While being opinionated in the implementation, the intention is to stay as consistent and close to standards and best
practices as possible.


## Under the hood
Because cachaca is intended to simplify implementation of gRPC/gRPC-web/REST services it is based on a variety of libraries:
- [gin-gonic/gin](https://pkg.go.dev/github.com/gin-gonic/gin) for handling HTTP and REST
- [google.golang.org/grpc](https://pkg.go.dev/google.golang.org/grpc) for handling gRPC requests
- [improbable-eng/grpc-web](https://pkg.go.dev/github.com/improbable-eng/grpc-web/go/grpcweb?utm_source=godoc) for proxying gRPC-web requests to gRPC
- [zitadel/oidc](https://pkg.go.dev/github.com/zitadel/oidc) for handling the OIDC authorization
- [go-jose/go-jose](https://pkg.go.dev/gopkg.in/go-jose/go-jose.v2/jwt?utm_source=godoc) for handling JWTs


## Initializing the server
A minimal example to run the server works is provided. As can be seen, the server object can be used directly in order
to register HTTP and gRPC endpoints.

Please note that gRPC-web is simply a proxy to gRPC so there is no additional setup necessary.

Example:
```go
server, _ := NewServer()
l, _ := net.Listen("tcp", fmt.Sprintf(":%d", 0))

server.GET("/ping", func(context *gin.Context) {
    context.String(http.StatusOK, "pong")
})

if err := server.Serve(l); err != nil {
	panic(err)
}
```

## Using an authorizer
The authorizers can register themselves with the server and shall be passed to the server on initialization.
The provided example uses the OIDC authorizer implementation - but the other implementations work similar.

Example:
```go
// Prepare the OAuth/OIDC authorizer
provider, _ := rp.NewRelyingPartyOIDC("issuer", "clientId", "clientSecret", "http://localhost:8443/oidc/authorize", []string{"openid"})
signingKey := &jose.SigningKey{Algorithm: jose.HS256, Key: []byte(uuid.NewString())}

authorizer := oidc.NewAuthorizer(signingKey)
authorizer.RegisterRelyingParty("test", provider)

server, _ := NewServer(authorizer)
l, _ := net.Listen("tcp", ":8443")

if err := server.Serve(l); err != nil {
	panic(err)
}
```


## Accessing the credentials from the environment
[auth/auth.go](https://github.com/unsafesystems/cachaca/auth/auth.go) exposes the `auth.GetCredentials` function which
allows access to the credentials from the authorizer middleware from the `*gin.Context` variable in HTTP requests and 
`context.Context` variable in gRPC requests.

Each authorizer middleware ships with its own Credentials object which must be used to retrieve the credentials.

Example:
```go
func (s *Service) CommonName(ctx context.Context, _ *CommonNameRequest) (*CommonNameResponse, error) {
	commonName, ok := auth.GetCredentials[string](ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no credentials found")
	}

	return &CommonNameResponse{CommonName: *commonName}, nil
}
```


## TODOs
- [ ] Setting cookies in gRPC-web: https://github.com/improbable-eng/grpc-web/issues/833
- [ ] Support PKCE with OIDC
- [ ] Adhere to the Listen, Run, Stop interface from rpcserve
- [ ] Logger / Error pkg compatibility
- [ ] Make server props private
- [ ] Transparent Re-Auth as implemented might be insecure?
- [ ] Chainable authentication mechanisms


## OIDC
The server provides an implementation to support deployments where OIDC is being used 

Information and design decisions about the OIDC implementation are summarized below. They are largely based on the
following documents - have a read - it's probably worth it:
- [Best Practices - OAuth for Single Page Apps [curity.io]](https://curity.io/resources/learn/spa-best-practices/)
- [OAuth 2.0 for Browser-Based Apps [ietf.org]](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#section-6.2)
- [Authorization Code Flow with Proof Key for Code Exchange [auth0.com]](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce)
- [Proof Key for Code Exchange by OAuth Public Clients [ietf.org]](https://datatracker.ietf.org/doc/html/rfc7636)


### BFF (Backend for Frontend)-style proxy for SPAs (Single Page Apps)
The browser is a hostile place to execute code, and implementing security is a difficult area of SPA development.
We therefore implement an adoption of the BFF (Backend for Frontend) pattern for SPAs according to the
[IETF Draft "OAuth 2.0 for Browser-Based Apps" Section 6.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#section-6.2).
Access Tokens and Refresh Tokens are kept secured on the server while a traditional cookie based session is initialized
with the browser. The Cookie can be a secure http-only implementation, further reducing the attack surface. 

The Cachaca OIDC Authorizer has the ability to execute code and handle the full OAuth flow itself. This enables the 
ability to keep the request to obtain an access token outside the JavaScript application. 

The JavaScript code is loaded from a CDN or other hosting server (A). Cachaca will initialize the OAuth flow itself, by 
redirecting the browser to the authorization endpoint (B). When the user is redirected back, the browser delivers the 
authorization code that will be incercepted by Cachaca (C), where it can be exchanged for an access token at the token 
endpoint (D) using its client secret and PKCE code verifier. Cachaca then keeps the access token and refresh token 
stored internally, and creates a separate session with the browser-based app via a traditional browser cookie (E).

When the JavaScript application in the browser wants to make a request to the User Application, requests are proxied
through Cachaca (F), and Cachaca will make the request with the access token to the User Application (G), and forward
the response (H) back to the browser.

In this case, Cachaca IS considered a confidential client, and issued its own client secret. It will use the OAuth 2.0 
Authorization Code grant with PKCE to initiate a request for an access token. The connection between the browser and 
Cachaca IS a session cookie provided by Cachaca.

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐
│             │  │             │  │             │  │              │
│     CDN     │  │Authorization│  │    Token    │  │     User     │
│             │  │  Endpoint   │  │  Endpoint   │  │ Application  │
│             │  │             │  │             │  │              │
└─────────────┘  └─────────────┘  └─────────────┘  └──────────────┘
       ▲                ▲                ▲                  ▲
       │                │                │                  │
       │                │               (D)                (G)
       │                │                │                  │
       │                │                ▼                  │
       │                │          ┌────────────────────────┴─────┐
       │                │          │                              │
      (A)              (B)         │           Cachaca            │
       │                │          │     Authorizer / Library     │
       │                │          │                              │
       │                │          └────────┬──────────────────┬──┘
       │                │             ▲     │            ▲     │
       │                │             │     │            │     │
       │                │            (C)   (E)          (F)   (H)
       │                │             │     │            │     │
       ▼                ▼             │     ▼            │     ▼
┌─────────────────────────────────────┴──────────────────┴────────┐
│                                                                 │
│                           BROWSER                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```


### Access Token Introspection
In the case of Mobile (Native) applications we no longer have the problem of inherent insecure storage of tokens such as
in SPAs. Therefore, the process is much more straight forward than in the SPA case.

We expect the native client to obtain a valid access token and refresh token using the OAuth 2.0 Authorization Code 
grant with PKCE. Cachaca will introspect the access token using the Introspection Endpoint as defined by OIDC. A
storage backend can temporarily store the introspection result to reduce the impact on performance and uptime the
introspection process may have.

Overview of the OAuth 2.0 Authorization Code grant with PKCE as we implemented it:
```
          ┌────────────────┐         ┌───────────────┐         ┌───────────────┐          ┌───────────────┐
          │                │         │               │         │               │          │               │
          │       APP      │         │  OIDC Server  │         │    Cachaca    │          │   User App    │
          │                │         │               │         │               │          │               │
          └────────┬───────┘         └───────┬───────┘         └───────┬───────┘          └───────┬───────┘
                   │                         │                         │                          │
  Initiate Login   │                         │                         │                          │
──────────────────►│                         │                         │                          │
                   │                         │                         │                          │
                  ┌┼┐                        │                         │                          │
 Generate         │┼┼──┐                     │                         │                          │
    t = nonce     │┼│  │                     │                         │                          │
  t_m = sha256(t) │┼┤◄─┘                     │                         │                          │
                  └┼┘                        │                         │                          │
                   │                         │                         │                          │
                   │ Authorization Code Req. │                         │                          │
                   ├────────────────────────►│                         │                          │
                   │ + t_m to /authorize     │                         │                          │
                   │                        ┌┼┐                        │                          │
                   │                        │┼┼──┐ Handle Login        │                          │
                   │                        │┼│  │ (e.g. Password,     │                          │
                   │                        │┼┤◄─┘ Phone, etc.)        │                          │
                   │                        └┼┘                        │                          │
                   │  Authorization Code     │                         │                          │
                   │◄────────────────────────┤                         │                          │
                   │                         │                         │                          │
                   │ Authorization Code + t  │                         │                          │
                   ├────────────────────────►│                         │                          │
                   │                         │                         │                          │
                   │ access, refresh token   │                         │                          │
                   │◄────────────────────────┤                         │                          │
                   │                         │                         │                          │
                   │         Resource Request + access token           │                          │
                   ├─────────────────────────┬────────────────────────►│                          │
                   │                         │                         │                          │
                   │                         │ Introspect access token │                          │
                   │                         │◄────────────────────────┤                          │
                   │                         │                         │                          │
                   │                         │ user_id, etc.           │                          │
                   │                         ├────────────────────────►│                          │
                   │                         │                         │                          │
                   │                                                   │Resource Request (user_id)│
                   │                                                   ├─────────────────────────►│
                   │                                                   │                          │
                   │                Resource Response                  │                          │
                   │◄──────────────────────────────────────────────────┤◄─────────────────────────┤
                   │                                                   │                          │
```
