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
