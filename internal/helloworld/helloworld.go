package helloworld

import (
	"context"

	"github.com/unsafesystems/cachaca/auth"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	UnimplementedHelloWorldServer
}

func (s *Service) Ping(_ context.Context, _ *PingRequest) (*PongResponse, error) {
	return &PongResponse{Message: "pong"}, nil
}

func (s *Service) CommonName(ctx context.Context, _ *CommonNameRequest) (*CommonNameResponse, error) {
	creds, ok := auth.GetCreds[auth.Credentials](ctx)
	if !ok || len(creds.Certificates) < 1 {
		return nil, status.Error(codes.Unauthenticated, "no credentials found")
	}

	cert := creds.Certificates[0]
	commonName := cert.Subject.CommonName

	return &CommonNameResponse{CommonName: commonName}, nil
}

func (s *Service) Panic(_ context.Context, _ *PanicRequest) (*PanicResponse, error) {
	panic("this is a panic")
}
