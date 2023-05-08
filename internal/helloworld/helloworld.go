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
	commonName, ok := auth.GetCreds[string](ctx)
	if !ok || commonName == nil {
		return nil, status.Error(codes.Unauthenticated, "no credentials found")
	}

	return &CommonNameResponse{CommonName: *commonName}, nil
}

func (s *Service) Panic(_ context.Context, _ *PanicRequest) (*PanicResponse, error) {
	panic("this is a panic")
}
