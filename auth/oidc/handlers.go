package oidc

import (
	"context"
	"errors"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/gin-gonic/gin"
	"github.com/unsafesystems/cachaca/auth/oidc/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (az *Authorizer) GetAuthURL(ctx context.Context, _ *pb.GetAuthURLRequest) (*pb.GetAuthURLResponse, error) {
	url, err := az.authURL(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate auth url")
	}

	return &pb.GetAuthURLResponse{Url: url}, nil
}

func (az *Authorizer) GetAuthURLHTTP(ctx *gin.Context) {
	url, err := az.authURL(ctx)
	if err != nil {
		handleErrorHTTP(ctx, err)

		return
	}

	ctx.JSON(http.StatusOK, pb.GetAuthURLResponse{Url: url})
}

func (az *Authorizer) ExchangeCode(ctx context.Context, in *pb.ExchangeCodeRequest) (*pb.ExchangeCodeResponse, error) {
	//nolint:contextcheck
	err := az.exchangeCode(ctx, in)
	if err != nil {
		return nil, handleErrorGRPC(err)
	}

	return &pb.ExchangeCodeResponse{}, nil
}

func (az *Authorizer) ExchangeCodeHTTP(ctx *gin.Context) {
	var req pb.ExchangeCodeRequest

	err := ctx.BindJSON(&req)
	if err != nil {
		handleErrorHTTP(ctx, err)

		return
	}

	err = az.exchangeCode(ctx, &req)
	if err != nil {
		handleErrorHTTP(ctx, err)

		return
	}

	ctx.JSON(http.StatusOK, &pb.ExchangeCodeResponse{})
}

func (az *Authorizer) RefreshToken(ctx context.Context, _ *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	//nolint:contextcheck
	err := az.refreshToken(ctx)
	if err != nil {
		return nil, handleErrorGRPC(err)
	}

	return &pb.RefreshTokenResponse{}, nil
}

func (az *Authorizer) RefreshTokenHTTP(ctx *gin.Context) {
	req := new(pb.RefreshTokenRequest)

	err := ctx.BindJSON(req)
	if err != nil {
		handleErrorHTTP(ctx, err)

		return
	}

	err = az.refreshToken(ctx)
	if err != nil {
		handleErrorHTTP(ctx, err)

		return
	}

	ctx.JSON(http.StatusOK, &pb.RefreshTokenResponse{})
}

func (az *Authorizer) ExchangeToken(ctx context.Context, in *pb.ExchangeTokenRequest,
) (*pb.ExchangeTokenResponse, error) {
	res, err := az.exchangeToken(ctx, in)
	if err != nil {
		return nil, handleErrorGRPC(err)
	}

	return res, nil
}

func (az *Authorizer) ExchangeTokenHTTP(ctx *gin.Context) {
	req := new(pb.ExchangeTokenRequest)

	err := ctx.BindJSON(req)
	if err != nil {
		handleErrorHTTP(ctx, err)

		return
	}

	res, err := az.exchangeToken(ctx, req)
	if err != nil {
		handleErrorHTTP(ctx, err)

		return
	}

	ctx.JSON(http.StatusOK, res)
}

func handleErrorHTTP(ctx *gin.Context, err error) {
	if errors.Is(err, ErrBadRequest) {
		log.Warn().Err(err).Msg("bad request")

		_ = ctx.AbortWithError(http.StatusBadRequest, ErrBadRequest)

		return
	}

	log.Err(err).Msg("internal error")

	_ = ctx.AbortWithError(http.StatusInternalServerError, ErrInternal)
}

func handleErrorGRPC(err error) error {
	if errors.Is(err, ErrBadRequest) {
		log.Warn().Err(err).Msg("bad request")

		return status.Error(codes.InvalidArgument, "bad request")
	}

	log.Err(err).Msg("internal error")

	return status.Error(codes.Internal, "internal error")
}
