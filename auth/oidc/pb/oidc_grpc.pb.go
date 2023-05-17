// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.20.3
// source: auth/oidc/pb/oidc.proto

package pb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	OIDC_GetAuthURL_FullMethodName    = "/cachaca.authentication.v1.OIDC/GetAuthURL"
	OIDC_ExchangeCode_FullMethodName  = "/cachaca.authentication.v1.OIDC/ExchangeCode"
	OIDC_RefreshToken_FullMethodName  = "/cachaca.authentication.v1.OIDC/RefreshToken"
	OIDC_ExchangeToken_FullMethodName = "/cachaca.authentication.v1.OIDC/ExchangeToken"
)

// OIDCClient is the client API for OIDC service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type OIDCClient interface {
	GetAuthURL(ctx context.Context, in *GetAuthURLRequest, opts ...grpc.CallOption) (*GetAuthURLResponse, error)
	ExchangeCode(ctx context.Context, in *ExchangeCodeRequest, opts ...grpc.CallOption) (*ExchangeCodeResponse, error)
	RefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...grpc.CallOption) (*RefreshTokenResponse, error)
	ExchangeToken(ctx context.Context, in *ExchangeTokenRequest, opts ...grpc.CallOption) (*ExchangeTokenResponse, error)
}

type oIDCClient struct {
	cc grpc.ClientConnInterface
}

func NewOIDCClient(cc grpc.ClientConnInterface) OIDCClient {
	return &oIDCClient{cc}
}

func (c *oIDCClient) GetAuthURL(ctx context.Context, in *GetAuthURLRequest, opts ...grpc.CallOption) (*GetAuthURLResponse, error) {
	out := new(GetAuthURLResponse)
	err := c.cc.Invoke(ctx, OIDC_GetAuthURL_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oIDCClient) ExchangeCode(ctx context.Context, in *ExchangeCodeRequest, opts ...grpc.CallOption) (*ExchangeCodeResponse, error) {
	out := new(ExchangeCodeResponse)
	err := c.cc.Invoke(ctx, OIDC_ExchangeCode_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oIDCClient) RefreshToken(ctx context.Context, in *RefreshTokenRequest, opts ...grpc.CallOption) (*RefreshTokenResponse, error) {
	out := new(RefreshTokenResponse)
	err := c.cc.Invoke(ctx, OIDC_RefreshToken_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oIDCClient) ExchangeToken(ctx context.Context, in *ExchangeTokenRequest, opts ...grpc.CallOption) (*ExchangeTokenResponse, error) {
	out := new(ExchangeTokenResponse)
	err := c.cc.Invoke(ctx, OIDC_ExchangeToken_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// OIDCServer is the server API for OIDC service.
// All implementations must embed UnimplementedOIDCServer
// for forward compatibility
type OIDCServer interface {
	GetAuthURL(context.Context, *GetAuthURLRequest) (*GetAuthURLResponse, error)
	ExchangeCode(context.Context, *ExchangeCodeRequest) (*ExchangeCodeResponse, error)
	RefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenResponse, error)
	ExchangeToken(context.Context, *ExchangeTokenRequest) (*ExchangeTokenResponse, error)
	mustEmbedUnimplementedOIDCServer()
}

// UnimplementedOIDCServer must be embedded to have forward compatible implementations.
type UnimplementedOIDCServer struct {
}

func (UnimplementedOIDCServer) GetAuthURL(context.Context, *GetAuthURLRequest) (*GetAuthURLResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAuthURL not implemented")
}
func (UnimplementedOIDCServer) ExchangeCode(context.Context, *ExchangeCodeRequest) (*ExchangeCodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ExchangeCode not implemented")
}
func (UnimplementedOIDCServer) RefreshToken(context.Context, *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RefreshToken not implemented")
}
func (UnimplementedOIDCServer) ExchangeToken(context.Context, *ExchangeTokenRequest) (*ExchangeTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ExchangeToken not implemented")
}
func (UnimplementedOIDCServer) mustEmbedUnimplementedOIDCServer() {}

// UnsafeOIDCServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to OIDCServer will
// result in compilation errors.
type UnsafeOIDCServer interface {
	mustEmbedUnimplementedOIDCServer()
}

func RegisterOIDCServer(s grpc.ServiceRegistrar, srv OIDCServer) {
	s.RegisterService(&OIDC_ServiceDesc, srv)
}

func _OIDC_GetAuthURL_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAuthURLRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OIDCServer).GetAuthURL(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OIDC_GetAuthURL_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OIDCServer).GetAuthURL(ctx, req.(*GetAuthURLRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OIDC_ExchangeCode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExchangeCodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OIDCServer).ExchangeCode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OIDC_ExchangeCode_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OIDCServer).ExchangeCode(ctx, req.(*ExchangeCodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OIDC_RefreshToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RefreshTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OIDCServer).RefreshToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OIDC_RefreshToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OIDCServer).RefreshToken(ctx, req.(*RefreshTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OIDC_ExchangeToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExchangeTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OIDCServer).ExchangeToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: OIDC_ExchangeToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OIDCServer).ExchangeToken(ctx, req.(*ExchangeTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// OIDC_ServiceDesc is the grpc.ServiceDesc for OIDC service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var OIDC_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "cachaca.authentication.v1.OIDC",
	HandlerType: (*OIDCServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAuthURL",
			Handler:    _OIDC_GetAuthURL_Handler,
		},
		{
			MethodName: "ExchangeCode",
			Handler:    _OIDC_ExchangeCode_Handler,
		},
		{
			MethodName: "RefreshToken",
			Handler:    _OIDC_RefreshToken_Handler,
		},
		{
			MethodName: "ExchangeToken",
			Handler:    _OIDC_ExchangeToken_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "auth/oidc/pb/oidc.proto",
}