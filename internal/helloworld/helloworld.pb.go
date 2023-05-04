// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.20.3
// source: internal/helloworld/helloworld.proto

package helloworld

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message string `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *PingRequest) Reset() {
	*x = PingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_helloworld_helloworld_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingRequest) ProtoMessage() {}

func (x *PingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_internal_helloworld_helloworld_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingRequest.ProtoReflect.Descriptor instead.
func (*PingRequest) Descriptor() ([]byte, []int) {
	return file_internal_helloworld_helloworld_proto_rawDescGZIP(), []int{0}
}

func (x *PingRequest) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

type PongResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message string `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *PongResponse) Reset() {
	*x = PongResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_helloworld_helloworld_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PongResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PongResponse) ProtoMessage() {}

func (x *PongResponse) ProtoReflect() protoreflect.Message {
	mi := &file_internal_helloworld_helloworld_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PongResponse.ProtoReflect.Descriptor instead.
func (*PongResponse) Descriptor() ([]byte, []int) {
	return file_internal_helloworld_helloworld_proto_rawDescGZIP(), []int{1}
}

func (x *PongResponse) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

type CommonNameRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *CommonNameRequest) Reset() {
	*x = CommonNameRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_helloworld_helloworld_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CommonNameRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CommonNameRequest) ProtoMessage() {}

func (x *CommonNameRequest) ProtoReflect() protoreflect.Message {
	mi := &file_internal_helloworld_helloworld_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CommonNameRequest.ProtoReflect.Descriptor instead.
func (*CommonNameRequest) Descriptor() ([]byte, []int) {
	return file_internal_helloworld_helloworld_proto_rawDescGZIP(), []int{2}
}

type CommonNameResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CommonName string `protobuf:"bytes,1,opt,name=common_name,json=commonName,proto3" json:"common_name,omitempty"`
}

func (x *CommonNameResponse) Reset() {
	*x = CommonNameResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_helloworld_helloworld_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CommonNameResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CommonNameResponse) ProtoMessage() {}

func (x *CommonNameResponse) ProtoReflect() protoreflect.Message {
	mi := &file_internal_helloworld_helloworld_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CommonNameResponse.ProtoReflect.Descriptor instead.
func (*CommonNameResponse) Descriptor() ([]byte, []int) {
	return file_internal_helloworld_helloworld_proto_rawDescGZIP(), []int{3}
}

func (x *CommonNameResponse) GetCommonName() string {
	if x != nil {
		return x.CommonName
	}
	return ""
}

type PanicRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PanicRequest) Reset() {
	*x = PanicRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_helloworld_helloworld_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PanicRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PanicRequest) ProtoMessage() {}

func (x *PanicRequest) ProtoReflect() protoreflect.Message {
	mi := &file_internal_helloworld_helloworld_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PanicRequest.ProtoReflect.Descriptor instead.
func (*PanicRequest) Descriptor() ([]byte, []int) {
	return file_internal_helloworld_helloworld_proto_rawDescGZIP(), []int{4}
}

type PanicResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *PanicResponse) Reset() {
	*x = PanicResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_helloworld_helloworld_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PanicResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PanicResponse) ProtoMessage() {}

func (x *PanicResponse) ProtoReflect() protoreflect.Message {
	mi := &file_internal_helloworld_helloworld_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PanicResponse.ProtoReflect.Descriptor instead.
func (*PanicResponse) Descriptor() ([]byte, []int) {
	return file_internal_helloworld_helloworld_proto_rawDescGZIP(), []int{5}
}

var File_internal_helloworld_helloworld_proto protoreflect.FileDescriptor

var file_internal_helloworld_helloworld_proto_rawDesc = []byte{
	0x0a, 0x24, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
	0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2f, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x6f, 0x72, 0x6c, 0x64,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x75,
	0x6e, 0x73, 0x61, 0x66, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2e, 0x63, 0x61, 0x63,
	0x68, 0x61, 0x63, 0x61, 0x22, 0x27, 0x0a, 0x0b, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x28, 0x0a,
	0x0c, 0x50, 0x6f, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a,
	0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x13, 0x0a, 0x11, 0x43, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x35, 0x0a, 0x12,
	0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x4e,
	0x61, 0x6d, 0x65, 0x22, 0x0e, 0x0a, 0x0c, 0x50, 0x61, 0x6e, 0x69, 0x63, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x22, 0x0f, 0x0a, 0x0d, 0x50, 0x61, 0x6e, 0x69, 0x63, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x32, 0xbe, 0x02, 0x0a, 0x0a, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x57, 0x6f,
	0x72, 0x6c, 0x64, 0x12, 0x5d, 0x0a, 0x04, 0x50, 0x69, 0x6e, 0x67, 0x12, 0x29, 0x2e, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x75, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65,
	0x6d, 0x73, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x61, 0x63, 0x61, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2a, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x75, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2e, 0x63, 0x61,
	0x63, 0x68, 0x61, 0x63, 0x61, 0x2e, 0x50, 0x6f, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x6f, 0x0a, 0x0a, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x4e, 0x61, 0x6d, 0x65,
	0x12, 0x2f, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x75, 0x6e, 0x73, 0x61, 0x66, 0x65,
	0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x61, 0x63, 0x61, 0x2e,
	0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x30, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x75, 0x6e, 0x73, 0x61, 0x66,
	0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x61, 0x63, 0x61,
	0x2e, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x60, 0x0a, 0x05, 0x50, 0x61, 0x6e, 0x69, 0x63, 0x12, 0x2a, 0x2e, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x75, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x73, 0x79, 0x73, 0x74,
	0x65, 0x6d, 0x73, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x61, 0x63, 0x61, 0x2e, 0x50, 0x61, 0x6e, 0x69,
	0x63, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2b, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x75, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2e,
	0x63, 0x61, 0x63, 0x68, 0x61, 0x63, 0x61, 0x2e, 0x50, 0x61, 0x6e, 0x69, 0x63, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x2d, 0x5a, 0x2b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x75, 0x6e, 0x73, 0x61, 0x66, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d,
	0x73, 0x2f, 0x63, 0x61, 0x63, 0x68, 0x61, 0x63, 0x61, 0x2f, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x77,
	0x6f, 0x72, 0x6c, 0x64, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_internal_helloworld_helloworld_proto_rawDescOnce sync.Once
	file_internal_helloworld_helloworld_proto_rawDescData = file_internal_helloworld_helloworld_proto_rawDesc
)

func file_internal_helloworld_helloworld_proto_rawDescGZIP() []byte {
	file_internal_helloworld_helloworld_proto_rawDescOnce.Do(func() {
		file_internal_helloworld_helloworld_proto_rawDescData = protoimpl.X.CompressGZIP(file_internal_helloworld_helloworld_proto_rawDescData)
	})
	return file_internal_helloworld_helloworld_proto_rawDescData
}

var file_internal_helloworld_helloworld_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_internal_helloworld_helloworld_proto_goTypes = []interface{}{
	(*PingRequest)(nil),        // 0: github.unsafesystems.cachaca.PingRequest
	(*PongResponse)(nil),       // 1: github.unsafesystems.cachaca.PongResponse
	(*CommonNameRequest)(nil),  // 2: github.unsafesystems.cachaca.CommonNameRequest
	(*CommonNameResponse)(nil), // 3: github.unsafesystems.cachaca.CommonNameResponse
	(*PanicRequest)(nil),       // 4: github.unsafesystems.cachaca.PanicRequest
	(*PanicResponse)(nil),      // 5: github.unsafesystems.cachaca.PanicResponse
}
var file_internal_helloworld_helloworld_proto_depIdxs = []int32{
	0, // 0: github.unsafesystems.cachaca.HelloWorld.Ping:input_type -> github.unsafesystems.cachaca.PingRequest
	2, // 1: github.unsafesystems.cachaca.HelloWorld.CommonName:input_type -> github.unsafesystems.cachaca.CommonNameRequest
	4, // 2: github.unsafesystems.cachaca.HelloWorld.Panic:input_type -> github.unsafesystems.cachaca.PanicRequest
	1, // 3: github.unsafesystems.cachaca.HelloWorld.Ping:output_type -> github.unsafesystems.cachaca.PongResponse
	3, // 4: github.unsafesystems.cachaca.HelloWorld.CommonName:output_type -> github.unsafesystems.cachaca.CommonNameResponse
	5, // 5: github.unsafesystems.cachaca.HelloWorld.Panic:output_type -> github.unsafesystems.cachaca.PanicResponse
	3, // [3:6] is the sub-list for method output_type
	0, // [0:3] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_internal_helloworld_helloworld_proto_init() }
func file_internal_helloworld_helloworld_proto_init() {
	if File_internal_helloworld_helloworld_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_internal_helloworld_helloworld_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PingRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_helloworld_helloworld_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PongResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_helloworld_helloworld_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CommonNameRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_helloworld_helloworld_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CommonNameResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_helloworld_helloworld_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PanicRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_internal_helloworld_helloworld_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PanicResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_internal_helloworld_helloworld_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_internal_helloworld_helloworld_proto_goTypes,
		DependencyIndexes: file_internal_helloworld_helloworld_proto_depIdxs,
		MessageInfos:      file_internal_helloworld_helloworld_proto_msgTypes,
	}.Build()
	File_internal_helloworld_helloworld_proto = out.File
	file_internal_helloworld_helloworld_proto_rawDesc = nil
	file_internal_helloworld_helloworld_proto_goTypes = nil
	file_internal_helloworld_helloworld_proto_depIdxs = nil
}
