//nolint
package oidc

import (
	"context"
	"github.com/google/uuid"
	"github.com/redis/rueidis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
	"testing"
	"time"
)

func TestStorageTestSuite(t *testing.T) {
	suite.Run(t, new(StorageTestSuite))
}

type StorageTestSuite struct {
	suite.Suite
	storage []Storage
}

func (s *StorageTestSuite) SetupSuite() {
	s.storage = make([]Storage, 0)

	// In-Memory storage
	s.storage = append(s.storage, NewMemoryStorage())

	// Redis storage
	client, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress: []string{"127.0.0.1:6379"},
	})
	require.NoError(s.T(), err)
	s.storage = append(s.storage, NewRedisStorage(client, time.Minute))
}

func (s *StorageTestSuite) TestNotFound() {
	for _, storage := range s.storage {
		id := uuid.NewString()
		res, err := storage.Get(context.Background(), id)
		assert.ErrorIs(s.T(), err, ErrNotFound)
		assert.Nil(s.T(), res)
	}
}

func (s *StorageTestSuite) TestHappyPath() {
	for _, storage := range s.storage {
		id := uuid.NewString()
		session := &Session{
			ID: id,
			Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
				Token: &oauth2.Token{
					AccessToken: "foo",
				},
			},
		}

		err := storage.Set(context.Background(), session)
		assert.NoError(s.T(), err)

		res, err := storage.Get(context.Background(), id)
		assert.NoError(s.T(), err)
		assert.Equal(s.T(), "foo", res.AccessToken)

		err = storage.Delete(context.Background(), id)
		assert.NoError(s.T(), err)
		res, err = storage.Get(context.Background(), id)
		assert.ErrorIs(s.T(), err, ErrNotFound)
	}
}

func (s *StorageTestSuite) TestDeleteNotFound() {
	for _, storage := range s.storage {
		err := storage.Delete(context.Background(), uuid.NewString())
		assert.NoError(s.T(), err)
	}
}

// MockStorage is an autogenerated mock type for the MockStorage type
type MockStorage struct {
	mock.Mock
}

// Delete provides a mock function with given fields: ctx, sessionID
func (_m *MockStorage) Delete(ctx context.Context, sessionID string) error {
	ret := _m.Called(ctx, sessionID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, sessionID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Get provides a mock function with given fields: ctx, sessionID
func (_m *MockStorage) Get(ctx context.Context, sessionID string) (*Session, error) {
	ret := _m.Called(ctx, sessionID)

	var r0 *Session
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*Session, error)); ok {
		return rf(ctx, sessionID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *Session); ok {
		r0 = rf(ctx, sessionID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Session)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, sessionID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Set provides a mock function with given fields: ctx, session
func (_m *MockStorage) Set(ctx context.Context, session *Session) error {
	ret := _m.Called(ctx, session)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *Session) error); ok {
		r0 = rf(ctx, session)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewStorage interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockStorage creates a new instance of MockStorage. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockStorage(t mockConstructorTestingTNewStorage) *MockStorage {
	mock := &MockStorage{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
