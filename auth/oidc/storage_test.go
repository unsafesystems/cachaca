//nolint
package oidc

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
	"testing"
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
	s.storage = append(s.storage, NewMemoryStorage())
}

func (s *StorageTestSuite) TestNotFound() {
	for _, storage := range s.storage {
		fmt.Println(storage)
		id := uuid.NewString()
		res, err := storage.Get(context.Background(), id)
		assert.ErrorIs(s.T(), err, ErrNotFound)
		assert.Nil(s.T(), res)
	}
}

func (s *StorageTestSuite) TestHappyPath() {
	for _, storage := range s.storage {
		id := uuid.NewString()
		token := &oidc.Tokens[*oidc.IDTokenClaims]{
			Token: &oauth2.Token{
				AccessToken: "foo",
			},
		}

		err := storage.Set(context.Background(), id, token)
		assert.NoError(s.T(), err)

		res, err := storage.Get(context.Background(), id)
		assert.NoError(s.T(), err)
		assert.Equal(s.T(), token.AccessToken, res.AccessToken)

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
