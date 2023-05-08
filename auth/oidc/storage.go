package oidc

import (
	"context"
	"errors"

	"github.com/zitadel/oidc/v2/pkg/oidc"
)

var ErrNotFound = errors.New("not found")

type Storage interface {
	Get(ctx context.Context, sessionID string) (*oidc.Tokens[*oidc.IDTokenClaims], error)
	Set(ctx context.Context, sessionID string, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error
	Delete(ctx context.Context, sessionID string) error
}

type MemoryStorage struct {
	tokens map[string]*oidc.Tokens[*oidc.IDTokenClaims]
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		tokens: make(map[string]*oidc.Tokens[*oidc.IDTokenClaims]),
	}
}

func (s *MemoryStorage) Get(_ context.Context, sessionID string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	if tokens, ok := s.tokens[sessionID]; ok {
		return tokens, nil
	}

	return nil, ErrNotFound
}

func (s *MemoryStorage) Set(_ context.Context, sessionID string, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	s.tokens[sessionID] = tokens

	return nil
}

func (s *MemoryStorage) Delete(_ context.Context, sessionID string) error {
	delete(s.tokens, sessionID)

	return nil
}
