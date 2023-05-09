package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3/json"
	"github.com/redis/rueidis"
)

var ErrNotFound = errors.New("not found")

type Storage interface {
	Get(ctx context.Context, sessionID string) (*Session, error)
	Set(ctx context.Context, session *Session) error
	Delete(ctx context.Context, sessionID string) error
}

type MemoryStorage struct {
	tokens map[string]string
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		tokens: make(map[string]string),
	}
}

func (s *MemoryStorage) Get(_ context.Context, sessionID string) (*Session, error) {
	if tokens, ok := s.tokens[sessionID]; ok {
		res := new(Session)

		err := json.Unmarshal([]byte(tokens), res)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal token: %w", err)
		}

		return res, nil
	}

	return nil, ErrNotFound
}

func (s *MemoryStorage) Set(_ context.Context, session *Session) error {
	val, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to encode tokens: %w", err)
	}

	s.tokens[session.ID] = string(val)

	return nil
}

func (s *MemoryStorage) Delete(_ context.Context, sessionID string) error {
	delete(s.tokens, sessionID)

	return nil
}

type RedisStorage struct {
	client       rueidis.Client
	cacheTimeout time.Duration
}

func NewRedisStorage(client rueidis.Client, cacheTimeout time.Duration) *RedisStorage {
	return &RedisStorage{
		client:       client,
		cacheTimeout: cacheTimeout,
	}
}

func (s *RedisStorage) Get(ctx context.Context, sessionID string) (*Session, error) {
	cmd := s.client.B().Get().Key(sessionID).Cache()

	res := s.client.DoCache(ctx, cmd, s.cacheTimeout)
	if res.Error() != nil {
		if rueidis.IsRedisNil(res.Error()) {
			return nil, ErrNotFound
		}

		return nil, fmt.Errorf("failed to get token: %w", res.Error())
	}

	tokens := new(Session)

	err := res.DecodeJSON(tokens)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tokens: %w", err)
	}

	return tokens, nil
}

func (s *RedisStorage) Set(ctx context.Context, session *Session) error {
	val, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to encode tokens: %w", err)
	}

	cmd := s.client.B().Set().Key(session.ID).Value(string(val)).Build()

	res := s.client.Do(ctx, cmd)
	if res.Error() != nil {
		return fmt.Errorf("failed to set token: %w", res.Error())
	}

	return nil
}

func (s *RedisStorage) Delete(ctx context.Context, sessionID string) error {
	cmd := s.client.B().Del().Key(sessionID).Build()

	res := s.client.Do(ctx, cmd)
	if res.Error() != nil {
		return fmt.Errorf("failed to delete token: %w", res.Error())
	}

	return nil
}
