package oidc

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto"
)

type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) bool
	Del(ctx context.Context, key string) bool
}

type RistrettoCache struct {
	cache *ristretto.Cache
}

func NewRistrettoCache(cache *ristretto.Cache) *RistrettoCache {
	return &RistrettoCache{cache: cache}
}

func (r *RistrettoCache) Get(_ context.Context, key string) ([]byte, bool) {
	res, ok := r.cache.Get(key)
	if !ok {
		return nil, false
	}

	val, ok := res.([]byte)

	return val, ok
}

func (r *RistrettoCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) bool {
	var res bool
	if ttl == 0 {
		res = r.cache.Set(key, value, int64(len(value)))
	} else {
		res = r.cache.SetWithTTL(key, value, int64(len(value)), ttl)
	}

	// When we are running in Test Mode we should call ristretto.Wait to ensure that the cache is populated and no data
	// is stuck in the buffer.
	if flag.Lookup("test.v") != nil {
		r.cache.Wait()
	}

	return res
}

func (r *RistrettoCache) Del(_ context.Context, key string) bool {
	r.cache.Del(key)

	return true
}

func getCacheValue[T any](ctx context.Context, cache Cache, key string) (*T, bool) {
	data, ok := cache.Get(ctx, fmt.Sprintf("%T:%s", *new(T), key))
	if !ok {
		return nil, false
	}

	res := new(T)

	err := json.Unmarshal(data, res)
	if err != nil {
		return nil, false
	}

	return res, true
}

func setCacheValue[T any](ctx context.Context, key string, cache Cache, value *T, ttl time.Duration) bool {
	data, err := json.Marshal(value)
	if err != nil {
		return false
	}

	return cache.Set(ctx, fmt.Sprintf("%T:%s", *new(T), key), data, ttl)
}

func wrapFunctionForCache[T any](ctx context.Context, key string, cache Cache, wrap func() (*T, time.Duration, error),
) (*T, error) {
	res, ok := getCacheValue[T](ctx, cache, key)
	if ok {
		return res, nil
	}

	res, ttl, err := wrap()
	if err != nil {
		return nil, err
	}

	if ttl > 0 {
		setCacheValue[T](ctx, key, cache, res, ttl)
	}

	return res, nil
}
