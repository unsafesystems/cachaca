//nolint:ireturn
package oidc

type URLOptions struct {
	loginURL    string
	callbackURL string
	logoutURL   string
	errorURL    string
	successURL  string
}

func (o *URLOptions) apply(authorizer *Authorizer) {
	if o.loginURL != "" {
		authorizer.loginURL = o.loginURL
	}

	if o.callbackURL != "" {
		authorizer.callbackURL = o.callbackURL
	}

	if o.logoutURL != "" {
		authorizer.logoutURL = o.logoutURL
	}

	if o.errorURL != "" {
		authorizer.errorURL = o.errorURL
	}

	if o.successURL != "" {
		authorizer.successURL = o.successURL
	}
}

func WithLoginURL(url string) Option {
	return &URLOptions{
		loginURL: url,
	}
}

func WithCallbackURL(url string) Option {
	return &URLOptions{
		callbackURL: url,
	}
}

func WithLogoutURL(url string) Option {
	return &URLOptions{
		logoutURL: url,
	}
}

func WithErrorURL(url string) Option {
	return &URLOptions{
		errorURL: url,
	}
}

func WithSuccessURL(url string) Option {
	return &URLOptions{
		successURL: url,
	}
}

type TokenCallBackOptions struct {
	tokenCallback SessionCallbackFunc
}

func (o *TokenCallBackOptions) apply(authorizer *Authorizer) {
	if o.tokenCallback != nil {
		authorizer.sessionCallback = o.tokenCallback
	}
}

func WithTokenCallback(tokenCallback SessionCallbackFunc) Option {
	return &TokenCallBackOptions{
		tokenCallback: tokenCallback,
	}
}

type StorageOptions struct {
	storage Storage
}

func (o *StorageOptions) apply(authorizer *Authorizer) {
	if o.storage != nil {
		authorizer.storage = o.storage
	}
}

func WithStorage(storage Storage) Option {
	return &StorageOptions{
		storage: storage,
	}
}
