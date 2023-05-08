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
	tokenCallback TokenCallback
}

func (o *TokenCallBackOptions) apply(authorizer *Authorizer) {
	if o.tokenCallback != nil {
		authorizer.tokenCallback = o.tokenCallback
	}
}

func WithTokenCallback(tokenCallback TokenCallback) Option {
	return &TokenCallBackOptions{
		tokenCallback: tokenCallback,
	}
}
