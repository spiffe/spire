package middleware

import "context"

func AuthorizeAny() Authorizer {
	return anyAuthorizer{}
}

type anyAuthorizer struct{}

func (a anyAuthorizer) Name() string {
	return "any"
}

func (a anyAuthorizer) AuthorizeCaller(ctx context.Context) (context.Context, error) {
	return ctx, nil
}
