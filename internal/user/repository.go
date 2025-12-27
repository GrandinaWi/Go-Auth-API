package user

import "context"

type Repository interface {
	GetByID(ctx context.Context, id int64) (*User, error)
	GetByCredentials(ctx context.Context, username string, password string) (*User, error)
	Create(ctx context.Context, username string, password string, age int64) (*User, error)
	GetUserInfo(ctx context.Context, id int64) (*User, error)
}
