package user

import (
	"context"
	"errors"
)

type Service interface {
	Register(ctx context.Context, username, password string, age int64) (*User, error)
	Login(ctx context.Context, username, password string) (*User, error)
	GetUser(ctx context.Context, id int64) (*User, error)
}

type service struct {
	repo Repository
}

var ErrInvalidInput = errors.New("input null")
var ErrPasswordTooShort = errors.New("password too short")

func NewService(repo Repository) Service {
	return &service{repo: repo}
}

func (s *service) Register(ctx context.Context,
	username, password string,
	age int64,
) (*User, error) {
	if username == "" || password == "" {
		return nil, ErrInvalidInput
	}
	if len(password) < 8 {
		return nil, ErrPasswordTooShort
	}
	return s.repo.Create(ctx, username, password, age)
}
func (s *service) Login(ctx context.Context, username, password string) (*User, error) {
	if username == "" || password == "" {
		return nil, ErrInvalidInput
	}
	return s.repo.GetByCredentials(ctx, username, password)
}
func (s *service) GetUser(ctx context.Context, id int64) (*User, error) {
	if id == 0 {
		return nil, ErrInvalidInput
	}
	return s.repo.GetUserInfo(ctx, id)
}
