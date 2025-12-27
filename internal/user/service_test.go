package user

import (
	"context"
	"testing"

	_ "github.com/lib/pq"
)

func TestLoginAndRegister(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPostgres(db)
	service := NewService(repo)
	ctx := context.Background()

	u, err := service.Register(ctx, "testuser", "secret123", 30)
	if err != nil {
		t.Fatalf("create error: %v", err)
	}
	if u.ID == 0 {
		t.Fatalf("id is zero")
	}

	_, err = service.Register(ctx, "testuser", "secret123", 30)
	if err == nil {
		t.Fatalf("expected error on duplicate username")
	}
	u2, err := service.Login(ctx, "testuser", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if u2 == nil {
		t.Fatalf("login fail")
	}

	u3, err := service.Login(ctx, "testuser", "secret12345")
	if err != nil {
		t.Fatal(err)
	}
	if u3 != nil {
		t.Fatalf("login fail")
	}

}
func TestService_GetUser(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPostgres(db)
	service := NewService(repo)
	ctx := context.Background()

	u, err := service.Register(ctx, "testuser", "secret123", 30)
	if err != nil {
		t.Fatalf("register error: %v", err)
	}

	uGet, err := service.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("get user error: %v", err)
	}
	if uGet == nil {
		t.Fatalf("expected user")
	}
	if uGet.ID != u.ID {
		t.Fatalf("wrong user returned")
	}
}
