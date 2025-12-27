package user

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"
)

func TestUserCrateAndLogin(t *testing.T) {
	db := setupTestDB(t)
	repo := NewPostgres(db)
	ctx := context.Background()

	u, err := repo.Create(ctx, "testuser", "secret123", 30)
	if err != nil {
		t.Fatalf("create error: %v", err)
	}
	if u.ID == 0 {
		t.Fatalf("id is zero")
	}

	u2, err := repo.GetByCredentials(ctx, "testuser", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if u2 == nil {
		t.Fatalf("login fail")
	}

	u3, err := repo.GetByCredentials(ctx, "testuser", "secret12345")
	if err != nil {
		t.Fatal(err)
	}
	if u3 != nil {
		t.Fatalf("login fail")
	}
}
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("postgres", "postgres://postgres:Exdark123@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("TRUNCATE TABLE public.users RESTART IDENTITY")
	if err != nil {
		t.Fatal(err)
	}
	return db
}
