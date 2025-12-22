package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"strings"
	"time"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Age      int64  `json:"age"`
	Password string `json:"password"`
}

var db *sql.DB

// в ПРОДЕ обязательно
// env-переменная
//
// длинный ключ
//
// не в коде
var jwtSecret = []byte("super-secret-key")

type contextKey string

const userIDKey contextKey = "userID"

func getUserId(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Json invalid", http.StatusBadRequest)
		return
	}
	var userID int64
	err := db.QueryRow(
		"SELECT id FROM public.users WHERE username=$1 AND password=$2",
		creds.Username,
		creds.Password,
	).Scan(&userID)

	if err == sql.ErrNoRows {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Println("login query error:", err)
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "token invalid", http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

func getUser(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	userID, ok := r.Context().Value(userIDKey).(int64)
	if !ok {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	var user User
	err := db.QueryRow("SELECT username,age FROM public.users WHERE id = $1", userID).Scan(&user.Username, &user.Age)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"user_id":  userID,
		"username": user.Username,
		"age":      user.Age,
	})
}
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(auth, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method")
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		userID := int64(claims["user_id"].(float64))

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func main() {
	var err error
	dsn := "postgres://postgres:Exdark123@localhost:5432/postgres?sslmode=disable"
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to postgres")
	mux := http.NewServeMux()
	mux.HandleFunc("/login", getUserId)
	mux.Handle("/user", authMiddleware(http.HandlerFunc(getUser)))
	http.ListenAndServe(":8080", mux)
}
