package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type User struct {
	Username string `json:"username"`
	Age      int64  `json:"age"`
	Password string `json:"password"`
}

var users = map[int64]User{
	1: {
		Username: "Bellaria02",
		Age:      25,
		Password: "Exdark123",
	},
}

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
	for id, user := range users {
		if user.Username == creds.Username && user.Password == creds.Password {
			token := fmt.Sprintf("token_%d", id)
			json.NewEncoder(w).Encode(map[string]any{
				"user_id": id,
				"token":   token,
			})
			return
		}
	}
	http.Error(w, "User not found", http.StatusNotFound)
}

func getUser(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	userID := r.Context().Value(userIDKey).(int64)
	user, ok := users[userID]
	if !ok {
		http.Error(w, "User not found", http.StatusNotFound)
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
		if len(parts) != 2 {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		var userID int64

		_, err := fmt.Sscanf(parts[1], "token-%d", &userID)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
		}

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", getUserId)
	mux.Handle("/user", authMiddleware(http.HandlerFunc(getUser)))
	http.ListenAndServe(":8080", mux)
}
