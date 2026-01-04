package user

import (
	"encoding/json"
	"errors"
	"gostart/internal/auth"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GetHandler(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := r.Context().Value(auth.UserIDKey).(int64)
		if !ok {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		u, err := svc.GetUser(r.Context(), userID)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(u)
	})
}

func LoginHandler(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		u, err := svc.Login(r.Context(), creds.Username, creds.Password)
		if err != nil {
			http.Error(w, "DB error Login", http.StatusInternalServerError)
			return
		}
		if u == nil {
			http.Error(w, "Invalid credentials", http.StatusNotFound)
			return
		}
		claims := jwt.MapClaims{
			"user_id": u.ID,
			"exp":     time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(auth.JwtSecret)
		if err != nil {
			http.Error(w, "token invalid", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"token": tokenString,
		})
	})
}
func RegisterHandler(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Age      int64  `json:"age"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		u, err := svc.Register(r.Context(), creds.Username, creds.Password, creds.Age)
		if err != nil {
			log.Println("REGISTER ERROR:", err) // ← ВАЖНО
			if errors.Is(err, ErrUserAlreadyExists) {
				http.Error(w, "User already exists", http.StatusConflict)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"id": u.ID,
		})
	})
}
