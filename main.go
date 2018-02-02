package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
)

func main() {
	router := mux.NewRouter()
	fmt.Println("Starting application . . .")
	router.HandleFunc("/auth", CreateTokenEndpoint).Methods("POST")
	router.HandleFunc("/protected", ProtectedEndPoint).Methods("GET")
	log.Fatal(http.ListenAndServe(":8080", router))
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JwtToken struct {
	Token string `json:"token"`
}

type Exception struct {
	Message string `json:"message"`
}

func CreateTokenEndpoint(w http.ResponseWriter, r *http.Request) {
	var user User
	_ = json.NewDecoder(r.Body).Decode(&user)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"password": user.Password,
	})
	tokenString, err := token.SignedString([]byte("string"))
	if err != nil {
		fmt.Println(err)
	}
	json.NewEncoder(w).Encode(JwtToken{Token: tokenString})
}

func ProtectedEndPoint(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	token, _ := jwt.Parse(params["token"][0], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("there is an error . .")
		}
		return []byte("secret"), nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User
		mapstructure.Decode(claims, &user)
		json.NewEncoder(w).Encode(user)
	} else {
		json.NewEncoder(w).Encode(Exception{Message: "Invalid token"})
	}
}

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := req.Header.Get("auth")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2{
				token, err := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, err) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("there was an error")
				}
				return []byte("secret"), nil
			)}
			if err != nil {
				json.NewEncoder(w).Encode(Exception{Message: err.Error()})
				return
			}
			if token.Valid {
				context.Set(req, "decoded", token.Claims)
				next(w, r)
			}else {
				json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"}
			}
		}
	}else {
		json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
	}
})


func TestEndpoint(w http.ResponseWriter, req *http.Request) {
	decode := context.Get(req, "decode")
	var user User
	mapstructure.Decode(decoded.(jwt.MapClaimsl), &user)
	json.NewEncoder(w).Encode(user)
}
