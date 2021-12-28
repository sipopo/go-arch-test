package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

var users = make(map[string]string)

func main() {

	http.HandleFunc("/", baseEndPoint)
	http.HandleFunc("/register", registerEndPoint)
	if http.ListenAndServe(":8080", nil) != nil {
		log.Fatalln("Can't listen address")
	}
}

func baseEndPoint(w http.ResponseWriter, r *http.Request) {
	log.Println("show base web")
	io.WriteString(w, showHTML())
}

func registerEndPoint(w http.ResponseWriter, r *http.Request) {
	log.Println("register web")
	if r.Method != http.MethodPost {
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	hash, err := getHash([]byte(password))
	if err != nil {
		log.Printf("Can't get hash from password %w \n", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	users[username] = string(hash)
	printAllUsers()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getHash(password []byte) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return []byte(""), fmt.Errorf("can't generate hash %w", err)
	}
	return hash, nil
}

func printAllUsers() {
	for u, p := range users {
		log.Printf("username: %v, password: %v", u, p)
	}
}

func showHTML() string {
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>HMAC Example</title>
	</head>
	<body>
		<form action="/register" method="post">
			<input type="username" name="username" />
			<input type="password" name="password" />
			<input type="submit" />
		</form>
	</body>
	</html>`

	return html
}
