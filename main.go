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
	log.Println("Start progam")
	http.HandleFunc("/", baseEndPoint)
	http.HandleFunc("/register", registerEndPoint)
	http.HandleFunc("/login", loginEndPoint)

	if http.ListenAndServe(":8080", nil) != nil {
		log.Fatalln("Can't listen address")
	}
}

func baseEndPoint(w http.ResponseWriter, r *http.Request) {
	log.Println("show Login Form")
	log.Printf("Len of users %v \n", len(users))
	// check if users exists
	if len(users) == 0 {
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}
	printAllUsers()
	io.WriteString(w, showLoginForm())

}

func loginEndPoint(w http.ResponseWriter, r *http.Request) {
	log.Println("loginEndPoint")
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	if username == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if users[username] == "" {
		io.WriteString(w, showRegisterForm())
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(users[username]), []byte(password))
	if err != nil {
		log.Printf("user %v has a wrong password", username)
		// http.Redirect(w, r, "/register", http.StatusSeeOther)
		io.WriteString(w, "You aren`t login!")
		return
	}
	io.WriteString(w, "You are login!")
}

func registerEndPoint(w http.ResponseWriter, r *http.Request) {
	log.Println("register web")
	if r.Method != http.MethodPost {
		io.WriteString(w, showRegisterForm())
		return
	}

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	if username == "" || password == "" {
		log.Println("Empty data for register")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	hash, err := getHash([]byte(password))
	if err != nil {
		log.Printf("Can't get hash from password %w \n", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
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

func showRegisterForm() string {
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>Reguster Form</title>
	</head>
	<body>
	    <label> Register Form </label>
		<form action="/register" method="post">
		    <label for="username">Username: </label>
			<input type="username" id="username" name="username" /></br>
			<label for="password">Password: </label>
			<input type="password" id="password" name="password" /></br>
			<input type="submit" />
		</form>
	</body>
	</html>`

	return html
}

func showLoginForm() string {
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>Login Form</title>
	</head>
	<body>
	 	<label> Login Form </label>
		<form action="/login" method="post">
		    <label for="username">Username: </label>
			<input type="username" id="username" name="username" /></br>
			<label for="password">Password: </label>
			<input type="password" id="password" name="password" /></br>
			<input type="submit" />
		</form>
	</body>
	</html>`

	return html
}
