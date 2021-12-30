package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	users          = make(map[string]string)
	keyHmac []byte = []byte("some secret key")
	sep     string = "."
)

func main() {
	log.Println("Start progam")

	log.Println("Check tokens")
	session := "checksessionid"
	token, err := createToken(session)
	if err != nil {
		log.Println("error in createToken %w", err)
	}
	checksession, err := parseToken(token)
	if checksession != session {
		log.Printf("error in compare tokens, %v", err)
	}
	// log.Printf("token: %v, session: %v", token, checksession)

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
		log.Printf("Can't get hash from password %v \n", err)
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

func createToken(sessionID string) (string, error) {
	mac := hmac.New(sha256.New, keyHmac)
	_, err := mac.Write([]byte(sessionID))
	if err != nil {
		return "", fmt.Errorf("can't make hash for session")
	}
	token := sessionID + "." + string(mac.Sum(nil))
	// log.Printf("token: %t", token)
	return token, nil
}

func parseToken(signedToken string) (string, error) {
	ss := strings.Split(signedToken, sep)
	if len(ss) <= 1 || len(ss) > 2 {
		return "", fmt.Errorf("wrogn token format")
	}
	sessionID := ss[0]
	sessionMAC := []byte(ss[1])

	mac := hmac.New(sha256.New, keyHmac)
	_, err := mac.Write([]byte(sessionID))
	if err != nil {
		return "", fmt.Errorf("invalid token 1")
	}
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(sessionMAC, expectedMAC) {
		return "", fmt.Errorf("invalid token 2")
	}
	return sessionID, nil
}
