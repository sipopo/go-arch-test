package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	password []byte
	First    string
}

// key is email, value is user
var db = map[string]user{}

// key is user id from oath, value id in my own system
var oauthConnections = map[string]string{}

// key is sessionid, value is email
var sessions = map[string]string{}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/partial-register", partialRegister)
	http.HandleFunc("/oauth/yandex/login", startYandexOauth)
	http.HandleFunc("/oauth/yandex/receive", completeYandexOauth)
	http.HandleFunc("/oauth/yandex/register", registerYandexOauth)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	var e string
	if sID != "" {
		e = sessions[sID]
	}

	var f string
	if user, ok := db[e]; ok {
		f = user.First
	}

	errMsg := r.FormValue("msg")

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>Document</title>
	</head>
	<body>
	<h1>IF YOU HAVE A SESSION, HERE IS YOUR NAME: %s</h1>
	<h1>IF YOU HAVE A SESSION, HERE IS YOUR EMAIL: %s</h1>
	<h1>IF THERE IS ANY MESSAGE FOR YOU, HERE IT IS: %s</h1>
        <h1>REGISTER</h1>
		<form action="/register" method="POST">
		<label for="first">First</label>
		<input type="text" name="first" placeholder="First" id="first">
		<input type="email" name="e">
			<input type="password" name="p">
			<input type="submit">
        </form>
        <h1>LOG IN</h1>
        <form action="/login" method="POST">
            <input type="email" name="e">
			<input type="password" name="p">
			<input type="submit">
		</form>
		</p>
		<form action="/oauth/yandex/login" method="POST">
			<input type="submit" value="Login with Yandex">
		</form>
		<h1>LOGOUT</h1>
		<form action="/logout" method="POST">
		<input type="submit" value="LOGOUT">
	</form>
	</body>
	</html>`, f, e, errMsg)
}


func partialRegister(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if name == "" {
		msg := url.QueryEscape("No name information")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	

	email := r.FormValue("email")
	if email == "" {
		msg := url.QueryEscape("No email information")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	email, err := url.QueryUnescape(email)
	if err != nil {
		msg := url.QueryEscape("can't recognize email")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}


	signedUserID := r.FormValue("signedUserID")
	if signedUserID == "" {
		msg := url.QueryEscape("No signedUserDI information")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
	}

	fmt.Fprintf(w,`<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta http-equiv="X-UA-Compatible" content="ie=edge">
		<title>Document</title>
	</head>
	<body>
		<h1>Partial-REGISTER</h1>
		<form action="/oauth/yandex/register" method="POST">
		<label for="First">First Name</label>
		<input type="text" name="first" placeholder="First" id="First" value="%s">
		<label for="email">Email</label>
		<input type="email" name="email" value="%s">
		<input type="hidden" name="signedUserID" value="%s">
		<input type="submit" value="register">
		</form>
	</body>
	</html>
	`, name, email, signedUserID)

}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		msg := url.QueryEscape("your email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		msg := url.QueryEscape("your email password needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	f := r.FormValue("first")
	if f == "" {
		msg := url.QueryEscape("your first name needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	bsp, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		msg := "there was an internal server error - evil laugh: hahahahaha"
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	log.Println("password", p)
	log.Println("bcrypted", bsp)
	db[e] = user{
		password: bsp,
		First:    f,
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("e")
	if e == "" {
		msg := url.QueryEscape("your email needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	p := r.FormValue("p")
	if p == "" {
		msg := url.QueryEscape("your email password needs to not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if _, ok := db[e]; !ok {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	err := bcrypt.CompareHashAndPassword(db[e].password, []byte(p))
	if err != nil {
		msg := url.QueryEscape("your email or password didn't match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	token, err := createSession(e)
	if err != nil {
		msg := url.QueryEscape("cound't create token in login")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	c := http.Cookie{
		Name:  "sessionID",
		Value: token,
	}

	http.SetCookie(w, &c)

	msg := url.QueryEscape("you logged in " + e)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)

}

//createSession Create session for e (login or email)
// return token
func createSession(e string) (string, error) {
	sUUID := uuid.New().String()
	sessions[sUUID] = e
	token, err := createToken(sUUID)
	if err != nil {
		log.Println("couldn't createToken in createSession:" + err.Error())
		return "", fmt.Errorf("coudn't create Token for session")
	}
	log.Println("session created")
	return token, nil
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c, err := r.Cookie("sessionID")
	if err != nil {
		c = &http.Cookie{
			Name:  "sessionID",
			Value: "",
		}
	}

	sID, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}

	delete(sessions, sID)

	c.MaxAge = -1

	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
