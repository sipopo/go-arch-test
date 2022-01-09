package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yandex"
)

var yandexOauthConfig = &oauth2.Config{
	ClientID:     "10087b9e83934a60ad9fb2bdcec9c67e",
	ClientSecret: "6175da789e824edda426e86baed5e81c",
	Endpoint:     yandex.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/receive",
}

func main() {

	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/yandex", startYandexOauth)
	http.HandleFunc("/oauth/receive", completeYandexOauth)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Document</title>
</head>
<body>
	<form action="/oauth/yandex" method="post">
		<input type="submit" value="Login with Yandex">
	</form>
</body>
</html>`)
}

func startYandexOauth(w http.ResponseWriter, r *http.Request) {
	redirectURL := yandexOauthConfig.AuthCodeURL("MyState_00")
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func completeYandexOauth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	if state != "MyState_00" {
		http.Error(w, "State is incorrect", http.StatusBadRequest)
		return
	}

	token, err := yandexOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Couldn't login", http.StatusInternalServerError)
		return
	}

	ts := yandexOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)

	resp, err := client.Get("https://login.yandex.ru/info?with_openid_identity=1")
	if err != nil {
		http.Error(w, "Couldn't get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Couldn't read github information", http.StatusInternalServerError)
		return
	}

	log.Println(string(bs))
}
