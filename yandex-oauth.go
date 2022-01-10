package main

import (
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yandex"
)

var states = map[string]time.Time{}

var yandexOauthConfig = &oauth2.Config{
	ClientID:     "10087b9e83934a60ad9fb2bdcec9c67e",
	ClientSecret: "6175da789e824edda426e86baed5e81c",
	Endpoint:     yandex.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/yandex/receive",
}

func startYandexOauth(w http.ResponseWriter, r *http.Request) {
	state := uuid.New().String()
	states[state] = time.Now().Add(1 * time.Hour)

	log.Println(state)
	redirectURL := yandexOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func completeYandexOauth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	log.Println(code, state)
	// if state != "MyState_00" {
	// 	http.Error(w, "State is incorrect", http.StatusBadRequest)
	// 	return
	// }
	//
	// token, err := yandexOauthConfig.Exchange(r.Context(), code)
	// if err != nil {
	// 	http.Error(w, "Couldn't login", http.StatusInternalServerError)
	// 	return
	// }
	//
	// ts := yandexOauthConfig.TokenSource(r.Context(), token)
	// client := oauth2.NewClient(r.Context(), ts)
	//
	// resp, err := client.Get("https://login.yandex.ru/info?with_openid_identity=1")
	// if err != nil {
	// 	http.Error(w, "Couldn't get user", http.StatusInternalServerError)
	// 	return
	// }
	// defer resp.Body.Close()
	//
	// bs, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	http.Error(w, "Couldn't read github information", http.StatusInternalServerError)
	// 	return
	// }
	//
	// log.Println(string(bs))
}
