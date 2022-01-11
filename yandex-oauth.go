package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
	"encoding/json"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yandex"
)


// {"id": "...", "login": "...", "client_id": "", "openid_identities": ["..."], "psuid": "..."}

type yandexResponse struct {
	ID string `json: "id"`
	Login string `json: "login"`
	ClientID string `json: "client_id"`
	OpenidIdentities []string `json: "openid_identities"`
	Psuid string `json: "psuid"`
}

var states = map[string]time.Time{}

var yandexOauthConfig = &oauth2.Config{
	ClientID:     "10087b9e83934a60ad9fb2bdcec9c67e",
	ClientSecret: "6175da789e824edda426e86baed5e81c",
	Endpoint:     yandex.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/yandex/receive",
}

func startYandexOauth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	state := uuid.New().String()
	states[state] = time.Now().Add(1 * time.Minute)

	log.Println(state)
	redirectURL := yandexOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func completeYandexOauth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	if code == "" {
		msg := url.QueryEscape("the code is empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if state == "" {
		msg := url.QueryEscape("the state is empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	// log.Println(code, state)

	if time.Now().After(states[state]) {
		msg := url.QueryEscape("the state is expired")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		log.Printf("State %v is expired ", state)
		return
	}

	token, err := yandexOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		msg := url.QueryEscape("can't do exchage: " + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		// http.Error(w, "Couldn't login", http.StatusInternalServerError)
		return
	}

	ts := yandexOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)

	resp, err := client.Get("https://login.yandex.ru/info?with_openid_identity=1")
	if err != nil {
		msg := url.QueryEscape("can't do exchage: " + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		// http.Error(w, "Couldn't get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Couldn't read yandex information", http.StatusInternalServerError)
		return
	}

	reader := Reader.NewReader(string(bs))
	log.Println(string(bs))
	log.Printf("%T : %v", bs, bs)
	log.Printf("%T : %v", resp.Body, resp.Body)

	var yar yandexResponse

	err = json.NewDecoder(reader).Decode(&yar)
	if err != nil {
		http.Error(w, "Couldn't decode JSON" + err.Error(), http.StatusInternalServerError)
		log.Println(err)
		return
	}

	yandexID := yar.ID
	log.Println("Print yandex id only", yandexID)
}
