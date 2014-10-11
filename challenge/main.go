package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
)

// User is ...
type User struct {
	Name     string `json:"username"`
	Password string `json:"password"`
}

// Auth is ...
type Auth struct {
	Domain string `json:"domain"`
	Users  []User `json:"users"`
}

var auths []Auth

func init() {
	b, err := ioutil.ReadFile("users.json")

	if err != nil {
		panic(err)
	}

	if err := json.Unmarshal(b, &auths); err != nil {
		panic(err)
	}

	for _, auth := range auths {
		for i, user := range auth.Users {
			auth.Users[i].Password = encode(user.Password)
		}
	}
}

func encode(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return "{SHA256}" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	tokens := strings.Split(r.URL.String(), "/")

	if len(tokens) != 6 || tokens[5] != "proxyauth" {
		http.NotFound(w, r)
		return
	}

	domain := tokens[4]

	var domainExists bool
	var users []User

	for _, auth := range auths {
		if auth.Domain == domain {
			domainExists = true
			users = auth.Users
			break
		}
	}

	if !domainExists {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var userExists bool

	for _, u := range users {
		if u.Name == username && u.Password == password {
			userExists = true
		}
	}

	if !userExists {
		w.WriteHeader(http.StatusOK)
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	http.HandleFunc("/api/2/domains/", handle)
	http.ListenAndServe(":8080", nil)
}
