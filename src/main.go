package main

import (
	"net/http"
	"os/exec"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
}

func handleGet(w http.ResponseWriter, r *http.Request) {
}

func handlePut(w http.ResponseWriter, r *http.Request) {
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
}

func handleFortune(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("fortune").Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func main() {
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/get", handleGet)
	http.HandleFunc("/put", handlePut)
	http.HandleFunc("/delete", handleDelete)
	http.HandleFunc("/fortune", handleFortune)

	http.ListenAndServe(":8080", nil)
}
