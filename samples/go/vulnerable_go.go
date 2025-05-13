package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	_ "github.com/go-sql-driver/mysql"
)

// Hardcoded credentials vulnerability
const password = "hardcoded_password"

func main() {
	// Insecure random number generator
	randomValue := rand.Intn(100)  // Insecure random

	// Database connection
	db, err := sql.Open("mysql", fmt.Sprintf("root:%s@tcp(localhost:3306)/mydb", password))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	http.HandleFunc("/user", getUserHandler(db))
	http.HandleFunc("/search", searchHandler(db))
	http.HandleFunc("/command", commandHandler)
	http.HandleFunc("/file", fileHandler)
	http.HandleFunc("/template", templateHandler)

	http.ListenAndServe(":8080", nil)
}

// SQL Injection vulnerability
func getUserHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("id")
		
		// SQL Injection vulnerability
		query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
		rows, err := db.Query(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// Process results...
		fmt.Fprintf(w, "User found")
	}
}

// Another SQL Injection vulnerability
func searchHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		searchTerm := r.URL.Query().Get("q")
		
		// SQL Injection vulnerability
		query := "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'"
		rows, err := db.Query(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		// Process results...
		fmt.Fprintf(w, "Search results")
	}
}

// Command injection vulnerability
func commandHandler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	
	// Command injection vulnerability
	cmd := exec.Command("sh", "-c", "ls " + command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Command output: %s", output)
}

// Path traversal vulnerability
func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	
	// Path traversal vulnerability
	filePath := "data/" + filename
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "File content: %s", content)
}

// XSS vulnerability
func templateHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	
	// XSS vulnerability
	tmpl := fmt.Sprintf("<h1>Hello, %s!</h1>", name)
	unsafeTemplate := template.HTML(tmpl)
	
	t, _ := template.New("page").Parse(`{{.}}`)
	t.Execute(w, unsafeTemplate)
}
