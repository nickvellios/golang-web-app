package main

import (
	"log"
	"net/http"
	"time"

	"github.com/nickvellios/golang-web-app/db"

	"github.com/julienschmidt/httprouter"
)

type glob struct {
	udb *db.UrlDB
}

var templateDir = "./src/github.com/nickvellios/golang-web-app/templates/"

func main() {
	time.LoadLocation("PST")

	g := &glob{}
	g.udb = &db.UrlDB{}
	g.udb.Open()
	defer g.udb.Db.Close()

	router := httprouter.New()
	router.GET("/", g.AuthMiddleware(g.Index, ""))
	router.GET("/signup/", g.Signup)
	router.POST("/signup/", g.SignupPost)
	router.GET("/logout/", g.Logout)
	router.GET("/login/", g.Login)
	router.POST("/login/", g.LoginPost)
	router.ServeFiles("/assets/*filepath", http.Dir("./bin/assets"))

	log.Fatal(http.ListenAndServe(":8080", router))
}
