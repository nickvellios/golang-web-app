package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"

	"github.com/nickvellios/golang-web-app/jwt"
	"github.com/nickvellios/golang-web-app/users"

	"github.com/julienschmidt/httprouter"
)

const LOGIN_EXPIRATION_SEC = 1200 // 20min

var templates = template.Must(template.ParseFiles(
	templateDir+"index.html",
	templateDir+"login.html",
	templateDir+"signup.html",
	templateDir+"header.html",
	templateDir+"footer.html"))

type Page struct {
	Title   string
	Content interface{}
}

func renderTemplate(w http.ResponseWriter, tmpl string, data *Page) {
	err := templates.ExecuteTemplate(w, tmpl, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Index page handler
func (g *glob) Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	u, _ := r.Context().Value("email").(string)
	p := &Page{
		Title: "Home",
		Content: struct {
			Email    interface{}
			LoggedIn interface{}
		}{
			template.HTML(string(u)),
			(len(u) > 0),
		},
	}
	renderTemplate(w, "index", p)
}

// Login page handler
func (g *glob) Login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	p := &Page{Title: "Login"}
	renderTemplate(w, "login", p)
}

// Logout handler
func (g *glob) Logout(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	cook := http.Cookie{Name: "user", Value: "", HttpOnly: true, MaxAge: -1, Path: "/"}
	http.SetCookie(w, &cook)
	http.Redirect(w, r, "/", 302)
}

// Signup page handler
func (g *glob) Signup(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	u, _ := r.Context().Value("email").(string)
	p := &Page{Title: "Signup " + u}
	renderTemplate(w, "signup", p)
}

// SignupPost is the sign up form action handler.
func (g *glob) SignupPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user := &users.User{
		Email: r.FormValue("email"),
		Name:  r.FormValue("name"),
		Db:    g.udb.Db,
	}
	err := user.Create(r.FormValue("password"))
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}
	setCookie(w, user.Email)
	user.SetCSRF()
	http.Redirect(w, r, "/", 302)
}

// LoginPost is the login form action handler.
func (g *glob) LoginPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	user := &users.User{
		Email: r.FormValue("email"),
		Db:    g.udb.Db,
	}
	if !user.Authenticate(r.FormValue("password")) {
		fmt.Fprint(w, "Authentication Failed.  Bad username/password combination or user not found\n")
		return
	}
	setCookie(w, user.Email)
	user.SetCSRF()
	http.Redirect(w, r, "/", 302)
}

func setCookie(w http.ResponseWriter, u string) {
	claim := make(map[string]string)
	claim["email"] = u
	jwt := jwt.Generate(claim, LOGIN_EXPIRATION_SEC)
	cookie := http.Cookie{Name: "user", Value: jwt, HttpOnly: true, MaxAge: LOGIN_EXPIRATION_SEC, Path: "/"}
	http.SetCookie(w, &cookie)
}

// Check if user is logged in.  If not, or something is fishy with the JWT, redirect to the location specified in the `to` parameter if it is set.
func (g *glob) AuthMiddleware(fn func(http.ResponseWriter, *http.Request, httprouter.Params), to string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		theJWT, err := jwt.DecodeFromCookie(r, "user")
		if err != nil {
			// Revoke cookie
			cookie := http.Cookie{Name: "user", Value: "", HttpOnly: true, MaxAge: -1, Path: "/"}
			http.SetCookie(w, &cookie)
			// If the redirect to option is set redirect there, if not just load the page without the cookie or context.
			if len(to) > 0 {
				http.Redirect(w, r, to, 302)
			} else {
				fn(w, r, ps)
			}
			return
		}
		email := theJWT["email"]
		setCookie(w, email) // Issue new JWT with reset expiration since it hasn't expired yet.
		// All is good, continue to http handler.
		ctx := context.WithValue(r.Context(), "email", email)
		fn(w, r.WithContext(ctx), ps)
	}
}
