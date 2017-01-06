package users

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"

	"github.com/nickvellios/golang-web-app/ncrypt"
)

type User struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	//Password  string  `json:"-"`
	Hash      string  `json:"-"`
	CSRFToken string  `json:"-"`
	Id        int     `json:"id"`
	Db        *sql.DB `json:"-"`
}

func (u *User) Authenticate(pass string) bool {
	if !u.Load() {
		return false
	}

	err := ncrypt.CheckPassHash([]byte(u.Hash), []byte(pass))
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	return true
}

// Load reloads the user from the database.  Only value needed to be set is 'Email', the rest will be populated.
func (u *User) Load() bool {
	rows, err := u.Db.Query("SELECT name, password, id, csrftok FROM users WHERE email = $1", u.Email)
	if err != nil {
		fmt.Println(err.Error())
	}

	for rows.Next() {
		err = rows.Scan(&u.Name, &u.Hash, &u.Id, &u.CSRFToken)
		if err != nil {
			fmt.Println(err.Error())
		}
		return true
	}

	return false
}

/*
func (u *User) Save() {
	// Save user to db
	u.HashPass()
	stmt, err := u.Db.Prepare("UPDATE users SET email=$1, name=$2, password=$3 WHERE id=$4")
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = stmt.Exec(u.Email, u.Name, u.Hash, u.Id)
	if err != nil {
		fmt.Println(err.Error())
	}
}
*/

// Create saves a user object to the database.  If a duplicate email is found this will fail.
func (u *User) Create(pass string) error {
	if !u.validEmail() {
		return errors.New("Invalid email format")
	}
	if u.Exists() {
		return errors.New("User already exists")
	}
	u.sanitize()
	u.HashPass(pass)
	var lastInsertId int
	err := u.Db.QueryRow("INSERT INTO users(email, name, password) VALUES($1,$2,$3) returning id;", u.Email, u.Name, u.Hash).Scan(&lastInsertId)
	if err != nil {
		return err //fmt.Println(err.Error())
	}

	u.Id = lastInsertId
	return nil
}

func (u *User) validEmail() bool {
	re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return re.MatchString(u.Email)
}

func (u *User) sanitize() {
	// Clean up user object to prevent XSS attacks
}

func (u *User) Exists() bool {
	rows, err := u.Db.Query("SELECT id FROM users WHERE email = $1", u.Email)
	if err != nil {
		fmt.Println(err.Error())
	}

	for rows.Next() {
		err = rows.Scan(&u.Id)
		if err != nil {
			fmt.Println(err.Error())
		}
		return true
	}

	return false
}

func (u *User) SetCSRF() {
	u.CSRFToken = CSRFToken()
	stmt, err := u.Db.Prepare("UPDATE users SET csrftok=$1 WHERE id=$2")
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = stmt.Exec(u.CSRFToken, u.Id)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func (u *User) RevokeCSRF() {
	u.CSRFToken = ""
	stmt, err := u.Db.Prepare("UPDATE users SET csrftok=$1 WHERE id=$2")
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = stmt.Exec(u.CSRFToken, u.Id)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func (u *User) HashPass(pass string) {
	hash, _ := ncrypt.HashPass([]byte(pass))
	u.Hash = string(hash)
}

func CSRFToken() string {
	h := sha256.New()
	crutime := time.Now().Unix()
	io.WriteString(h, strconv.FormatInt(crutime, 10))
	io.WriteString(h, string(ncrypt.RandomBytes(17)))
	token := fmt.Sprintf("%x", h.Sum(nil))
	return token
}
