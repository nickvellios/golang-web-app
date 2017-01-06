package db

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type UrlDB struct {
	Db *sql.DB
}

// Database configuration

const (
	DB_USER     = "postgres"
	DB_PASSWORD = "postgres"
	DB_NAME     = "nick"
)

// Global DB error checking
func checkDBErr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func (udb *UrlDB) Open() error {
	dbinfo := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", DB_USER, DB_PASSWORD, DB_NAME)
	var err error
	udb.Db, err = sql.Open("postgres", dbinfo)
	if err != nil {
		panic(err)
	}
	// Bootstrap database table
	_, err = udb.Db.Query(`CREATE TABLE IF NOT EXISTS users (
								id SERIAL PRIMARY KEY,
								email VARCHAR(256) UNIQUE,
								password VARCHAR(128),
								name VARCHAR(64),
								csrftok VARCHAR(64),
								t_stamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
							);`)
	checkDBErr(err)
	return err
}
