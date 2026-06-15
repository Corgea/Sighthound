package main

import "database/sql"

func safe(user string, db *sql.DB) {
	db.Query("SELECT * FROM users WHERE id = ?", user)
}
