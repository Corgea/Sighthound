package main

import (
	"database/sql"
	"os/exec"
)

func unsafe(user string, db *sql.DB) {
	exec.Command("sh", "-c", user).Run()
	db.Query("SELECT * FROM users WHERE id = " + user)
}
