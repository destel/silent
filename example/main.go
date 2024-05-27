package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"

	_ "github.com/go-sql-driver/mysql"

	"github.com/destel/silent"
)

func init() {
	c := silent.MultiKeyCrypter{}
	c.AddKey(0x1, MustDecodeBase64("Qpk1tvmH8nAljiKyyDaGJXRH82ZjWtEX+2PR50sB5WU="))
	//c.Bypass = true

	silent.RegisterCrypterFor[silent.EncryptedValue](&c)
}

func MustDecodeBase64(s string) []byte {
	res, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return res
}

type User struct {
	Username string
	Token    silent.EncryptedValue
}

func main() {
	if err := doMain(context.Background()); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func doMain(ctx context.Context) error {
	db, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:54778)/megatest")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	_, err = db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS users (username VARCHAR(255), token VARBINARY(255), PRIMARY KEY (username))")
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Write
	user := User{
		Username: "alice",
		Token:    silent.EncryptedValue("Alice's secret token"),
	}

	res, err := db.ExecContext(ctx, `INSERT INTO users (username, token) VALUES (?, ?) ON DUPLICATE KEY UPDATE token = VALUES(token)`, user.Username, user.Token)
	if err != nil {
		return fmt.Errorf("failed to insert user: %w", err)
	}

	ra, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if ra == 1 {
		fmt.Println("User inserted")
	} else {
		fmt.Println("User updated")
	}

	// Read
	var user2 User
	err = db.QueryRowContext(ctx, "SELECT username, token FROM users WHERE username = ?", user.Username).Scan(&user2.Username, &user2.Token)
	if err != nil {
		return fmt.Errorf("failed to select user: %w", err)
	}

	fmt.Printf("User2: %+v\n", user2)
	return nil
}
