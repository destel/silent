package silent_test

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"

	_ "github.com/proullon/ramsql/driver"

	"github.com/destel/silent"
)

type User struct {
	Username string                `json:"username"`
	Token    silent.EncryptedValue `json:"token"`
}

// RawUser is a helper type to read users from the database without decrypting the token column.
// It serves to demonstrate that the token column is indeed encrypted in the database.
type RawUser struct {
	Username string
	Token    []byte
}

// This example showcases how to automatically encrypt and decrypt the token column of the users table in the database.
// The tokens are encrypted before storing them in the database and decrypted when retrieving the user data.
// Additionally, the example demonstrates that database is actually encrypted by reading the users again and scanning the token column as []byte.
func Example_databaseEncryptAndDecrypt() {
	db, err := initDB()
	if err != nil {
		fmt.Println("failed to init db:", err)
		return
	}

	// Initialize the crypter and bind it to the EncryptedValue type
	crypter := silent.MultiKeyCrypter{}
	crypter.AddKey(0x1, mustDecodeBase64("Qpk1tvmH8nAljiKyyDaGJXRH82ZjWtEX+2PR50sB5WU="))

	silent.BindCrypterTo[silent.EncryptedValue](&crypter)

	// Prepare some users
	alice := User{
		Username: "alice",
		Token:    silent.EncryptedValue("some token"),
	}

	bob := User{
		Username: "bob",
		Token:    silent.EncryptedValue("another token"),
	}

	// Save encrypted users to DB
	if err := saveUser(db, &alice, &bob); err != nil {
		fmt.Println("failed to save users:", err)
		return
	}

	// Read the users back. They will be automatically decrypted
	rows, err := db.Query("SELECT username, token FROM users")
	if err != nil {
		fmt.Println("failed to fetch users:", err)
		return
	}

	users, err := scanAllRows(rows, func(rows *sql.Rows) (*User, error) {
		var u User
		err := rows.Scan(&u.Username, &u.Token)
		return &u, err
	})
	if err != nil {
		fmt.Println("failed to scan users:", err)
		return
	}

	fmt.Println("Decrypted users:")
	for _, u := range users {
		fmt.Printf("%+v\n", u)
	}
	fmt.Println("")

	// Now read the same users again but without decrypting the token column.
	// Scan into RawUser type for this
	rows, err = db.Query("SELECT username, token FROM users")
	if err != nil {
		fmt.Println("failed to fetch users:", err)
		return
	}

	encryptedUsers, err := scanAllRows(rows, func(rows *sql.Rows) (*RawUser, error) {
		var u RawUser
		err := rows.Scan(&u.Username, &u.Token)
		return &u, err
	})
	if err != nil {
		fmt.Println("failed to scan users:", err)
		return
	}

	fmt.Println("Encrypted users:")
	for _, u := range encryptedUsers {
		fmt.Printf("%+v\n", u)
	}
}

// This example illustrates how to automatically encrypt and decrypt the token field of the User struct
// when marshaling and unmarshaling JSON data
func Example_jsonEncryptAndDecrypt() {
	// Initialize the crypter and bind it to the EncryptedValue type
	crypter := silent.MultiKeyCrypter{}
	crypter.AddKey(0x1, mustDecodeBase64("Qpk1tvmH8nAljiKyyDaGJXRH82ZjWtEX+2PR50sB5WU="))

	silent.BindCrypterTo[silent.EncryptedValue](&crypter)

	// Marshal some users to JSON to demonstrate how the token field is automatically encrypted
	users := []User{
		{
			Username: "alice",
			Token:    silent.EncryptedValue("some token"),
		},
		{
			Username: "bob",
			Token:    silent.EncryptedValue("another token"),
		},
	}

	j, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		fmt.Println("failed to marshal users:", err)
		return
	}

	// Print the encrypted JSON
	fmt.Println("Encrypted JSON:")
	fmt.Println(string(j))
	fmt.Println("")

	// Unmarshal the JSON back to demonstrate how the token field is automatically decrypted
	var decryptedUsers []User
	if err := json.Unmarshal(j, &decryptedUsers); err != nil {
		fmt.Println("failed to unmarshal users:", err)
		return
	}

	// Print the decrypted users
	fmt.Println("Decrypted users:")
	for _, u := range decryptedUsers {
		fmt.Printf("%+v\n", u)
	}
}

func mustDecodeBase64(s string) []byte {
	res, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return res
}

func initDB() (*sql.DB, error) {
	db, err := sql.Open("ramsql", "testdb")
	if err != nil {
		return nil, err
	}

	_, err = db.Exec("CREATE TABLE users (username VARCHAR(255), token VARBINARY(255), PRIMARY KEY (username))")
	if err != nil {
		return nil, err
	}

	return db, nil
}

func saveUser(db *sql.DB, users ...*User) error {
	for _, u := range users {
		_, err := db.Exec(`INSERT INTO users (username, token) VALUES (?, ?)`, u.Username, u.Token)
		if err != nil {
			return err
		}

	}
	return nil
}

// scanAllRows is a generic helper function that scans all rows from a sql.Rows object into a slice of T
func scanAllRows[T any](rows *sql.Rows, f func(*sql.Rows) (T, error)) ([]T, error) {
	defer rows.Close()

	var res []T
	for rows.Next() {
		v, err := f(rows)
		if err != nil {
			return nil, err
		}

		res = append(res, v)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}
