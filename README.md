# Silent [![GoDoc](https://pkg.go.dev/badge/github.com/destel/silent)](https://pkg.go.dev/github.com/destel/silent)
Silent is a Go library designed for transparent data encryption at rest in SQL, NoSQL databases, and beyond. 
It eliminates boilerplate code, allowing you to manage sensitive data with minimal changes to your application.
True to its name, it operates silently, making your code less verbose and more secure. 


> ⚠️ **Warning**: This library is in early development stage and should not be used in production yet.


## Key features
- Zero boilerplate: configure encryption once and use it everywhere
- Pluggable Crypter interface for custom encryption strategies
- Built-in crypter that supports key rotation and powered by the encryption-at-rest library from [MinIO](https://github.com/minio/sio)
- HashiCorp Vault Adapter: Integration with HashiCorp Vault encryption service (coming soon)
- Support for SQL databases, JSON serialization, and more formats (BSON and others coming soon)


## Installation
```bash
go get github.com/destel/silent
```


## Basic usage
[Full runnable example](https://pkg.go.dev/github.com/destel/silent#example-package-DatabaseEncryptAndDecrypt)
```go
// Create a Crypter instance
var crypter silent.Crypter = ... // Initialize crypter

// Bind the crypter to the EncryptedValue type
silent.BindCrypterTo[silent.EncryptedValue](crypter)

// Use EncryptedValue in your models
type User struct {
    Username string
    Token    silent.EncryptedValue
}

user := User{
    Username: "john_doe",
    Token:    silent.EncryptedValue("some token"),
}

// Work with your models as usual
res, err := db.ExecContext(ctx, `INSERT INTO users (username, token) VALUES (?, ?)`, user.Username, user.Token)
```


## Design philosophy
Library is built upon three core concepts that work together to provide a simple and flexible way to encrypt and decrypt sensitive data:
- Crypter Interface
  - Defines the Encrypt and Decrypt methods
  - Allows for custom encryption strategies
- EncryptedValue type 
  - Transparently handles encryption and decryption
  - Abstracts away the complexity of working with encrypted data
- BindCrypterTo function
  - Binds a crypter instance to an EncryptedValue type





## MultiKeyCrypter
Silent ships with a built-in MultiKeyCrypter that provides a secure and flexible encryption solution. 
It supports multiple encryption keys and seamless key rotation, 
making it easy to maintain the security of your encrypted data over time.


### Features
- Support for multiple encryption keys
- Zero downtime key rotation
- Powered by the MinIO encryption-at-rest [library](https://github.com/minio/sio), ensuring strong security
- Bypass mode for easy testing and debugging in development environments


### Usage
To use MultiKeyCrypter, simply create an instance, then add your encryption keys with unique IDs.
MultiKeyCrypter uses the last added key for encryption and automatically selects 
the appropriate key for decryption based on the key ID embedded in the encrypted data
```go
crypter := silent.MultiKeyCrypter{}
crypter.AddKey(1, []byte("your-encryption-key-1")) // never hardcode keys in production
crypter.AddKey(2, []byte("your-encryption-key-2"))

silent.BindCrypterTo[silent.EncryptedValue](&crypter)
```

To rotate keys, simply add a new key with a unique identifier, without removing the old keys:
```go
crypter.AddKey(3, []byte("your-new-encryption-key"))
```

MultiKeyCrypter also supports a bypass mode, which is useful for testing and debugging in development environments. 
In bypass mode data is prefixed with '#' instead of being encrypted, making it readable in plain text.
Decryption is still performed as usual, allowing to work with both encrypted and plain text data in the same environment.
```go
crypter := silent.MultiKeyCrypter{}
crypter.AddKey(1, []byte("your-encryption-key"))
crypter.Bypass = true

silent.BindCrypterTo[silent.EncryptedValue](&crypter)
```

### Best practices
- Never hardcode encryption keys in your code
- Use a secure key management system to store and manage your keys
- Rotate your encryption keys regularly


## Coming soon: HashiCorp Vault crypter
First stable release will have a built-in adapter for [HashiCorp Vault](https://www.vaultproject.io/) encryption service. 


## Beyond SQL: encrypted data everywhere
Silent's EncryptedValue is not limited to SQL databases. It seamlessly integrates with various storage systems and formats, 
ensuring that your sensitive data remains encrypted across your entire application stack.


### JSON serialization
EncryptedValue is automatically encrypted when serialized to JSON, making it effortless to secure your data in JSON-based storage systems. 
This includes:
- NoSQL databases that use JSON for communication (e.g., CouchDB, Firebase)
- REST APIs
- JSON files
- Message queues
- Caches

Simply use EncryptedValue in your structs, and Silent will handle the encryption and decryption transparently whenever the data is serialized or deserialized.

[Full runnable example](https://pkg.go.dev/github.com/destel/silent#example-package-JsonEncryptAndDecrypt)
```go
type User struct {
    Username string                `json:"username"`
    Token    silent.EncryptedValue `json:"token"`
}
```

### Coming soon: BSON and more
I'm actively working on expanding Silent's support for more formats and storage systems. 
The first stable release will include support for BSON serialization, used in MongoDB.

 
## Advanced usage: creating custom EncryptedValue types
In some scenarios, you may need to use different encryption strategies or keys for different parts of your application. 
For example, you might have a requirement to encrypt sensitive user data with a specific encryption algorithm, 
while system-level data needs to be encrypted with a different algorithm or key. 
Silent provides the flexibility to handle such cases by allowing you to create custom EncryptedValue types, 
each bound to its own crypter instance.

Silent uses a type factory pattern to create custom EncryptedValue types. 
To ensure that each custom EncryptedValue type is unique, Silent employs a trick of 
creating distinct dummy types that are not used later in the code.

```go
// Define a type
type dummyType struct{} // this won't be used in your code
type CustomEncryptedValue = silent.EncryptedValueFactory[dummyType]

// Bind it to its own crypter
silent.BindCrypterTo[CustomEncryptedValue](customCrypter)
```

Now, you can use different encryption strategies or keys for different parts of your application.
```go
type User struct {
    Username string
    Token    silent.EncryptedValue
}

type Admin struct {
    Username string
    Token    CustomEncryptedValue
}
```