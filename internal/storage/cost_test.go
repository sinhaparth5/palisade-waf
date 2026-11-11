package storage

import "golang.org/x/crypto/bcrypt"

// bcrypt at the production cost would add about a quarter second per account.
func init() { PasswordCost = bcrypt.MinCost }
