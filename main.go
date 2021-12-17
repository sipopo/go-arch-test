package main

import (
	// "encoding/json"
	"fmt"
	"log"
	"golang.org/x/crypto/bcrypt"

)


func main() {
	password := "12345678"

	hash, err := hashPassword(password)
	if err != nil {
		log.Fatalf("something wrong with hash %w", err)
	}
	fmt.Printf("You hash of password is %s \n", hash)

	err = comparePassword("password", hash)
	if err != nil {
		log.Fatalf("Password is not correct, error: %s", err)
	}
	log.Println("Everething ok !")
}

func hashPassword(password string) ([]byte, error){
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

func comparePassword(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	return err
}