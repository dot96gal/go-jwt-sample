package main

import (
	"crypto"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func makeHMACTokenString(secret []byte) (string, error) {
	claims := jwt.MapClaims{
		"user_id": 12345678,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secret)
}

func validateHMACTokenString(tokenString string, secret []byte) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Printf("user_id: %v\n", int64(claims["user_id"].(float64)))
		fmt.Printf("exp: %v\n", time.Unix(int64(claims["exp"].(float64)), 0))
		return true, nil
	} else {
		fmt.Println(err)
		return false, err
	}
}

func execHMAC() {
	hmacSecret := []byte("HMAC_SECRET")

	tokenString, err := makeHMACTokenString(hmacSecret)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("{%s}\n", tokenString)

	valid, err := validateHMACTokenString(tokenString, hmacSecret)
	if err != nil {
		log.Fatal(err)
	}
	if valid {
		fmt.Println("valid token")
	} else {
		fmt.Println("invalid token")
	}
}

func loadECDSAPrivateKeyFromDisk(path string) (crypto.PrivateKey, error) {
	privateKeyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	privateKey, err := jwt.ParseECPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func loadECDSAPublicKeyFromDisk(path string) (crypto.PublicKey, error) {
	publicKeyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	publicKey, err := jwt.ParseECPublicKeyFromPEM(publicKeyData)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func makeECDSATokenString(privateKey crypto.PrivateKey) (string, error) {
	claims := jwt.MapClaims{
		"user_id": 12345678,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	return token.SignedString(privateKey)
}

func validateECDSATokenString(tokenString string, publicKey crypto.PublicKey) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return publicKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Printf("user_id: %v\n", int64(claims["user_id"].(float64)))
		fmt.Printf("exp: %v\n", time.Unix(int64(claims["exp"].(float64)), 0))
		return true, nil
	} else {
		fmt.Println(err)
		return false, err
	}
}

func execECDSA() {
	privateKey, err := loadECDSAPrivateKeyFromDisk("./secret/id_ecdsa")
	if err != nil {
		log.Fatal(err)
	}

	tokenString, err := makeECDSATokenString(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("{%s}\n", tokenString)

	publicKey, err := loadECDSAPublicKeyFromDisk("./secret/id_ecdsa.pub.pkcs8")
	if err != nil {
		log.Fatal(err)
	}

	valid, err := validateECDSATokenString(tokenString, publicKey)
	if err != nil {
		log.Fatal(err)
	}

	if valid {
		fmt.Println("valid token")
	} else {
		fmt.Println("invalid token")
	}
}

func main() {
	execHMAC()
	execECDSA()
}
