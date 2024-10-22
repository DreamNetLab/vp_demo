package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
)

type Signature struct {
	R, S *big.Int
}

func (s *Signature) ToByte() []byte {
	sign, _ := json.Marshal(*s)
	return sign
}

func (s *Signature) ByteToSign(sign []byte) {
	var signature Signature
	json.Unmarshal(sign, &signature)
	s.R = signature.R
	s.S = signature.S
}

func GenPrivateKey() *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("generate private key err:" + err.Error())
	}
	return privateKey
}

func GenPublicKey(privateKey *ecdsa.PrivateKey) *ecdsa.PublicKey {
	return &privateKey.PublicKey
}

func Sign(data []byte, privateKey *ecdsa.PrivateKey) *Signature {
	dataHash := sha256.Sum256(data)
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, dataHash[:])

	return &Signature{r, s}
}

func Verify(data []byte, signature Signature, publicKey *ecdsa.PublicKey) bool {
	dataHash := sha256.Sum256(data)
	valid := ecdsa.Verify(publicKey, dataHash[:], signature.R, signature.S)
	return valid
}
