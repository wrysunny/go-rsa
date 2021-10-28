package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/wonderivan/logger"
	"log"
	"math/big"
)

func GenRSAKey(length int) (privatekey []byte, pubilckey []byte){
	// 真随机数 unix、linux  /dev/urandom. On Windows systems, Reader uses the RtlGenRandom API.
	prikey, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		logger.Error("Error GenerateKey Fail !")
		return nil, nil
	}
	pubkey := &prikey.PublicKey
	// MarshalPKCS1PrivateKey converts an RSA private key to PKCS #1, ASN.1 DER form.
	pristream := x509.MarshalPKCS1PrivateKey(prikey)
	/*
	type Block struct {
	    Type    string
	    Headers map[string]string
	    Bytes   []byte
	}
	A Block represents a PEM encoded structure.
	The encoded form is:
	   -----BEGIN Type-----
	   Headers
	   base64-encoded Bytes
	   -----END Type-----
	 */
	// 加密保存到内存
	privatekey = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pristream,
	})
	// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form.
	pkixderstream, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		logger.Error("Error Marshal PKIX Public Key !")
	}
	pubilckey = pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY",
		Bytes: pkixderstream,
	})
	// 可以保存到数据库中
	logger.Info("Gen %d Bit Rsa Key Success.",length)
	return
}


// 私钥解密消息
func PrivateDecrypt(privatekey []byte, SecretMessage []byte) (ciphertext []byte) {
	// 获取私钥
	pri, err := FormatPrivatekey(privatekey)
	if err != nil {
		logger.Error("Format private Failed.", err.Error())
	}
	// 解密
	ciphertext, err = rsa.DecryptOAEP(sha512.New(), rand.Reader, pri, SecretMessage, []byte("public"))
	if err != nil {
		logger.Error("Decrypt Msg Failed.", err.Error())
	}
	logger.Info("Private Decrypt Message: ", ciphertext)
	return ciphertext
}

// 私钥加密/签名消息
func PrivateEncrypt(privatekey []byte, ciphertext []byte) (signature []byte) {
	// 获取私钥
	pri, err := FormatPrivatekey(privatekey)
	if err != nil {
		logger.Error("Format Private Failed.", err.Error())
	}
	// 签名
	// func SignPSS(rand io.Reader, priv *PrivateKey, hash crypto.Hash, digest []byte, opts *PSSOptions) ([]byte, error)
	// func SignPKCS1v15(rand io.Reader, priv *PrivateKey, hash crypto.Hash, hashed []byte) ([]byte, error)
	signature, err = rsa.SignPKCS1v15(rand.Reader, pri, crypto.Hash(0), ciphertext)
	if err != nil {
		logger.Error("Private Sign Message Failed. ", err.Error())
	}
	logger.Info("Private Encrypt Signature Message: ", signature)
	return
}

// 公钥解密/验证消息
func PublicDecrypt(publickey []byte, signature []byte) (ciphertext []byte){
	// 获取公钥
	pub, err := FormatPublickey(publickey)
	if err != nil {
		logger.Error("Format Public Failed.", err.Error())
	}
	// 验签
	// func VerifyPSS(pub *PublicKey, hash crypto.Hash, digest []byte, sig []byte, opts *PSSOptions) error
	// func VerifyPKCS1v15(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error
	c := new(big.Int)
	m := new(big.Int)
	m.SetBytes(signature)
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	out := c.Bytes()
	skip := 0
	for i := 2; i < len(out); i++ {
		if i+1 >= len(out) {
			break
		}
		if out[i] == 0xff && out[i+1] == 0 {
			skip = i + 2
			break
		}
	}
	logger.Info("Public Decrypt Message: ", out[skip:])
	return out[skip:]
}

// 公钥加密消息
func PublicEncrypt(publickey []byte, ciphertext []byte) (SecretMessage []byte){
	pub,err := FormatPublickey(publickey)
	if err!= nil {
		logger.Alert("Format Publickey Failed.", err.Error())
	}
	// 加密
	ciphertext, err = rsa.EncryptOAEP(sha512.New(), rand.Reader, pub, ciphertext, []byte("public"))
	if err != nil {
		logger.Alert("Encrypt Msg Failed.", err.Error())
	}
	logger.Info("Public Encrypt Secret Message: ", ciphertext)
	return ciphertext
}

// 解析公钥
func FormatPublickey(publickey []byte) (public *rsa.PublicKey, err error){
	// 解析公钥
	block, _ := pem.Decode(publickey)
	if block == nil || block.Type != "PUBLIC KEY" {
		logger.Error("failed to decode PEM block containing public key.")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.Alert("x509: unknown format", err.Error())
		return nil, errors.New("x509: unknown format")
	}
	return pub.(*rsa.PublicKey), nil
}

// 解析私钥
func FormatPrivatekey(privatekey []byte) (private *rsa.PrivateKey, err error){
	// 解析公钥
	block, _ := pem.Decode(privatekey)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		logger.Error("failed to decode PEM block containing private key.")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		logger.Alert("x509: unknown format", err.Error())
		return nil, errors.New("x509: unknown format")
	}
	return pri, nil
}

func main() {
	privatekey, publickey := GenRSAKey(2048)
	enmsg := PublicEncrypt(publickey,[]byte("hello 你好 Golang!!@#$%^&*()986543svd  dw"))
	log.Println(string(enmsg))
	msg := PrivateDecrypt(privatekey,enmsg)
	log.Println(string(msg))
	sign := PrivateEncrypt(privatekey, []byte("ss000000"))
	log.Println(string(PublicDecrypt(publickey, sign)))


}