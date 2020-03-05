package security

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"
)

const plainText = "Hello Go 2020"

func TestEncryptDecrypt(t *testing.T) {

	key, err := GenerateKey()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log("KEY:", base64.StdEncoding.EncodeToString(key[:]))

	cipherText, err := Encrypt(key[:], []byte(plainText))
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	encoded := base64.StdEncoding.EncodeToString(cipherText)

	t.Log(encoded)

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	p, err := Decrypt(key[:], []byte(decoded))
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	if !bytes.Equal(cipherText, decoded) || string(p) != plainText {
		t.Error("Invalid ")
		t.FailNow()
	}

	t.Log(string(p))
}

