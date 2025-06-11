package gosdk

import (
	"encoding/hex"
	"testing"

	"github.com/ChainSafe/go-schnorrkel"
)

func TestPre(t *testing.T) {
	skA, pkA, err := schnorrkel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	skB, pkB, err := schnorrkel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	skC, _, err := schnorrkel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// gen  key
	capsule, aesKey, err := GenPreKey(pkA)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("AES key:", hex.EncodeToString(aesKey))
	// decrypt key
	deAesKey, err := DecryptKey(skA, capsule)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("decrypt AES key:", hex.EncodeToString(deAesKey))
	// decrypt key with fake skA
	fdeAesKey, err := DecryptKey(skC, capsule)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("decrypt AES key with fake sk:", hex.EncodeToString(fdeAesKey))
	// generate re-encrypted key
	rk, xPk, err := GenReKey(skA, pkB)
	if err != nil {
		t.Fatal(err)
	}
	// re-encrypt key
	newCapsule, err := ReEncryptKey(rk, capsule)
	if err != nil {
		t.Fatal(err)
	}
	// decrypt re-encrypted key
	drAesKey, err := DecryptReKey(skB, newCapsule, xPk)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("decrypt re-encryption AES key:", hex.EncodeToString(drAesKey))
	// decrypt re-encrypted key with fake skB
	fdeReAesKey, err := DecryptReKey(skC, newCapsule, xPk)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("decrypt re-encryption AES key with fake skB:", hex.EncodeToString(fdeReAesKey))
}
