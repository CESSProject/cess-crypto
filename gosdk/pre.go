package gosdk

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/ristretto255"
	"github.com/pkg/errors"
)

type Capsule struct {
	E *ristretto255.Element
	V *ristretto255.Element
	S *ristretto255.Scalar
}

func GenPreKey(pkA *schnorrkel.PublicKey) (*Capsule, []byte, error) {
	// generate E,V key-pairs
	skE, pkE, err := schnorrkel.GenerateKeypair()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate key error")
	}
	skV, pkV, err := schnorrkel.GenerateKeypair()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate key error")
	}
	// get H(E || V)
	ebpk := pkToElement(pkE).Encode([]byte{})
	vbpk := pkToElement(pkV).Encode([]byte{})
	h := hashAndConvToScalar(append(ebpk[:], vbpk[:]...))
	// get s = v + e * H(E || V)
	s := ristretto255.NewScalar().Add(
		skToScalar(skV),
		ristretto255.NewScalar().Multiply(skToScalar(skE), h),
	)
	// get (pk_A)^{e+v}
	point := pkToElement(pkA)
	point.ScalarMult(
		ristretto255.NewScalar().Add(
			skToScalar(skE),
			skToScalar(skV),
		),
		point,
	)
	// gen AES key
	txtBytes, err := point.MarshalText()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate key error")
	}
	key := sha256.Sum256(txtBytes)

	return &Capsule{
		E: pkToElement(pkE),
		V: pkToElement(pkV),
		S: s,
	}, key[:], nil
}

func DecryptKey(sk *schnorrkel.SecretKey, capsule *Capsule) ([]byte, error) {
	// get (pk_A)^{e+v}
	point := ristretto255.NewElement().ScalarMult(
		skToScalar(sk),
		ristretto255.NewElement().Add(capsule.E, capsule.V),
	)
	// gen AES key
	txtBytes, err := point.MarshalText()
	if err != nil {
		return nil, errors.Wrap(err, "decrypt key error")
	}
	key := sha256.Sum256(txtBytes)

	return key[:], nil
}

func GenReKey(skA *schnorrkel.SecretKey, pkB *schnorrkel.PublicKey) (*ristretto255.Scalar, *schnorrkel.PublicKey, error) {
	// generate x,X key-pair
	skX, pkX, err := schnorrkel.GenerateKeypair()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate re-encryption key error")
	}
	// get d=H(X||pk_B||pk_B^{x})
	xbpk, bbpk := pkX.Encode(), pkB.Encode()
	point := ristretto255.NewElement().ScalarMult(skToScalar(skX), pkToElement(pkB))
	txt, err := point.MarshalText()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate re-encryption key error")
	}
	d := hashAndConvToScalar(append(append(xbpk[:], bbpk[:]...), txt...))
	rk := ristretto255.NewScalar().Multiply(skToScalar(skA), d.Invert(d))
	return rk, pkX, nil
}

func ReEncryptKey(rk *ristretto255.Scalar, capsule *Capsule) (*Capsule, error) {
	// check sG==V+H(E||V)E
	sG := ristretto255.NewElement().ScalarBaseMult(capsule.S)
	ebpk := capsule.E.Encode([]byte{})
	vbpk := capsule.V.Encode([]byte{})
	h := hashAndConvToScalar(append(ebpk[:], vbpk[:]...))
	point := ristretto255.NewElement().Add(
		capsule.V,
		ristretto255.NewElement().ScalarMult(h, capsule.E),
	)
	if point.Equal(sG) != 1 {
		return nil, errors.Wrap(errors.New("invalid params"), "re-encrypt key error")
	}
	txt, err := capsule.S.MarshalText()
	if err != nil {
		return nil, errors.Wrap(err, "re-encrypt key error")
	}
	newS := ristretto255.NewScalar()
	if err = newS.UnmarshalText(txt); err != nil {
		return nil, errors.Wrap(err, "re-encrypt key error")
	}
	return &Capsule{
		E: ristretto255.NewElement().ScalarMult(rk, capsule.E),
		V: ristretto255.NewElement().ScalarMult(rk, capsule.V),
		S: newS,
	}, nil
}

func DecryptReKey(skB *schnorrkel.SecretKey, newCapsule *Capsule, pkX *schnorrkel.PublicKey) ([]byte, error) {
	// S= pkX^{skB}
	S := ristretto255.NewElement().ScalarMult(skToScalar(skB), pkToElement(pkX))
	txt, err := S.MarshalText()
	if err != nil {
		return nil, errors.Wrap(err, "decrypt re-encryption key error")
	}
	// recreate d=H(pkX || pkB || S)
	pkB, err := skB.Public()
	if err != nil {
		return nil, errors.Wrap(err, "decrypt re-encryption key error")
	}
	xbpk, bbpk := pkX.Encode(), pkB.Encode()
	d := hashAndConvToScalar(append(append(xbpk[:], bbpk[:]...), txt...))
	point := ristretto255.NewElement().ScalarMult(
		d,
		ristretto255.NewElement().Add(
			newCapsule.E,
			newCapsule.V,
		),
	)
	txtBytes, err := point.MarshalText()
	if err != nil {
		return nil, errors.Wrap(err, "decrypt re-encryption key error")
	}
	key := sha256.Sum256(txtBytes)
	return key[:], nil
}

func skToScalar(sk *schnorrkel.SecretKey) *ristretto255.Scalar {
	s := ristretto255.NewScalar()
	bs := sk.Encode()
	s.Decode(bs[:])
	return s
}

func pkToElement(pk *schnorrkel.PublicKey) *ristretto255.Element {
	e := ristretto255.NewElement()
	bpk := pk.Encode()
	e.Decode(bpk[:])
	return e
}

func hashAndConvToScalar(data []byte) *ristretto255.Scalar {
	hash := sha512.Sum512(data)
	return ristretto255.NewScalar().FromUniformBytes(hash[:])
}
