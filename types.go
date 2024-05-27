package crypto

import (
	"crypto/ecdsa"
	"math/big"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

type DistributionSharesBox struct {
  Commitments []*Point
	Shares      []*Share
	U           *big.Int
}

// Share includes the encrypted share and dleq information,
// DLEQ(G1,H1,G2,H2) == > DLEQ(H,X,PK,S)
// H is the second base point of ecc curve, X can be calculated both by dealer and participants( need the Commitments and Position),
// so H,X are not included in the struct directly
type Share struct {
	PK        *ecdsa.PublicKey
	Position  int
	S         *Point // Share
	challenge *big.Int
	response  *big.Int
}

// DecryptedShare includes the decrypted share and dleq information,
// DLEQ(G1,H1,G2,H2) ==> DLEQ(G,PK,S,Y)
type DecryptedShare struct {
	PK        *ecdsa.PublicKey
	Position  int
	S         *Point
	Y         *Point
	challenge *big.Int
	response  *big.Int
}

