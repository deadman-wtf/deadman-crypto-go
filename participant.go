package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"
)

type Participant struct {
	PK        *ecdsa.PublicKey
	position  int
	share     *Point
	challenge *big.Int
	response  *big.Int
}

type Dealer struct {
	Participant
	privateKey *ecdsa.PrivateKey
}

func NewDealer(private *ecdsa.PrivateKey) *Dealer {
  return &Dealer{
    Participant: Participant{PK: &private.PublicKey},
    privateKey: private,
  }
}

func (d *Dealer) DistributeSecret(secret *big.Int, pks []*ecdsa.PublicKey, threshold int) (*DistributionSharesBox, error) {
  if len(pks) < threshold {
    return nil, errors.New(fmt.Sprintf("len of public_keys(%d) < threshold(%d). ", len(pks), threshold))
  }

  // generates a random polynomial of degree t-1
	poly, err := InitPolynomial(threshold-1, theCurveN)
	if err != nil {
		return nil, err
	}

  // initialize the participant's Position
	shares := make([]*Share, len(pks))
	for i, pk := range pks {
		shares[i] = &Share{
			PK:       pk,
			Position: i + 1,
		}
	}

	return d.distribute(secret, shares, threshold, poly)
}

func (d *Dealer) ExtractSecretShare(sharesBox *DistributionSharesBox) (*DecryptedShare, error) {
	// find share for the dealer itself
	var share *Share
	for _, s := range sharesBox.Shares {
		if s.PK.X.Cmp(d.privateKey.X) == 0 && s.PK.Y.Cmp(d.privateKey.Y) == 0 {
			share = s
			break
		}
	}
	if share == nil {
		return nil, errors.New("no share for me")
	}
	return d.extractSecretShare(share)
}

func (d *Dealer) extractSecretShare(share *Share) (*DecryptedShare, error) {
	// Decryption of the shares.
	// Using its private key x_i, each participant finds the decrypted share S_i from Y_i by computing S_i = Y_i·(1/x_i mod N).
	// Y_i is encrypted share: Y_i := (p(i)mod N)·PK_i
	// find modular multiplicative inverses of private key
	privateInverse := new(big.Int).ModInverse(d.privateKey.D, theCurveN)
	six, siy := theCurve.ScalarMult(share.S.X, share.S.Y, privateInverse.Bytes())

	// To this end it suffices to prove knowledge of an α such that PK_i= G·α and Y'_i= S_i·α,
	// which is accomplished by the non-interactive version of the protocol DLEQ(G,PK_i,S_i,Y'_i).
	// DLEQ(G,PK_i,S_i,Y'_i) => DLEQ(G, publickey, decrypted_share, encryted_share) ,
	// where the encryted_share IS NOT the distributed share, but IS the value x_i·S_i .
	// All of this is to prove and tell participants that the decrypted share is must use your own public key encrypted,
	// and only you can decrypt the share with your own private key and verify the share's proof.
	w, err := rand.Int(rand.Reader, theCurveN)
	if err != nil {
		return nil, err
	}
	dleq := NewDLEQ(G1, &Point{d.PK.X, d.PK.Y}, &Point{six, siy}, nil, w, d.privateKey.D)
	c, r := dleq.ChallengeAndResponse()
	decShare := &DecryptedShare{
		PK:        d.PK,
		Position:  share.Position,
		S:         dleq.G2,
		Y:         dleq.H2,
		challenge: c,
		response:  r,
	}
	return decShare, nil
}

// VerifyDistributionShares verifies that the distribution shares are consistent so that they can be used to reconstruct the secret later.
func VerifyDistributionShares(sharesBox *DistributionSharesBox) bool {
	if sharesBox == nil {
		return false
	}
	if len(sharesBox.Shares) < len(sharesBox.Commitments) {
		return false
	}

	// Verification of the shares.
	// The verifier computes X_i = ∑(j = 0 -> t - 1): (C_j)·(i^j) from the C_j values.
	// Using PK_i,X_i,Y_i,r_i,c_i 1 ≤ i ≤ n as input, the verifier computes A_1i,A_2i as:
	// A_1i = H·(r_i) + X_i·c_i,   A_2i = PK_i·(r_i) + Y_i·c_i
	// and checks that the hash of X_i,Y_i, A_1i, A_2i,  1 ≤ i ≤ n, matches c_i.

	// variables for reuse
	hasher := sha3.New256()

	Cj := sharesBox.Commitments
	bigi, bigj, bigij := new(big.Int), new(big.Int), new(big.Int)
	H := &Point{Hx, Hy}

	Xix, Xiy, Cijx, Cijy := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	for _, share := range sharesBox.Shares {
		Xix.Set(Cj[0].X)
		Xiy.Set(Cj[0].Y)
		for j := 1; j < len(Cj); j++ {
			bigi.SetInt64(int64(share.Position))
			bigj.SetInt64(int64(j))
			bigij.Exp(bigi, bigj, theCurveN)                                 // i^j mod N
			Cijx, Cijy = theCurve.ScalarMult(Cj[j].X, Cj[j].Y, bigij.Bytes()) // C_j · i^j
			Xix, Xiy = theCurve.Add(Xix, Xiy, Cijx, Cijy)
		}
		//log.Printf("Verify Xi: %s, %s\n", Xix.Text(16), Xiy.Text(16))

		// DLEQ(H,X_i,PK_i,Y_i)
		ok := DLEQVerify(hasher, H, &Point{X: Xix, Y: Xiy}, &Point{X: share.PK.X, Y: share.PK.Y}, share.S, share.challenge, share.response)
		if !ok {
			return false
		}
	}
	return true
}

// VerifyDecryptedShare verify a decrypted share publicly.
func VerifyDecryptedShare(decShare *DecryptedShare) bool {
	hasher := sha3.New256()
	return DLEQVerify(hasher, G1, &Point{decShare.PK.X, decShare.PK.Y}, decShare.S, decShare.Y, decShare.challenge, decShare.response)
}

// ReconstructSecret reconstruct the secret publicly by using no-less-than threshold number of decrypted shares.
func ReconstructSecret(decShares []*DecryptedShare, u *big.Int) *big.Int {
	// Pooling the shares. Suppose
	// w.l.o.g. that  participants P(i) produce  correct values for S_i, for i= 1,...,t.
	// The secret s·G is obtained by Lagrange interpolation:
	// ∑(i=1->t)(λ_i·S_i) = ∑(i=1->t)(λ_i·(p(i)·G)) = G·(∑(i=1->t)p(i)*λ_i = G·p(0) = G·s,
	// where λ_i= ∏(j≠i)j/(j−i) is a Lagrange coefficient.
	bigjs := make(map[int]*big.Int)
	for _, ds := range decShares {
		bigjs[ds.Position] = big.NewInt(int64(ds.Position))
	}
	sGx, sGy := new(big.Int), new(big.Int)
	for _, ds := range decShares {
		//  λ_i
		lambda := lagrangeCoefficient(ds.Position, bigjs)
		lambdaSix, lambdaSiy := theCurve.ScalarMult(ds.S.X, ds.S.Y, lambda.Bytes())
		sGx, sGy = theCurve.Add(sGx, sGy, lambdaSix, lambdaSiy)
	}

	// secret = U xor SHA256(s · G)
	hash256 := Hash(sha3.New256(), sGx, sGy)
	secret := new(big.Int).Xor(u, new(big.Int).SetBytes(hash256))
	return secret
}

// lagrangeCoefficient returns  λ_i
//
// where λ_i= ∏(j≠i)j/(j−i) mod n is a Lagrange coefficient.
// 1 <= i <= threshold  0 <= j < threshold
// bigjs is a map of j->big.NewInt(j)
// The returned values are already mod n
func lagrangeCoefficient(i int, bigjs map[int]*big.Int) *big.Int {
	numerator, denominator := big.NewInt(1), big.NewInt(1)
	jsubi := new(big.Int)
	bi := big.NewInt(int64(i))
	for j, bj := range bigjs {
		if j != i {
			numerator.Mul(numerator, bj)
			// jsubi will be reset to the value bj-bi, so it's safe to just reuse it
			jsubi.Sub(bj, bi)
			denominator.Mul(denominator, jsubi)
		}
	}
	numerator.Mod(numerator, theCurveN)
	inverseDenom := new(big.Int).ModInverse(denominator, theCurveN)
	numerator.Mul(numerator, inverseDenom)
	numerator.Mod(numerator, theCurveN)
	return numerator
}
