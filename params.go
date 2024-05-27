package crypto

import (
	"crypto/elliptic"
	"math/big"
)

var (
  theCurve = elliptic.P256()
  theCurveN = new(big.Int).Set(theCurve.Params().N)
)

var (
  // Generator point Hx,Hy of secp256r1
	//
	// Used as generator point for the value in Pedersen Commitments.
	// Created as NUMS (nothing-up-my-sleeve) curve point from SHA256 hash of G.
	// Details: Calculate sha256 of uncompressed serialization format of G, treat the
	// result as x-coordinate, find the first point on  curve with this x-coordinate
	// (which happens to exist on the curve)
	//
  // For secp256k1 and secp256r1 reference generator point values: http://www.secg.org/sec2-v2.pdf 
	Hx, _ = new(big.Int).SetString("698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be", 16)
	Hy, _ = new(big.Int).SetString("4992f5f57d7e55b0d637ed659b98857242597f00da1d893e681bf4c62627b249", 16)
	G1    = &Point{theCurve.Params().Gx, theCurve.Params().Gy}
	G2    = &Point{Hx, Hy}
)
