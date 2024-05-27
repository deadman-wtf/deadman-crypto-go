# deadman-crypto-go

This is a fork of go-pvss that is modified to use the P256 (secp256r1) curve as
it is compliant with HTTP signature auth.

This repository contains the cryptography for:

- Publicly verifiable secret sharing scheme
- DLEQ zero-knowledge-proofs

## Generator point verification for curve

```python
import hashlib
import binascii

# Finite field prime
p256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

# Curve parameters for the curve equation: y^2 = x^3 + a256*x +b256
a256 = p256 - 3
b256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

# Curve order
qq = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Create a finite field of order p256
FF = GF(p256)

# Define a curve over that field with specified Weierstrass a and b parameters
secp256r1 = EllipticCurve([FF(a256), FF(b256)])

# Since we know P-256's order we can skip computing it and set it explicitly
secp256r1.set_order(qq)
# Base point (x, y)
hasher = hashlib.sha256(binascii.unhexlify('046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5'))
hash_of_g_as_int = Integer(int(hasher.hexdigest(),16))

POINT_H = secp256r1.lift_x(hash_of_g_as_int)
'secp256r1: %x %x'%POINT_H.xy()
```
