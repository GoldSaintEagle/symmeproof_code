// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package elliptic implements several standard elliptic curves over prime
// fields.
package symmeproof

// This package operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
// calculation can be performed within the transform (as in ScalarMult and
// ScalarBaseMult). But even for Add and Double, it's faster to apply and
// reverse the transform than to operate in affine coordinates.

import (
	"io"
	"math/big"
	"sync"
)

// A Curve represents a short-form Weierstrass curve with a=-3.
// See https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html
type Curve interface {
	// Params returns the parameters for the curve.
	Params() *CurveParams
	// IsOnCurve reports whether the given (x,y) lies on the curve.
	IsOnCurve(x, y *big.Int) bool
	// Add returns the sum of (x1,y1) and (x2,y2)
	Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int)
	// Double returns 2*(x,y)
	Double(x1, y1 *big.Int) (x, y *big.Int)
	// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
	ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int)
	// ScalarBaseMult returns k*G, where G is the base point of the group
	// and k is an integer in big-endian form.
	ScalarBaseMult(k []byte) (x, y *big.Int)


	GetY(x *big.Int) (*big.Int, bool)
	GetPoint(buf []byte) (ECPoint, bool)
}

var q, _ = new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)
var tq, _ = new(big.Int).SetString("31113198102954452147185586463257825348719852176590288178196863522396847884940", 10)

var M0, _ = new(big.Int).SetString("de04a371ff86fa6f2e9ec62a84edf0481e6cc3c04d8c2bfee011b6d7e3a0f14e72615d23cd1b53c8e730f38b93cd03", 16)
var M1, _ = new(big.Int).SetString("2500c5e8554129bd326fcbb1c0d252b6afbccb4ab7975caa7aad9e79509ad2e268658f85f7848df6d132d341edf7808", 16)
var M2, _ = new(big.Int).SetString("1633a9f1ccc0b2a4b7dcad6aa6e49807363e13933af46accb001c57bfd29b1bb0b7022e9fae921fa7d84e5278ec7b38", 16)
var M3, _ = new(big.Int).SetString("fdbc2882489a42c83547bde77359129b907c4d6e0f7b9ffeb6efac6471dc817e3993d828ea685fc10837f1c416a128", 16)
var M4, _ = new(big.Int).SetString("a177bcafffa7fbf3c4d0901eec4ff4918a7da5a321201fff2e9884fa19e969ad6a755b02c3b6c8921c80b11fb14f48", 16)
var M5, _ = new(big.Int).SetString("88a06494ec044b581cb079f2c7f4e2a288e07876571b2ec43b1e97e75100947f0b4f9bc7432482543f8095dfbd6a78", 16)
var M6, _ = new(big.Int).SetString("687aa744b47bc125431d8a6e5cac34d6a4e7e3a5ca23d877f0f946fc2ee2537035d3771fe80cdc224ead9fc9367e98", 16)
var M7, _ = new(big.Int).SetString("5d7b37586b972613ddbc1d8b2a7f21cd8612d9288c70ea1a794ad3b9376c2fb53da2422a0584c4f646657404dfea88", 16)
var M8, _ = new(big.Int).SetString("4d3943fb213a1453319b6651926905a9c7ccc9a70fd7b6426432aee6eb0053eec39c4ceb0fb0762f9e53cf256b0fa8", 16)
var M9, _ = new(big.Int).SetString("3d3f129b08b27a0d04087d4985c60d51b01e0108e941269e96168ab7244fb5536f0060507f33ad2e980d80fa5dbcf8", 16)
var M10, _ = new(big.Int).SetString("394b8504a50a0f146f20b744c77735c007da00f7d1f29fffb5b1fda31173db2d04be4995a0491de143eb99b06834e8", 16)
var M11, _ = new(big.Int).SetString("300100beb3ca284f6406a76323a9115bb38d2367d96a6a609f266cb90e9f56c4da75ea9ff4fefd5bdef5d3cb26e038", 16)
var M12, _ = new(big.Int).SetString("2b5213676a0dd9735a447197e7fc79cfa208bc0c8c025fffc7d18155d5002f158cf3c73f2e43c56be22f03d04eca58", 16)
var M13, _ = new(big.Int).SetString("294e42211dadf30ebb4736ba83e4d366b843dcfa1a559d05be8645bd00acd39786657689a32ec23148c79e6d511448", 16)
var M14, _ = new(big.Int).SetString("25ca5249df3d1a496487f627eb0d44221012835ca5b5d105415f9c661bda08648067b8b46446035e1c7544b044bb68", 16)
var M15, _ = new(big.Int).SetString("21831d804d362f763756c223662d935cffc32260a64575bc35247c33e865938498829ef6e9d3d2af3b0c3815117ab8", 16)
var M16, _ = new(big.Int).SetString("1e1aa9afffef971c17ad64a1f7fd8d0e1e28c81a133161158adb59e0870020b83238977a01c6f5aa6d731caf210ec8", 16)
var M17, _ = new(big.Int).SetString("1d1dfc414facfb12c729ce72b0e8a5ceb4409ff7a572e86492e4f2357e60a5f11b9742c5be9245be0523cc0184b1f8", 16)
var M18, _ = new(big.Int).SetString("1a8276dbf0a8f3df6cbb13d739e6eb04ca51c3504664cbf09505ef9f8257fe3edbfc578a0190a2d708801d147ca208", 16)
var M19, _ = new(big.Int).SetString("190420d6c2a6a53b669ae77490c7e16244545e2b4d3eaad10001fef7dff54a100ce34f006da55528aa466ac4023b28", 16)
var M20, _ = new(big.Int).SetString("1854ac36933c6194f393274046ad5cf65e8326fc86beb429f57cae56c849bf44369df52a7faed494436b102b59d758", 16)
var M21, _ = new(big.Int).SetString("167b9be4a8755d693bcf44accfe43f37e9282dbf3875e40cd91ef559e9af1532121057343ba8087c0a732262633868", 16)
var M22, _ = new(big.Int).SetString("15663aef3a8e8d57d324e4d5d54b5e19750d91534e6a0a68c251e67156b61116fb9a592b8c0ef8a7698f836d115488", 16)
var M23, _ = new(big.Int).SetString("13f4e94c678210c21572f22c17744f205ec79e8a183a9f47cf1b7adcc10b9720f064cbf7b664410f2eab3b48f365d8", 16)
var M24, _ = new(big.Int).SetString("124f8eccb36cc81e4876a96a6f407d6251af3d02aa06483f3f588dc2a149f98282d5e2bbb1e7dcaeeb7accd416bf18", 16)
var M25, _ = new(big.Int).SetString("6f0251b96ec5cef09712e04c6ac4098", 16)


var one = big.NewInt(1)
var twoInv, _ = new(big.Int).SetString("378128dc7fe1be9bcba7b18aa13b7c12079b30f013630affb8046db5f8e83c539c985748f346d4f239cc3ce2e4f340c", 16)

var Factors = []*big.Int{
	big.NewInt(2), big.NewInt(3), big.NewInt(5), big.NewInt(7),
	big.NewInt(11), big.NewInt(13), big.NewInt(17), big.NewInt(19), big.NewInt(23), big.NewInt(29),
	big.NewInt(31), big.NewInt(37), big.NewInt(41), big.NewInt(43), big.NewInt(47), big.NewInt(53),
	big.NewInt(59), big.NewInt(61), big.NewInt(67), big.NewInt(71), big.NewInt(73), big.NewInt(79),
	big.NewInt(83), big.NewInt(89), big.NewInt(97), q}

var mi = []*big.Int{
	big.NewInt(8), big.NewInt(3), big.NewInt(5), big.NewInt(7), big.NewInt(11), big.NewInt(13),
	big.NewInt(17), big.NewInt(19), big.NewInt(23), big.NewInt(29),	big.NewInt(31), big.NewInt(37),
	big.NewInt(41), big.NewInt(43), big.NewInt(47), big.NewInt(53),	big.NewInt(59), big.NewInt(61),
	big.NewInt(67), big.NewInt(71), big.NewInt(73), big.NewInt(79),	big.NewInt(83), big.NewInt(89),
	big.NewInt(97), q}

var Mi = []*big.Int{
	M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M16, M17, M18, M19, M20, M21, M22, M23, M24, M25}

var ti = []*big.Int{
	big.NewInt(3), big.NewInt(2), big.NewInt(4), big.NewInt(5), big.NewInt(8), big.NewInt(5),
	big.NewInt(9), big.NewInt(13), big.NewInt(21), big.NewInt(17), big.NewInt(9), big.NewInt(15),
	big.NewInt(27), big.NewInt(9), big.NewInt(38), big.NewInt(15), big.NewInt(33), big.NewInt(13),
	big.NewInt(29), big.NewInt(55), big.NewInt(30), big.NewInt(31), big.NewInt(7), big.NewInt(59),
	big.NewInt(16), tq}


// CurveParams contains the parameters of an elliptic curve and also provides
// a generic, non-constant time implementation of Curve.
type CurveParams struct {
	P       *big.Int // the order of the underlying field
	N       *big.Int // the order of the base point
	B       *big.Int // the constant of the curve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	BitSize int      // the size of the underlying field
	Name    string   // the canonical name of the curve
}

func (curve *CurveParams) Params() *CurveParams {
	return curve
}

func (curve *CurveParams) IsOnCurve(x, y *big.Int) bool {
	// y² = x³ + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3.Cmp(y2) == 0
}

// zForAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on the any of the curves handled here.
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file. If the point is ∞ it returns 0, 0.
func (curve *CurveParams) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.P)
	return
}

func (curve *CurveParams) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (curve *CurveParams) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, curve.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, curve.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, curve.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, curve.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, curve.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, curve.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, curve.P)

	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, curve.P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, curve.P)

	return x3, y3, z3
}

func (curve *CurveParams) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (curve *CurveParams) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b

	lambda1 := new(big.Int).Mul(x, x)
	tmp := new(big.Int).Set(lambda1)
	lambda1.Lsh(lambda1, 1)
	lambda1.Add(lambda1, tmp)
	lambda1.Mod(lambda1, curve.P) // 3 * x ^ 2

	lambda2 := new(big.Int).Lsh(y, 1)
	lambda2.Mul(lambda2, lambda2)
	tmp.Set(lambda2)
	tmp.Mod(tmp, curve.P)
	lambda2.Mul(lambda2, x)
	lambda2.Mod(lambda2, curve.P) // 4 * x * y ^ 2

	lambda3 := new(big.Int).Mul(tmp, tmp)
	//twoInv := new(big.Int).SetInt64(2)
	//twoInv.ModInverse(twoInv, curve.P)
	//fmt.Printf("%x\n", twoInv)
	lambda3.Mul(lambda3, twoInv)
	lambda3.Mod(lambda3, curve.P) // 8 * y ^ 4

	x3 := new(big.Int).Mul(lambda1, lambda1)
	tmp.Lsh(lambda2, 1)
	x3.Sub(x3, tmp)
	if x3.Sign() == -1 {
		x3.Add(x3, curve.P)
	}
	x3.Mod(x3, curve.P) // lambda1 ^ 2 - 2 * lambda2

	y3 := new(big.Int).Sub(lambda2, x3)
	if y3.Sign() == -1 {
		y3.Add(y3, curve.P)
	}
	y3.Mul(lambda1, y3)
	y3.Sub(y3, lambda3)
	if y3.Sign() == -1 {
		y3.Add(y3, curve.P)
	}
	y3.Mod(y3, curve.P) // lambda1 * (lambda2 - x3) - lambda3

	z3 := new(big.Int).Mul(y, z)
	z3.Lsh(z3, 1)
	z3.Mod(z3, curve.P) // 2 * y * z

	return x3, y3, z3
}

func (curve *CurveParams) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)

	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if byte&0x80 == 0x80 {
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			byte <<= 1
		}
	}

	return curve.affineFromJacobian(x, y, z)
}

func (curve *CurveParams) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

// GenerateKey returns a public/private key pair. The private key is
// generated using the given reader, which must return random data.
func GenerateKey(curve Curve, rand io.Reader) (priv []byte, x, y *big.Int, err error) {
	N := curve.Params().N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) >> 3
	priv = make([]byte, byteLen)

	for x == nil {
		_, err = io.ReadFull(rand, priv)
		if err != nil {
			return
		}
		// We have to mask off any excess bits in the case that the size of the
		// underlying field is not a whole number of bytes.
		priv[0] &= mask[bitSize%8]
		// This is because, in tests, rand will return all zeros and we don't
		// want to get the point at infinity and loop forever.
		priv[1] ^= 0x42

		// If the scalar is out of range, sample another random number.
		if new(big.Int).SetBytes(priv).Cmp(N) >= 0 {
			continue
		}

		x, y = curve.ScalarBaseMult(priv)
	}
	return
}

// Marshal converts a point into the uncompressed form specified in section 4.3.6 of ANSI X9.62.
func Marshal(curve Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	yBytes := y.Bytes()
	copy(ret[1+2*byteLen-len(yBytes):], yBytes)
	return ret
}

// Unmarshal converts a point, serialized by Marshal, into an x, y pair.
// It is an error if the point is not in uncompressed form or is not on the curve.
// On error, x = nil.
func Unmarshal(curve Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if len(data) != 1+2*byteLen {
		return
	}
	if data[0] != 4 { // uncompressed form
		return
	}
	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, nil
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

var initonce sync.Once
var p24_256 *CurveParams

func initAll() {
	initCurve()
}

func initCurve() {
	// See FIPS 186-3, section D.2.4
	p24_256 = &CurveParams{Name: "P-24-256"}
	p24_256.P, _ = new(big.Int).SetString("6f0251b8ffc37d37974f63154276f8240f3661e026c615ff7008db6bf1d078a73930ae91e68da9e4739879c5c9e6817", 16)
	p24_256.N, _ = new(big.Int).SetString("6f0251b8ffc37d37974f63154276f8240f3661e026c615ff7008db6bf1d078a73930ae91e68da9e4739879c5c9e6818", 16)
	//p24_256.P, _ = new(big.Int).SetString("1d", 16)
	//p24_256.N, _ = new(big.Int).SetString("1e", 16)
	p24_256.B, _ = new(big.Int).SetString("1", 16)
	p24_256.Gx, _ = new(big.Int).SetString("7c9402ba2a66450571c1bcdb1e74c4f3259d71331f428ecb1c849a9dae9cf39c132e1089c77efedc5f6ee7796a2945", 16)
	p24_256.Gy, _ = new(big.Int).SetString("81e2c493c34bbca6ca6ec554ac4daf9df84a2ed3838695423c38afe7e660bceb91aa5888d39fec9e4db535eb20d342", 16)
	p24_256.BitSize = 380
}

// P384 returns a Curve which implements P-384 (see FIPS 186-3, section D.2.4)
//
// The cryptographic operations do not use constant-time algorithms.
func P24_256() Curve {
	initonce.Do(initAll)
	return p24_256
}

func (curve *CurveParams) GetY(x *big.Int) (*big.Int, bool) {
	one := new(big.Int).SetInt64(1)
	y := new(big.Int).Mul(x, x)
	y.Mul(y, x)
	y.Add(y, one)
	ycheck := y.ModSqrt(y, curve.P)
	if ycheck == nil {
		return nil, false
	}
	return y, true
}

func (curve *CurveParams) GetPoint(buf []byte) (ECPoint, bool) {
	point := ECPoint{}
	x := new(big.Int).SetBytes(buf)
	y, ycheck := curve.GetY(x)
	if ycheck == false {
		return point, false
	}
	point = ECPoint{x, y}
	return point, true
}
