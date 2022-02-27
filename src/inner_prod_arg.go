package symmeproof

import (
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	"strconv"
)

/*
InnerProd Proof

This stores the argument values

*/
type InnerProdArg struct {
	X []ECPoint
	A *big.Int
	B *big.Int

	Challenges []*big.Int
}

func myHash(buf []byte) *big.Int {
	x := new(big.Int).SetInt64(0)
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			if i * 8 + j >= len(mi) {
				x.Mod(x, EC.N)
				if one.Cmp(x.Mod(new(big.Int).Mul(x, x), EC.N)) != 0 {
					fmt.Printf("Wrong challenge: %d\n", x)
				}
				return x
			}
			tmp := new(big.Int).Mul(ti[i * 8 + j], Mi[i * 8 + j])
			if (buf[i + 1] >> j) & 0x01 == 1 {
				tmp = tmp.Mul(tmp, new(big.Int).Sub(mi[i * 8 + j], one))
			}
			x = x.Add(x, tmp)
		}
	}
	x.Mod(x, EC.N)
	//x, _ := new(big.Int).SetString("486045032788235811830638878545834888637076321108634527871587439064599347504636433977794396925999365453377236211009", 10)
	return x
}

func GenerateNewParams(G, H []ECPoint, x *big.Int, X, P ECPoint) ([]ECPoint, []ECPoint, ECPoint) {
	nprime := len(G) / 2

	Gprime := make([]ECPoint, nprime)
	Hprime := make([]ECPoint, nprime)

	for i := range Gprime {
		//fmt.Printf("i: %d && i+nprime: %d\n", i, i+nprime)
		Gprime[i] = G[i].Add(G[i+nprime].Mult(x)) // G' = G1 + x * G2
		Hprime[i] = H[i].Add(H[i+nprime].Mult(x)) // H' = H1 + x * H2
	}


	Pprime := P.Add(X.Mult(x)) // P' = P + x * X

	return Gprime, Hprime, Pprime
}

/* Inner Product Argument
*/
func InnerProductProveSub(proof InnerProdArg, G, H []ECPoint, a []*big.Int, b []*big.Int, u ECPoint, P ECPoint) InnerProdArg {
	//fmt.Printf("Proof so far: %s\n", proof)
	if len(a) == 1 {
		// Prover sends a & b
		//fmt.Printf("a: %d && b: %d\n", a[0], b[0])
		proof.A = a[0]
		proof.B = b[0]
		return proof
	}

	curIt := int(math.Log2(float64(len(a)))) - 1

	nprime := len(a) / 2
	//fmt.Println(nprime)
	//fmt.Println(len(H))
	cl := InnerProduct(a[:nprime], b[nprime:]) // either this line
	cr := InnerProduct(a[nprime:], b[:nprime]) // or this line

	L := TwoVectorPCommitWithGens(G[nprime:], H[:nprime], a[:nprime], b[nprime:]).Add(u.Mult(cl))
	R := TwoVectorPCommitWithGens(G[:nprime], H[nprime:], a[nprime:], b[:nprime]).Add(u.Mult(cr))
	X := L.Add(R)

	proof.X[curIt] = X

	// prover sends L & R and gets a challenge
	s256 := sha256.Sum256([]byte(
		X.X.String() + X.Y.String()))

	//x := new(big.Int).SetBytes(s256[:])
	x := myHash(s256[:])

	proof.Challenges[curIt] = x

	Gprime, Hprime, Pprime := GenerateNewParams(G, H, x, X, P)
	//fmt.Printf("Prover - Intermediate Pprime value: %s \n", Pprime)

	// or these two lines
	aprime := VectorAdd(
		a[:nprime],
		ScalarVectorMul(a[nprime:], x)) // a' = a1 + x * a2
	bprime := VectorAdd(
		b[:nprime],
		ScalarVectorMul(b[nprime:], x)) // b' = b1 + x * b2

	return InnerProductProveSub(proof, Gprime, Hprime, aprime, bprime, u, Pprime)
}

func InnerProductProve(a []*big.Int, b []*big.Int, c *big.Int, P, U ECPoint, G, H []ECPoint) InnerProdArg {
	loglen := int(math.Log2(float64(len(a))))

	challenges := make([]*big.Int, loglen+1)
	Xvals := make([]ECPoint, loglen)

	runningProof := InnerProdArg{
		Xvals,
		big.NewInt(0),
		big.NewInt(0),
		challenges}

	// randomly generate an x value from public data
	x := sha256.Sum256([]byte(P.X.String() + P.Y.String()))

	runningProof.Challenges[loglen] = new(big.Int).SetBytes(x[:])

	Pprime := P.Add(U.Mult(new(big.Int).Mul(new(big.Int).SetBytes(x[:]), c)))
	ux := U.Mult(new(big.Int).SetBytes(x[:]))
	//fmt.Printf("Prover Pprime value to run sub off of: %s\n", Pprime)
	return InnerProductProveSub(runningProof, G, H, a, b, ux, Pprime)
}

/* Inner Product Verify
*/
func InnerProductVerify(c *big.Int, P, U ECPoint, G, H []ECPoint, ipp InnerProdArg) bool {
	//fmt.Println("Verifying Inner Product Argument")
	//fmt.Printf("Commitment Value: %s \n", P)
	s1 := sha256.Sum256([]byte(P.X.String() + P.Y.String()))
	chal1 := new(big.Int).SetBytes(s1[:])
	ux := U.Mult(chal1)
	curIt := len(ipp.Challenges) - 1

	if ipp.Challenges[curIt].Cmp(chal1) != 0 {
		fmt.Println("IPVerify - Initial Challenge Failed")
		return false
	}

	curIt -= 1

	Gprime := G
	Hprime := H
	Pprime := P.Add(ux.Mult(c)) // P' = P + (x*c)*u
	//fmt.Printf("New Commitment value with u^cx: %s \n", Pprime)

	for curIt >= 0 {
		Xval := ipp.X[curIt]

		// prover sends L & R and gets a challenge
		s256 := sha256.Sum256([]byte(
			Xval.X.String() + Xval.Y.String()))

		//chal2 := new(big.Int).SetBytes(s256[:])
		chal2 := myHash(s256[:])

		if ipp.Challenges[curIt].Cmp(chal2) != 0 {
			fmt.Println("IPVerify - Challenge verification failed at index " + strconv.Itoa(curIt))
			return false
		}

		Gprime, Hprime, Pprime = GenerateNewParams(Gprime, Hprime, chal2, Xval, Pprime)
		curIt -= 1
	}
	ccalc := new(big.Int).Mod(new(big.Int).Mul(ipp.A, ipp.B), EC.N) // c = a * b

	// a*G + b*H + c*ux
	Pcalc1 := Gprime[0].Mult(ipp.A)
	Pcalc2 := Hprime[0].Mult(ipp.B)
	Pcalc3 := ux.Mult(ccalc)
	Pcalc := Pcalc1.Add(Pcalc2).Add(Pcalc3)

	if !Pprime.Equal(Pcalc) {
		fmt.Println("IPVerify - Final Commitment checking failed")
		fmt.Printf("Final Pprime value: %s \n", Pprime)
		fmt.Printf("Calculated Pprime value to check against: %s \n", Pcalc)
		return false
	}

	return true
}

/* Inner Product Verify Fast
Given a inner product proof, verifies the correctness of the proof. Does the same as above except
we replace n separate exponentiations with a single multi-exponentiation.
*/

func InnerProductVerifyFast(c *big.Int, P, U ECPoint, G, H []ECPoint, ipp InnerProdArg) bool {
	//fmt.Println("Verifying Inner Product Argument")
	//fmt.Printf("Commitment Value: %s \n", P)
	s1 := sha256.Sum256([]byte(P.X.String() + P.Y.String()))
	chal1 := new(big.Int).SetBytes(s1[:])
	ux := U.Mult(chal1)
	curIt := len(ipp.Challenges) - 1

	// check first challenge
	if ipp.Challenges[curIt].Cmp(chal1) != 0 {
		fmt.Println("IPVerify - Initial Challenge Failed")
		return false
	}

	for j := curIt - 1; j >= 0; j-- {
		Xval := ipp.X[j]

		//prover sends L & R and gets a challenge
		s256 := sha256.Sum256([]byte(
			Xval.X.String() + Xval.Y.String()))

		//chal2 := new(big.Int).SetBytes(s256[:])
		chal2 := myHash(s256[:])

		if ipp.Challenges[j].Cmp(chal2) != 0 {
			fmt.Println("IPVerify - Challenge verification failed at index " + strconv.Itoa(j))
			return false
		}
	}
	// begin computing

	curIt -= 1
	Pprime := P.Add(ux.Mult(c)) // line 6 from protocol 1

	tmp1 := EC.Zero()
	for j := curIt; j >= 0; j-- {
		x := ipp.Challenges[j]		//x2 := new(big.Int).Exp(ipp.Challenges[j], big.NewInt(2), EC.N)
		//x2i := new(big.Int).ModInverse(x2, EC.N)

		//fmt.Println(tmp1)
		tmp1 = ipp.X[j].Mult(x).Add(tmp1)
		//fmt.Println(tmp1)
	}
	rhs := Pprime.Add(tmp1)

	sScalars := make([]*big.Int, EC.V)
	//invsScalars := make([]*big.Int, EC.V)

	for i := 0; i < EC.V; i++ {
		si := big.NewInt(1)
		for j := curIt; j >= 0; j-- {
			// original challenge if the jth bit of i is 0, otherwise challenge = 1
			chal := ipp.Challenges[j]
			if big.NewInt(int64(i)).Bit(j) == 1 {
				//chal = new(big.Int).ModInverse(chal, EC.N)
				chal = new(big.Int).SetInt64(1)
			}
			// fmt.Printf("Challenge raised to value: %d\n", chal)
			si = new(big.Int).Mod(new(big.Int).Mul(si, chal), EC.N)
		}
		//fmt.Printf("Si value: %d\n", si)
		sScalars[i] = si
		//invsScalars[i] = new(big.Int).ModInverse(si, EC.N)
	}

	ccalc := new(big.Int).Mod(new(big.Int).Mul(ipp.A, ipp.B), EC.N)
	lhs := TwoVectorPCommitWithGens(G, H, ScalarVectorMul(sScalars, ipp.A), ScalarVectorMul(sScalars, ipp.B)).Add(ux.Mult(ccalc))

	if !rhs.Equal(lhs) {
		fmt.Println("IPVerify - Final Commitment checking failed")
		fmt.Printf("Final rhs value: %s \n", rhs)
		fmt.Printf("Final lhs value: %s \n", lhs)
		return false
	}

	return true
}
