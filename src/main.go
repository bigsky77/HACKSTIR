// Package main implements the STIR protocol
// https://eprint.iacr.org/2024/390
package main

import (
	"hash"
	"math/bits"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/iop"
)

// CHECK Correctness
const rho = 8

// represents a Prover instance
type instance struct {

	// Polynomial
	p *iop.Polynomial

	// Domain
	domain *fft.Domain

	// nbSteps
	nbSteps int

	// Protocl parameters
	securityLevel         uint64
	protocolSecurityLevel uint64
	initialDegree         uint64
	finalDegree           uint64
	rate                  uint64
	verifierRepetitions   uint64
	stirFoldingFactor     uint64
	friFoldingFactor      uint64

	// Merkle tree parameters
	h hash.Hash

	// FiatShamir parameters
}

// represents a Witness
type Witness struct {
	tree merkletree.Tree
}

// represents a Commitment
type Commitment struct {
}

// represents a Proof
type Proof struct {
}

func main() {
	println("=========================================")
	println("STIR")

	// degree
	n := 24
	p := buildRandomPolynomial(n)
	prover := newInstance(n, p)

	// commit()
	witness, commitment := prover.commit(p)

	// prover()
	proof := prover.prove(witness)

	// verifier()
	verifier(commitment, proof)

	println("=========================================")
}

func newInstance(n int, p *iop.Polynomial) *instance {

	s := instance{
		p:                     p,
		securityLevel:         128,
		protocolSecurityLevel: 128,
		initialDegree:         uint64(n),
		finalDegree:           6,
		rate:                  2,
		verifierRepetitions:   1000,
		stirFoldingFactor:     16,
		friFoldingFactor:      8,
	}

	// build Domain
	size := p.Size()
	np := ecc.NextPowerOfTwo(uint64(size))

	// extending the domain
	np = np * rho

	s.domain = fft.NewDomain(np)

	//steps
	s.nbSteps = bits.TrailingZeros(uint(n))

	return &s
}

func (s *instance) commit(p *iop.Polynomial) (Witness, Commitment) {
	println("Commit")

	// evaluate p
	// evaluate p and sort the result
	coef := p.Coefficients()

	_p := make([]fr.Element, s.domain.Cardinality)
	copy(_p, coef)
	s.domain.FFT(_p, fft.DIF)
	fft.BitReverse(_p)

	// stack evaluations
	stackEvaluations(_p, int(s.stirFoldingFactor))

	// Merkle tree
	tree := merkletree.New(s.h)

	//
	w := Witness{
		tree: *tree,
	}

	c := Commitment{}

	return w, c

}

func (s *instance) prove(witness Witness) Proof {
	println("Prover")

	p := Proof{}

	return p
}

func verifier(c Commitment, p Proof) {
	println("Verifier")
}

// return a random polynomial of degree n, if n==-1 cancel the blinding
func buildRandomPolynomial(n int) *iop.Polynomial {
	var a []fr.Element
	if n == -1 {
		a := make([]fr.Element, 1)
		a[0].SetZero()
	} else {
		a = make([]fr.Element, n+1)
		for i := 0; i <= n; i++ {
			a[i].SetRandom()
		}
	}
	res := iop.NewPolynomial(&a, iop.Form{
		Basis: iop.Canonical, Layout: iop.Regular})
	return res
}

func stackEvaluations(evals []fr.Element, foldingFactor int) [][]fr.Element {
	if len(evals)%foldingFactor != 0 {
		panic("Evaluations length must be divisible by folding factor")
	}

	sizeOfNewDomain := len(evals) / foldingFactor
	stackedEvaluations := make([][]fr.Element, sizeOfNewDomain)

	for i := 0; i < sizeOfNewDomain; i++ {
		newEvals := make([]fr.Element, foldingFactor)
		for j := 0; j < foldingFactor; j++ {
			newEvals[j] = evals[i+j*sizeOfNewDomain]
		}
		stackedEvaluations[i] = newEvals
	}

	return stackedEvaluations
}
