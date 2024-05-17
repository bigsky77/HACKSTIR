// Package main implements the STIR protocol
// https://eprint.iacr.org/2024/390
package main

import (
	"hash"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/iop"
)

// represents a Prover instance
type instance struct {

	// Polynomial
	p *iop.Polynomial

	// Domain
	domain0 *fft.Domain

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

	s.domain0 = fft.NewDomain(uint64(p.Size()))

	return &s
}

func (s *instance) commit(p *iop.Polynomial) (Witness, Commitment) {
	println("Commit")

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
