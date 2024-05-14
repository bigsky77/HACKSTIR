// Package main implements the STIR protocol
// https://eprint.iacr.org/2024/390
package main

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/iop"
)

// represents a Prover instance
type instance struct {

	// Polynomial
	p *iop.Polynomial

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

	// FiatShamir parameters
}

func main() {
	println("=========================================")
	println("STIR")

	n := 24
	p := buildRandomPolynomial(n)
	instance := newInstance(n, p)

	// commit()
	witness := commit(p)

	// prover()
	instance.prover(witness)

	// verifier()
	verifier()

	println("=========================================")
}

func newInstance(n int, p *iop.Polynomial) *instance {

	return &instance{
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
}

func commit(p *iop.Polynomial) *iop.Polynomial {
	println("Commit")

	//n := uint64(p.Size())

	// domain
	//domain := fft.NewDomain(n)

	// evaluate over domain

	return p
}

func (s *instance) prover(witness *iop.Polynomial) {
	println("Prover")
}

func verifier() {
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
