// Package main implements the STIR protocol
// https://eprint.iacr.org/2024/390
package main

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"math/bits"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/iop"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"

	"github.com/consensys/gnark/logger"
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
	// TODO check that is corresponds to number of rounds
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
	domain fft.Domain
	p      *iop.Polynomial
	tree   merkletree.Tree
	evals  [][]fr.Element
}

// represents a Witness
type WitnessExtended struct {
	domain    fft.Domain
	p         *iop.Polynomial
	tree      merkletree.Tree
	evals     [][]fr.Element
	numRounds int
	// TODO confirm that it is a field element
	foldingRandomness fr.Element
}

// represents a Commitment
type Commitment struct {
	root []byte
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

	log := logger.Logger().With().Str("position", "start").Logger()
	log.Info().Msg("Commit")

	// commit()
	witness, commitment := prover.commit(p)

	// prover()
	log.Info().Msg("Prove")
	proof := prover.prove(witness)

	// verifier()
	log.Info().Msg("Verify")
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

	// hash
	s.h = sha256.New()

	return &s
}

func (s *instance) commit(p *iop.Polynomial) (Witness, Commitment) {
	// evaluate p
	// evaluate p and sort the result
	coef := p.Coefficients()

	_p := make([]fr.Element, s.domain.Cardinality)
	copy(_p, coef)
	s.domain.FFT(_p, fft.DIF)
	fft.BitReverse(_p)

	// stack evaluations
	foldedEvals := stackEvaluations(_p, int(s.stirFoldingFactor))

	// Merkle tree
	t := merkletree.New(s.h)

	for i := 0; i < len(foldedEvals); i++ {
		for k := 0; k < int(s.stirFoldingFactor); k++ {
			t.Push(foldedEvals[i][k].Marshal())
		}
	}

	rh := t.Root()

	// Build Witness
	w := Witness{
		domain: *s.domain,
		p:      p,
		tree:   *t,
		evals:  foldedEvals,
	}

	c := Commitment{
		root: rh,
	}

	return w, c

}

func (s *instance) prove(witness Witness) Proof {

	// TODO use Fiat Shamir for random fr.element
	xis := make([]string, s.nbSteps+1)
	for i := 0; i < s.nbSteps; i++ {
		xis[i] = paddNaming(fmt.Sprintf("x%d", i), fr.Bytes)
	}
	xis[s.nbSteps] = paddNaming("s0", fr.Bytes)
	fs := fiatshamir.NewTranscript(s.h, xis...)

	var salt fr.Element
	fs.Bind(xis[0], salt.Marshal())

	// derive the challenge
	bxi, _ := fs.ComputeChallenge(xis[0])
	var xi fr.Element
	xi.SetBytes(bxi)

	WitnessExtended := WitnessExtended{
		domain:            witness.domain,
		p:                 witness.p,
		tree:              witness.tree,
		evals:             witness.evals,
		numRounds:         0,
		foldingRandomness: xi,
	}

	for i := 0; i < s.nbSteps; i++ {
		round(WitnessExtended)
	}

	p := Proof{}

	return p
}

func round(witness WitnessExtended) {

	// fold poly

	// shift domian by scale offset

	// evaluate poly

	// stack evaluations

	// Merkle tree

	// get root

	// OOD randomness

	// Sample the indexes of L^k

	// Verifier quires

	// Update the witness

	// Then compute the set we are quotienting by

	// Build the quotient polynomial

}

func verifier(c Commitment, p Proof) {
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

// sort orders the evaluation of a polynomial on a domain
// such that contiguous entries are in the same fiber:
// {q(g⁰), q(g^{n/2}), q(g¹), q(g^{1+n/2}),...,q(g^{n/2-1}), q(gⁿ⁻¹)}
func sort(evaluations []fr.Element) []fr.Element {
	q := make([]fr.Element, len(evaluations))
	n := len(evaluations) / 2
	for i := 0; i < n; i++ {
		q[2*i].Set(&evaluations[i])
		q[2*i+1].Set(&evaluations[i+n])
	}
	return q
}

// paddNaming takes s = 0xA1.... and turns
// it into s' = 0xA1.. || 0..0 of size frSize bytes.
// Using this, when writing the domain separator in FiatShamir, it takes
// the same size as a snark variable (=number of byte in the block of a snark compliant
// hash function like mimc), so it is compliant with snark circuit.
func paddNaming(s string, size int) string {
	a := make([]byte, size)
	b := []byte(s)
	copy(a, b)
	return string(a)
}
