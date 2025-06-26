package dlnproofc

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	cmts "github.com/bnb-chain/tss-lib/v2/crypto/commitments"
)

const Iterations = 128 // Match the C wrapper's ITERATIONS

type Proof struct {
	Alpha [Iterations]*big.Int
	T     [Iterations]*big.Int
}

// var one = big.NewInt(1)

// NewDLNProof generates a new DLN proof using the C implementation
func NewDLNProofWithoutPadding(h1, h2, x, p, q, N *big.Int, rand io.Reader) *Proof {
	// Convert big.Int to byte slices for C wrapper
	h1Bytes := h1.Bytes()
	xBytes := x.Bytes()
	pBytes := p.Bytes()
	qBytes := q.Bytes()
	NBytes := N.Bytes()

	// Generate a hash for the proof (using h1 and h2)
	hasher := sha256.New()
	hasher.Write(h1Bytes)
	hasher.Write(h2.Bytes())
	hash := hasher.Sum(nil)

	// Determine output length (use the largest input size)
	outLen := len(NBytes)
	if len(h1Bytes) > outLen {
		outLen = len(h1Bytes)
	}
	if len(xBytes) > outLen {
		outLen = len(xBytes)
	}

	// Call the C wrapper to generate proof
	alphaList, tList, err := DLNProve(h1Bytes, xBytes, pBytes, qBytes, NBytes, hash, outLen)
	if err != nil {
		// Return nil on error - in production you might want to handle this differently
		return nil
	}

	// Convert byte slices back to big.Int
	proof := &Proof{}
	for i := 0; i < Iterations; i++ {
		proof.Alpha[i] = new(big.Int).SetBytes(alphaList[i])
		proof.T[i] = new(big.Int).SetBytes(tList[i])
	}

	return proof
}

// Verify checks if the DLN proof is valid using the C implementation
func (p *Proof) Verify(h1, h2, N *big.Int) bool {
	if p == nil {
		return false
	}

	// Convert big.Int to byte slices
	h1Bytes := h1.Bytes()
	h2Bytes := h2.Bytes()
	NBytes := N.Bytes()

	// Generate the same hash used during proof generation
	hasher := sha256.New()
	hasher.Write(h1Bytes)
	hasher.Write(h2Bytes)
	hash := hasher.Sum(nil)

	// Convert proof arrays to byte slice arrays
	alphaList := make([][]byte, Iterations)
	tList := make([][]byte, Iterations)

	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
			return false
		}
		alphaList[i] = padBytes(p.Alpha[i].Bytes(), len(NBytes))
		tList[i] = padBytes(p.T[i].Bytes(), len(NBytes))
	}
	// for tL := range tList {
	// 	fmt.Printf("t lengthz %d\n", len(tList[tL]))
	// }
	// Call the C wrapper to verify proof
	valid, err := DLNVerify(h1Bytes, h2Bytes, NBytes, alphaList, tList, hash)
	if err != nil {
		fmt.Println("DLNVerify error:", err)
		return false
	}

	return valid
}

// Helper function to pad byte slices to ensure consistent length
func padBytes(b []byte, length int) []byte {
	if len(b) >= length {
		return b
	}
	padded := make([]byte, length)
	copy(padded[length-len(b):], b)
	return padded
}

func NewDLNProof(h1, h2, x, p, q, N *big.Int, rand io.Reader) *Proof {
	return NewDLNProofWithPadding(h1, h2, x, p, q, N, rand)
}

// NewDLNProofWithPadding generates a proof with consistent byte lengths
func NewDLNProofWithPadding(h1, h2, x, p, q, N *big.Int, rand io.Reader) *Proof {
	// Calculate the maximum byte length needed
	maxLen := 0
	inputs := []*big.Int{h1, h2, x, p, q, N}
	for _, input := range inputs {
		if l := len(input.Bytes()); l > maxLen {
			maxLen = l
		}
	}

	// Pad all inputs to the same length
	h1Bytes := padBytes(h1.Bytes(), maxLen)
	xBytes := padBytes(x.Bytes(), maxLen)
	pBytes := padBytes(p.Bytes(), maxLen)
	qBytes := padBytes(q.Bytes(), maxLen)
	NBytes := padBytes(N.Bytes(), maxLen)

	// Generate hash
	hasher := sha256.New()
	hasher.Write(h1Bytes)
	hasher.Write(h2.Bytes())
	hash := hasher.Sum(nil)

	// Call C wrapper
	alphaList, tList, err := DLNProve(h1Bytes, xBytes, pBytes, qBytes, NBytes, hash, maxLen)
	if err != nil {
		return nil
	}

	// Convert to big.Int
	proof := &Proof{}
	for i := 0; i < Iterations; i++ {
		proof.Alpha[i] = new(big.Int).SetBytes(alphaList[i])
		proof.T[i] = new(big.Int).SetBytes(tList[i])
	}

	return proof
}

// VerifyWithPadding verifies a proof with consistent byte lengths
func (p *Proof) VerifyWithPadding(h1, h2, N *big.Int) bool {
	if p == nil {
		return false
	}

	// Calculate maximum length
	maxLen := 0
	inputs := []*big.Int{h1, h2, N}
	for _, input := range inputs {
		if l := len(input.Bytes()); l > maxLen {
			maxLen = l
		}
	}

	// Also check proof elements for maximum length
	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] != nil {
			if l := len(p.Alpha[i].Bytes()); l > maxLen {
				maxLen = l
			}
		}
		if p.T[i] != nil {
			if l := len(p.T[i].Bytes()); l > maxLen {
				maxLen = l
			}
		}
	}

	// Pad inputs
	h1Bytes := padBytes(h1.Bytes(), maxLen)
	h2Bytes := padBytes(h2.Bytes(), maxLen)
	NBytes := padBytes(N.Bytes(), maxLen)

	// Generate hash
	hasher := sha256.New()
	hasher.Write(h1Bytes)
	hasher.Write(h2Bytes)
	hash := hasher.Sum(nil)

	// Convert proof to padded byte arrays
	alphaList := make([][]byte, Iterations)
	tList := make([][]byte, Iterations)

	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
			return false
		}
		alphaList[i] = padBytes(p.Alpha[i].Bytes(), maxLen)
		tList[i] = padBytes(p.T[i].Bytes(), maxLen)
	}

	// Call C wrapper
	valid, err := DLNVerify(h1Bytes, h2Bytes, NBytes, alphaList, tList, hash)
	if err != nil {
		return false
	}

	return valid
}

func (p *Proof) Serialize() ([][]byte, error) {
	cb := cmts.NewBuilder()
	cb = cb.AddPart(p.Alpha[:])
	cb = cb.AddPart(p.T[:])
	ints, err := cb.Secrets()
	if err != nil {
		return nil, err
	}
	// Find the max length for padding
	maxLen := 0
	for _, part := range ints {
		if part != nil && len(part.Bytes()) > maxLen {
			maxLen = len(part.Bytes())
		}
	}
	bzs := make([][]byte, len(ints))
	for i, part := range ints {
		if part == nil {
			bzs[i] = []byte{}
			continue
		}
		bzs[i] = padBytes(part.Bytes(), maxLen)
	}
	return bzs, nil
}

func UnmarshalDLNProof(bzs [][]byte) (*Proof, error) {
	if len(bzs) == 0 {
		return nil, fmt.Errorf("UnmarshalDLNProof: input slice is empty")
	}
	// Check all slices are the same length
	expectedLen := len(bzs[0])
	for i, bz := range bzs {
		if len(bz) != expectedLen {
			return nil, fmt.Errorf("UnmarshalDLNProof: element %d has length %d, expected %d", i, len(bz), expectedLen)
		}
	}

	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}
	parsed, err := cmts.ParseSecrets(bis)
	if err != nil {
		return nil, err
	}
	if len(parsed) != 2 {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d parts but got %d", 2, len(parsed))
	}
	pf := new(Proof)
	if len1 := copy(pf.Alpha[:], parsed[0]); len1 != Iterations {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d but copied %d", Iterations, len1)
	}
	if len2 := copy(pf.T[:], parsed[1]); len2 != Iterations {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d but copied %d", Iterations, len2)
	}
	return pf, nil
}
