package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	SMT_DEPTH = 256
)

var (
	ErrKeyNotFound = errors.New("key not found in SMT")
	emptyNodeHash = make([]byte, sha256.Size)
)

// smtNode represents a node in the Sparse Merkle Tree.
type smtNode struct {
	Left  *smtNode
	Right *smtNode
	Hash  []byte
	Value []byte
}

// SMT implements a simplified Sparse Merkle Tree with value storage at leaves.
type SMT struct {
	root  *smtNode
	mutex sync.RWMutex
}

// --- SMT Merkle Proof Structure (Renamed) ---

// SMTProof contains the data needed to verify inclusion or non-inclusion in the SMT.
type SMTProof struct { // <<< RENAMED from MerkleProof
	Siblings [][]byte // Sibling hashes [level 0...level DEPTH-1]
	Value    []byte   // Value found at the leaf position for the key's path (nil if non-existent/deleted)
}

// NewSMT creates a new empty SMT.
func NewSMT() *SMT {
	return &SMT{root: nil}
}

// hash combines two hashes.
func hash(left, right []byte) []byte {
	lHash := emptyNodeHash
	if left != nil { lHash = left }
	rHash := emptyNodeHash
	if right != nil { rHash = right }
	if bytes.Equal(lHash, emptyNodeHash) && bytes.Equal(rHash, emptyNodeHash) { return emptyNodeHash }
	combined := append(lHash, rHash...)
	h := sha256.Sum256(combined)
	return h[:]
}

// hashLeaf calculates the hash of a leaf node's value.
func hashLeaf(value []byte) []byte {
	if value == nil { return emptyNodeHash }
	leafPrefix := []byte{0x00}
	dataToHash := append(leafPrefix, value...)
	h := sha256.Sum256(dataToHash)
	return h[:]
}

// Root returns the root hash of the SMT.
func (smt *SMT) Root() []byte {
	smt.mutex.RLock(); defer smt.mutex.RUnlock()
	if smt.root == nil { return emptyNodeHash }
	return smt.root.Hash
}

// --- SMT Copying Logic ---
func copyRecursive(node *smtNode) *smtNode {
	if node == nil { return nil }
	newNode := &smtNode{ Hash: append([]byte(nil), node.Hash...), Value: append([]byte(nil), node.Value...) }
	newNode.Left = copyRecursive(node.Left)
	newNode.Right = copyRecursive(node.Right)
	return newNode
}
func (smt *SMT) Copy() *SMT {
	smt.mutex.RLock(); defer smt.mutex.RUnlock()
	newSMT := NewSMT(); if smt.root != nil { newSMT.root = copyRecursive(smt.root) }
	return newSMT
}

// --- Get/Update/Delete Logic ---
func (smt *SMT) Get(key []byte) ([]byte, error) {
	smt.mutex.RLock(); defer smt.mutex.RUnlock()
	if smt.root == nil { return nil, ErrKeyNotFound }; keyHash := sha256.Sum256(key); pathBits := bytesToBits(keyHash[:])
	value, found := smt.getRecursive(smt.root, pathBits, 0); if !found { return nil, ErrKeyNotFound }
	if value == nil { return nil, nil }; valueCopy := make([]byte, len(value)); copy(valueCopy, value); return valueCopy, nil
}
func (smt *SMT) getRecursive(node *smtNode, pathBits []bool, level int) ([]byte, bool) {
	if node == nil { return nil, false }; if level == SMT_DEPTH { return node.Value, true }
	if !pathBits[level] { return smt.getRecursive(node.Left, pathBits, level+1) }
	return smt.getRecursive(node.Right, pathBits, level+1)
}
func (smt *SMT) Update(key, value []byte) error {
	smt.mutex.Lock(); defer smt.mutex.Unlock(); keyHash := sha256.Sum256(key); pathBits := bytesToBits(keyHash[:]); var err error
	smt.root, err = smt.updateRecursive(smt.root, pathBits, 0, value); if err != nil { return fmt.Errorf("SMT update failed: %w", err) }
	return nil
}
func (smt *SMT) updateRecursive(current *smtNode, pathBits []bool, level int, value []byte) (*smtNode, error) {
	if level == SMT_DEPTH { newLeaf := &smtNode{ Hash: hashLeaf(value), Value: value }; return newLeaf, nil }
	if current == nil { current = &smtNode{} }; var newChild *smtNode; var err error
	if !pathBits[level] { newChild, err = smt.updateRecursive(current.Left, pathBits, level+1, value); if err != nil { return nil, err }; current.Left = newChild } else { newChild, err = smt.updateRecursive(current.Right, pathBits, level+1, value); if err != nil { return nil, err }; current.Right = newChild }
	leftHash := emptyNodeHash; if current.Left != nil { leftHash = current.Left.Hash }; rightHash := emptyNodeHash; if current.Right != nil { rightHash = current.Right.Hash }
	current.Hash = hash(leftHash, rightHash)
	if current.Left == nil && current.Right == nil { if bytes.Equal(current.Hash, emptyNodeHash) { return nil, nil } }
	return current, nil
}
func (smt *SMT) Delete(key []byte) error { return smt.Update(key, nil) }

// --- Proof Generation ---

// generateProofRecursive traverses the tree, collecting sibling hashes.
// Uses the renamed SMTProof struct.
func (smt *SMT) generateProofRecursive(node *smtNode, pathBits []bool, level int, proof *SMTProof) (*smtNode, error) { // <<< Uses *SMTProof
	if node == nil {
		if level < SMT_DEPTH {
			proof.Siblings = append(proof.Siblings, append([]byte(nil), emptyNodeHash...))
			var nextNode *smtNode = nil
			if !pathBits[level] { return smt.generateProofRecursive(nextNode, pathBits, level+1, proof) }
			return smt.generateProofRecursive(nextNode, pathBits, level+1, proof)
		} else {
			proof.Value = nil // Correctly access Value field of SMTProof
			return nil, nil
		}
	}
	if level == SMT_DEPTH {
		proof.Value = node.Value // Correctly access Value field of SMTProof
		return node, nil
	}
	var err error; var siblingHash []byte
	if !pathBits[level] { // Go left
		if node.Right == nil { siblingHash = emptyNodeHash } else { siblingHash = node.Right.Hash }
		proof.Siblings = append(proof.Siblings, append([]byte(nil), siblingHash...))
		_, err = smt.generateProofRecursive(node.Left, pathBits, level+1, proof)
	} else { // Go right
		if node.Left == nil { siblingHash = emptyNodeHash } else { siblingHash = node.Left.Hash }
		proof.Siblings = append(proof.Siblings, append([]byte(nil), siblingHash...))
		_, err = smt.generateProofRecursive(node.Right, pathBits, level+1, proof)
	}
	if err != nil { return nil, err }
	return node, nil
}

// GenerateProof creates a Merkle proof for a given key.
// Returns the renamed SMTProof struct.
func (smt *SMT) GenerateProof(key []byte) (*SMTProof, error) { // <<< Returns *SMTProof
	smt.mutex.RLock(); defer smt.mutex.RUnlock()
	keyHash := sha256.Sum256(key); pathBits := bytesToBits(keyHash[:])

	proof := &SMTProof{ // <<< Use renamed struct
		Siblings: make([][]byte, 0, SMT_DEPTH),
	}

	_, err := smt.generateProofRecursive(smt.root, pathBits, 0, proof)
	if err != nil { return nil, fmt.Errorf("failed to generate proof: %w", err) }
	if len(proof.Siblings) != SMT_DEPTH { return nil, fmt.Errorf("internal error: generated proof has %d siblings, expected %d", len(proof.Siblings), SMT_DEPTH) }

	return proof, nil
}

// --- Proof Verification (Renamed) ---

// VerifySMTProof checks if an SMTProof is valid for a given key and root hash.
// Renamed from VerifyProof to avoid conflict.
func VerifySMTProof(proof *SMTProof, root []byte, key []byte) bool { // <<< RENAMED, takes *SMTProof
	if proof == nil { ErrorLogger.Println("VerifySMTProof failed: provided proof is nil"); return false }
	if len(proof.Siblings) != SMT_DEPTH { ErrorLogger.Printf("VerifySMTProof failed: proof contains %d siblings, expected %d", len(proof.Siblings), SMT_DEPTH); return false }

	keyHash := sha256.Sum256(key); pathBits := bytesToBits(keyHash[:])

	// Start with the hash of the value provided in the SMTProof
	currentHash := hashLeaf(proof.Value) // <<< Correctly access Value field of SMTProof

	for i := 0; i < SMT_DEPTH; i++ {
		level := SMT_DEPTH - 1 - i
		sibling := proof.Siblings[level]
		if !pathBits[level] { currentHash = hash(currentHash, sibling) } else { currentHash = hash(sibling, currentHash) }
	}

	isValid := bytes.Equal(currentHash, root)
	if !isValid { DebugLogger.Printf("VerifySMTProof failed: Computed root %x != Expected root %x", currentHash, root)
	} else { DebugLogger.Printf("VerifySMTProof successful for key %x...", key[:4]) }
	return isValid
}


// --- Utility Functions ---
func bytesToBits(b []byte) []bool {
	bits := make([]bool, len(b)*8); for i, B := range b { for j := 0; j < 8; j++ { if (B>>(7-j))&1 == 1 { bits[i*8+j] = true } } }; return bits
}
func (smt *SMT) Print() {
	fmt.Println("--- SMT Structure ---"); smt.mutex.RLock(); smt.printRecursive(smt.root, 0, ""); smt.mutex.RUnlock(); fmt.Println("---------------------")
}
func (smt *SMT) printRecursive(node *smtNode, level int, path string) {
	if node == nil { return }; indent := strings.Repeat("  ", level); nodeType := "I"; valueStr := ""; if level == SMT_DEPTH { nodeType = "L"; if node.Value != nil { valueStr = fmt.Sprintf(" V: %x...", node.Value[:min(4, len(node.Value))]) } else { valueStr = " V: <nil>" } }; hashStr := "<nil>"; if node.Hash != nil { hashStr = hex.EncodeToString(node.Hash[:4]) + "..." }; fmt.Printf("%s%s [%s] H: %s%s\n", indent, path, nodeType, hashStr, valueStr); smt.printRecursive(node.Left, level+1, path+"0"); smt.printRecursive(node.Right, level+1, path+"1")
}
func min(a, b int) int { if a < b { return a }; return b }