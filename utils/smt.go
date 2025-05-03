package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex" // <-- ADDED for printing
	"errors"
	"fmt"     // <-- ADDED for printing and errors
	"strings" // <-- ADDED for printing
	"sync"
)

const (
	// SMT_DEPTH defines the depth of the tree. SHA256 keys mean 256 levels.
	SMT_DEPTH = 256
)

var (
	// ErrKeyNotFound indicates a key doesn't exist in the SMT for Get operation.
	ErrKeyNotFound = errors.New("key not found in SMT")
	// Placeholder hash for empty nodes/subtrees (all zeros)
	emptyNodeHash = make([]byte, sha256.Size)
)

// smtNode represents a node in the Sparse Merkle Tree.
type smtNode struct {
	Left  *smtNode
	Right *smtNode
	Hash  []byte // Hash(Left.Hash || Right.Hash) or Hash(value) for leaves
	// TODO: Add 'value []byte' field here if storing values directly in leaves
}

// SMT implements a simplified Sparse Merkle Tree.
type SMT struct {
	root  *smtNode
	mutex sync.RWMutex
}

// NewSMT creates a new empty SMT.
func NewSMT() *SMT {
	return &SMT{
		root: nil, // Represents empty tree (hash is emptyNodeHash)
	}
}

// hash combines two hashes. Handles nil inputs (representing empty subtrees).
func hash(left, right []byte) []byte {
	lHash := emptyNodeHash
	if left != nil { lHash = left }
	rHash := emptyNodeHash
	if right != nil { rHash = right }
	// Optimization: if both inputs are empty, result is empty hash
	if bytes.Equal(lHash, emptyNodeHash) && bytes.Equal(rHash, emptyNodeHash) {
		return emptyNodeHash
	}
	combined := append(lHash, rHash...)
	h := sha256.Sum256(combined)
	return h[:]
}

// hashLeaf calculates the hash of a leaf node containing a value.
// Returns emptyNodeHash if value is nil (representing deletion/non-existence).
func hashLeaf(value []byte) []byte {
	if value == nil {
		return emptyNodeHash
	}
	// Simple H(value). Could add domain separation later if needed H(domain || value).
	h := sha256.Sum256(value)
	return h[:]
}

// Root returns the root hash of the SMT.
func (smt *SMT) Root() []byte {
	smt.mutex.RLock()
	defer smt.mutex.RUnlock()
	if smt.root == nil {
		return emptyNodeHash
	}
	// Return a copy to prevent external modification? Hashes are usually safe.
	return smt.root.Hash
}

// Get retrieves the value associated with a key.
// --- CURRENTLY A PLACEHOLDER - DOES NOT RETURN VALUE ---
// It only checks if a non-empty leaf exists at the key's path.
func (smt *SMT) Get(key []byte) ([]byte, error) {
	smt.mutex.RLock()
	defer smt.mutex.RUnlock()

	if smt.root == nil { return nil, ErrKeyNotFound }

	keyHash := sha256.Sum256(key)
	pathBits := bytesToBits(keyHash[:])

	currentNode := smt.root
	for i := 0; i < SMT_DEPTH; i++ {
		if currentNode == nil { return nil, ErrKeyNotFound }

		// --- Corrected bool comparison ---
		if !pathBits[i] { // Go left if bit is 0 (false)
			currentNode = currentNode.Left
		} else { // Go right if bit is 1 (true)
			currentNode = currentNode.Right
		}
	}

	// At expected leaf position
	if currentNode == nil || bytes.Equal(currentNode.Hash, emptyNodeHash) {
		return nil, ErrKeyNotFound
	}

	// Cannot return actual value yet. Signal presence.
	return nil, nil // Key exists (placeholder success)
}

// Update inserts, updates, or deletes (value=nil) a key in the SMT.
func (smt *SMT) Update(key, value []byte) error {
	smt.mutex.Lock()
	defer smt.mutex.Unlock()

	keyHash := sha256.Sum256(key)
	pathBits := bytesToBits(keyHash[:])
	leafHash := hashLeaf(value) // Hash of value, or emptyNodeHash for nil

	var err error
	smt.root, err = smt.updateRecursive(smt.root, pathBits, 0, leafHash)
	if err != nil {
		return fmt.Errorf("SMT update failed: %w", err) // <-- Use fmt
	}
	return nil
}

// updateRecursive is the core update logic.
func (smt *SMT) updateRecursive(current *smtNode, pathBits []bool, level int, leafHash []byte) (*smtNode, error) {
	// Base case: Reached the leaf level
	if level == SMT_DEPTH {
		// Return a new leaf node. If leafHash is emptyNodeHash, it's a deletion.
		// If the hash is identical to existing hash, can optimize by returning current.
		// For simplicity, always create/return new leaf representation.
		return &smtNode{Hash: leafHash}, nil
	}

	// If current path requires a node but none exists, create one.
	if current == nil {
		current = &smtNode{} // Represents an empty subtree implicitly
	}

	var newChild *smtNode
	var err error

	// --- Corrected bool comparison ---
	if !pathBits[level] { // Go left if bit is 0 (false)
		newChild, err = smt.updateRecursive(current.Left, pathBits, level+1, leafHash)
		if err != nil { return nil, err }
		// Optimization: if returned child is identical to current, no need to update hash
		// if current.Left == newChild { return current, nil } // Needs pointer comparison or deep compare
		current.Left = newChild
	} else { // Go right if bit is 1 (true)
		newChild, err = smt.updateRecursive(current.Right, pathBits, level+1, leafHash)
		if err != nil { return nil, err }
		// if current.Right == newChild { return current, nil }
		current.Right = newChild
	}

	// --- Recalculate Hash & Pruning ---
	leftHash := emptyNodeHash
	if current.Left != nil { leftHash = current.Left.Hash }
	rightHash := emptyNodeHash
	if current.Right != nil { rightHash = current.Right.Hash }

	newHash := hash(leftHash, rightHash)
	// Optimization: if hash hasn't changed, can return current node (requires storing old hash)
	// if bytes.Equal(newHash, current.Hash) { return current, nil }

	current.Hash = newHash

	// Pruning: If the node's hash is the empty hash AND both children are nil,
	// this node represents an empty subtree and can be represented by nil itself.
	if bytes.Equal(current.Hash, emptyNodeHash) && current.Left == nil && current.Right == nil {
		return nil, nil // Prune this node
	}

	return current, nil
}


// Delete sets the value for the key to nil.
func (smt *SMT) Delete(key []byte) error {
	return smt.Update(key, nil)
}

// --- Utility Functions ---

// bytesToBits converts a byte slice into a slice of bools (bits).
func bytesToBits(b []byte) []bool {
	bits := make([]bool, len(b)*8)
	for i, B := range b {
		for j := 0; j < 8; j++ {
			if (B>>(7-j))&1 == 1 { bits[i*8+j] = true } // No else needed, defaults to false
		}
	}
	return bits
}

// --- TODO: Proof Generation and Verification ---

// --- TODO: Value Retrieval for Get ---

// Helper for debugging tree structure
func (smt *SMT) printRecursive(node *smtNode, level int, path string) {
	if node == nil {
		// Optional: Print placeholder for nil nodes if needed for visualization
		// indent := strings.Repeat("  ", level)
		// fmt.Printf("%s%s <nil>\n", indent, path)
		return
	}
	indent := strings.Repeat("  ", level) // <-- Use strings
	nodeType := "I"
	if level == SMT_DEPTH { nodeType = "L" }

    // Check if hash is nil before trying to slice/encode
    hashStr := "<nil>"
    if node.Hash != nil {
        hashStr = hex.EncodeToString(node.Hash[:4]) + "..." // <-- Use hex
    }

	fmt.Printf("%s%s [%s] H: %s\n", indent, path, nodeType, hashStr) // <-- Use fmt

	smt.printRecursive(node.Left, level+1, path+"0")
	smt.printRecursive(node.Right, level+1, path+"1")
}

// Print outputs a simplified representation of the SMT structure to console.
func (smt *SMT) Print() {
	fmt.Println("--- SMT Structure ---") // <-- Use fmt
	smt.mutex.RLock() // Read lock for printing
	smt.printRecursive(smt.root, 0, "")
	smt.mutex.RUnlock()
	fmt.Println("---------------------") // <-- Use fmt
}