package utils

import (
	"bytes" // Keep for bytes.Equal and potentially append([]byte(nil), ...)
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
	Value []byte // Actual value stored only at leaf nodes
}

// SMT implements a simplified Sparse Merkle Tree with value storage at leaves.
type SMT struct {
	root  *smtNode
	mutex sync.RWMutex // Protects direct access/swap of the root pointer
}

// NewSMT creates a new empty SMT.
func NewSMT() *SMT {
	return &SMT{root: nil} // Correctly returns *SMT
}

// hash combines two hashes.
func hash(left, right []byte) []byte {
	lHash := emptyNodeHash
	if left != nil { lHash = left }
	rHash := emptyNodeHash
	if right != nil { rHash = right }
	if bytes.Equal(lHash, emptyNodeHash) && bytes.Equal(rHash, emptyNodeHash) {
		return emptyNodeHash // Return []byte
	}
	combined := append(lHash, rHash...)
	h := sha256.Sum256(combined)
	return h[:] // Return []byte
}

// hashLeaf calculates the hash of a leaf node's value.
func hashLeaf(value []byte) []byte {
	if value == nil {
		return emptyNodeHash // Return []byte
	}
	leafPrefix := []byte{0x00}
	dataToHash := append(leafPrefix, value...)
	h := sha256.Sum256(dataToHash)
	return h[:] // Return []byte
}

// Root returns the root hash of the SMT.
func (smt *SMT) Root() []byte {
	smt.mutex.RLock()
	defer smt.mutex.RUnlock()
	if smt.root == nil {
		return emptyNodeHash // Return []byte
	}
	return smt.root.Hash // Return []byte
}

// --- SMT Copying Logic ---

// copyRecursive performs a deep copy of an SMT node and its descendants.
func copyRecursive(node *smtNode) *smtNode {
	if node == nil {
		return nil // Return *smtNode
	}
	newNode := &smtNode{
		Hash:  append([]byte(nil), node.Hash...),
		Value: append([]byte(nil), node.Value...),
	}
	newNode.Left = copyRecursive(node.Left)
	newNode.Right = copyRecursive(node.Right)
	return newNode // Return *smtNode
}

// Copy creates a deep copy of the entire SMT.
func (smt *SMT) Copy() *SMT {
	smt.mutex.RLock()
	defer smt.mutex.RUnlock()
	newSMT := NewSMT()
	if smt.root != nil {
		newSMT.root = copyRecursive(smt.root)
	}
	return newSMT // Return *SMT
}


// Get retrieves the value associated with a key by traversing the tree.
func (smt *SMT) Get(key []byte) ([]byte, error) {
	smt.mutex.RLock()
	defer smt.mutex.RUnlock()
	if smt.root == nil { return nil, ErrKeyNotFound }
	keyHash := sha256.Sum256(key); pathBits := bytesToBits(keyHash[:])
	value, found := smt.getRecursive(smt.root, pathBits, 0)
	if !found { return nil, ErrKeyNotFound }
	if value == nil { return nil, nil } // Key exists, value is nil
	valueCopy := make([]byte, len(value)); copy(valueCopy, value)
	return valueCopy, nil // Return []byte, error
}

// getRecursive is the helper for Get, traversing the tree.
func (smt *SMT) getRecursive(node *smtNode, pathBits []bool, level int) ([]byte, bool) {
	if node == nil { return nil, false } // Return []byte, bool
	if level == SMT_DEPTH { return node.Value, true } // Leaf position exists, return its value and true
	if !pathBits[level] { return smt.getRecursive(node.Left, pathBits, level+1) }
	return smt.getRecursive(node.Right, pathBits, level+1) // Return results from recursive call
}


// Update inserts, updates, or deletes (value=nil) a key in the SMT.
func (smt *SMT) Update(key, value []byte) error {
	smt.mutex.Lock()
	defer smt.mutex.Unlock()
	keyHash := sha256.Sum256(key); pathBits := bytesToBits(keyHash[:])
	var err error
	smt.root, err = smt.updateRecursive(smt.root, pathBits, 0, value)
	if err != nil { return fmt.Errorf("SMT update failed: %w", err) } // Return error
	return nil // Return error (nil on success)
}

// updateRecursive now handles storing the value at the leaf.
func (smt *SMT) updateRecursive(current *smtNode, pathBits []bool, level int, value []byte) (*smtNode, error) {
	if level == SMT_DEPTH { newLeaf := &smtNode{ Hash: hashLeaf(value), Value: value }; return newLeaf, nil } // Return *smtNode, error
	if current == nil { current = &smtNode{} }
	var newChild *smtNode; var err error
	if !pathBits[level] { newChild, err = smt.updateRecursive(current.Left, pathBits, level+1, value); if err != nil { return nil, err }; current.Left = newChild } else { newChild, err = smt.updateRecursive(current.Right, pathBits, level+1, value); if err != nil { return nil, err }; current.Right = newChild }
	leftHash := emptyNodeHash; if current.Left != nil { leftHash = current.Left.Hash }
	rightHash := emptyNodeHash; if current.Right != nil { rightHash = current.Right.Hash }
	current.Hash = hash(leftHash, rightHash)
	if current.Left == nil && current.Right == nil { if bytes.Equal(current.Hash, emptyNodeHash) { return nil, nil } } // Return *smtNode, error
	return current, nil // Return *smtNode, error
}

// Delete sets the value for the key to nil.
func (smt *SMT) Delete(key []byte) error {
	return smt.Update(key, nil) // Return error
}

// bytesToBits converts a byte slice into a slice of bools (bits).
func bytesToBits(b []byte) []bool {
	bits := make([]bool, len(b)*8)
	for i, B := range b {
		for j := 0; j < 8; j++ {
			if (B>>(7-j))&1 == 1 { bits[i*8+j] = true }
		}
	}
	return bits // Return []bool
}


// --- Print Helper ---

// printRecursive is a helper for debugging tree structure
func (smt *SMT) printRecursive(node *smtNode, level int, path string) {
	if node == nil { return } // No return value
	indent := strings.Repeat("  ", level); nodeType := "I"; valueStr := ""
	if level == SMT_DEPTH { nodeType = "L"; if node.Value != nil { valueStr = fmt.Sprintf(" V: %x...", node.Value[:min(4, len(node.Value))]) } else { valueStr = " V: <nil>" } }
    hashStr := "<nil>"; if node.Hash != nil { hashStr = hex.EncodeToString(node.Hash[:4]) + "..." }
	fmt.Printf("%s%s [%s] H: %s%s\n", indent, path, nodeType, hashStr, valueStr)
	smt.printRecursive(node.Left, level+1, path+"0")
	smt.printRecursive(node.Right, level+1, path+"1")
	// No return value
}

// Print outputs a simplified representation of the SMT structure to console.
func (smt *SMT) Print() {
	fmt.Println("--- SMT Structure ---")
	smt.mutex.RLock(); smt.printRecursive(smt.root, 0, ""); smt.mutex.RUnlock()
	fmt.Println("---------------------")
	// No return value
}

// Helper for printing
func min(a, b int) int { if a < b { return a }; return b } // Return int