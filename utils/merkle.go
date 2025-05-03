package utils

import (
	"bytes"
)

// MerkleNode represents a node in the Merkle tree.
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Hash  []byte
}

// NewMerkleNode creates a new Merkle tree node.
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := MerkleNode{}

	if left == nil && right == nil {
		// Leaf node
		node.Hash = CalculateHash(data)
	} else {
		// Internal node
		prevHashes := append(left.Hash, right.Hash...)
		node.Hash = CalculateHash(prevHashes)
	}

	node.Left = left
	node.Right = right

	return &node
}

// NewMerkleTree creates a Merkle tree from a slice of data (hashes).
func NewMerkleTree(data [][]byte) *MerkleNode {
	if len(data) == 0 {
		InfoLogger.Println("Creating Merkle tree with transaction data")
		// Return a node representing the hash of empty data for consistency
		return NewMerkleNode(nil, nil, []byte{})
	}

	var nodes []*MerkleNode

	// Create leaf nodes
	for _, datum := range data {
		nodes = append(nodes, NewMerkleNode(nil, nil, datum))
	}

	// Build the tree level by level
	for len(nodes) > 1 {
		// Duplicate the last node if the number of nodes is odd
		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}

		var level []*MerkleNode
		// Combine pairs of nodes
		for i := 0; i < len(nodes); i += 2 {
			// Ensure nodes[i] and nodes[i+1] are not nil before accessing Hash
			if nodes[i] == nil || nodes[i+1] == nil {
				ErrorLogger.Panicf("Nil node encountered during Merkle tree construction at level (index %d)", i) // Should not happen with padding
			}
			node := NewMerkleNode(nodes[i], nodes[i+1], nil) // Data is nil for internal nodes
			level = append(level, node)
		}
		nodes = level // Move to the next level up
	}

	return nodes[0] // The root node
}


// MerkleProof contains the sibling hashes and their position relative to the path.
type MerkleProof struct {
    Siblings [][]byte // Hashes of sibling nodes along the path to the root
    IsLeft   []bool   // For each sibling, is the node *on the path* the left child?
}


// VerifyProof verifies a Merkle proof.
func VerifyProof(leafHash, rootHash []byte, proof MerkleProof) bool {
    if len(proof.Siblings) != len(proof.IsLeft) {
        ErrorLogger.Println("Proof siblings count does not match position info count")
        return false
    }

	// Handle empty tree or single element tree consistently with NewMerkleTree
    if rootHash == nil {
         // If expected root is nil, proof should be empty and leaf should be nil/empty hash
         return len(proof.Siblings) == 0 && bytes.Equal(leafHash, CalculateHash([]byte{}))
    }
	// Handle single element tree
	if len(proof.Siblings) == 0 {
		return bytes.Equal(leafHash, rootHash)
	}


    currentHash := leafHash
    for i := 0; i < len(proof.Siblings); i++ {
        siblingHash := proof.Siblings[i]
        var combined []byte
        // If the node *on the path* is the LEFT node, the SIBLING is the RIGHT node.
        if proof.IsLeft[i] {
            combined = append(currentHash, siblingHash...)
        } else {
        // If the node *on the path* is the RIGHT node, the SIBLING is the LEFT node.
            combined = append(siblingHash, currentHash...)
        }
        currentHash = CalculateHash(combined)
        DebugLogger.Printf("Proof Step %d: Combined hash %x", i, currentHash)
    }
     DebugLogger.Printf("Final calculated hash: %x, Expected root: %x", currentHash, rootHash)
    return bytes.Equal(currentHash, rootHash)
}

// FindMerklePath generates a Merkle proof for a given leaf hash.
// Returns the proof and a boolean indicating if the leaf was found.
func FindMerklePath(root *MerkleNode, leafHash []byte) (MerkleProof, bool) {
    var proof MerkleProof
    var pathNodes []*MerkleNode // Keep track of nodes on the path for position check

    var find func(*MerkleNode) bool
    find = func(node *MerkleNode) bool {
        if node == nil {
            return false
        }

        // Check if current node is the leaf we are looking for
        if node.Left == nil && node.Right == nil {
            isLeaf := bytes.Equal(node.Hash, leafHash)
            if isLeaf {
                pathNodes = append(pathNodes, node) // Add leaf to path start
            }
            return isLeaf
        }

        // Recursively search left child
        if find(node.Left) {
            pathNodes = append(pathNodes, node) // Add parent to path
            if node.Right != nil {
                proof.Siblings = append(proof.Siblings, node.Right.Hash)
                proof.IsLeft = append(proof.IsLeft, true) // Node on path (left) is left child
            } else {
                 // This case implies padding occurred. The sibling hash is the same as the node hash.
                 // However, our padding duplicates the node itself at the previous level,
                 // so the sibling reference (node.Right) should exist if padding happened correctly in NewMerkleTree.
                 // If node.Right is nil here, it might indicate an issue in tree construction for odd numbers.
                 WarnLogger.Println("Potentially missing right sibling during path generation - check tree construction for odd leaves")
                 // Assuming padding was done by duplicating the last element's hash:
                 // proof.Siblings = append(proof.Siblings, node.Left.Hash)
                 // proof.IsLeft = append(proof.IsLeft, true)
            }
            return true
        }

        // Recursively search right child
        if find(node.Right) {
            pathNodes = append(pathNodes, node) // Add parent to path
             if node.Left != nil {
                proof.Siblings = append(proof.Siblings, node.Left.Hash)
                proof.IsLeft = append(proof.IsLeft, false) // Node on path (right) is right child
            } else {
                 WarnLogger.Println("Potentially missing left sibling during path generation - check tree construction")
                 // proof.Siblings = append(proof.Siblings, node.Right.Hash)
                 // proof.IsLeft = append(proof.IsLeft, false)
            }
            return true
        }

        return false // Not found in this subtree
    }

    found := find(root)
    if !found {
         // Clear proof if not found
         proof.Siblings = nil
         proof.IsLeft = nil
    }
	// The proof is built bottom-up, so reverse it for top-down verification path
	for i, j := 0, len(proof.Siblings)-1; i < j; i, j = i+1, j-1 {
		proof.Siblings[i], proof.Siblings[j] = proof.Siblings[j], proof.Siblings[i]
		proof.IsLeft[i], proof.IsLeft[j] = proof.IsLeft[j], proof.IsLeft[i]
	}

    return proof, found
}