package core

import (
	"bytes"
	"encoding/gob"
	"time"
	"blockchain/utils"
)

// BlockHeader contains metadata for the block.
type BlockHeader struct {
	Height        uint64
	Timestamp     int64
	PrevBlockHash []byte
	MerkleRoot    []byte
	StateRoot     []byte
	Proposer      string // Renamed from Validator

	// VRF Fields
	VrfOutput     []byte
	VrfProof      []byte
}

// TxList is a slice of transactions. DEFINED HERE.
type TxList []*Transaction

// Hashes returns a slice of transaction hashes (IDs). METHOD DEFINED HERE.
func (txl TxList) Hashes() [][]byte {
	hashes := make([][]byte, 0, len(txl))
	for i, tx := range txl {
		if tx == nil || tx.ID == nil {
			utils.ErrorLogger.Panicf("Nil transaction or transaction ID encountered at index %d while getting hashes from TxList", i)
			continue
		}
		hashes = append(hashes, tx.ID)
	}
	return hashes
}

// Block represents a block in the blockchain.
type Block struct {
	Header       BlockHeader
	Transactions TxList // Uses TxList defined above
	Hash         []byte
	Signatures   map[string][]byte
}

// NewBlock creates a new block instance.
func NewBlock(height uint64, prevHash, stateRoot []byte, txs TxList, proposerAddr string) *Block {
	header := BlockHeader{ Height: height, Timestamp: time.Now().UnixNano(), PrevBlockHash: prevHash, StateRoot: stateRoot, Proposer: proposerAddr }
	merkleTree := utils.NewMerkleTree(txs.Hashes()) // Uses TxList.Hashes()
    if merkleTree == nil { header.MerkleRoot = utils.CalculateHash([]byte{}) } else { header.MerkleRoot = merkleTree.Hash }
	block := &Block{ Header: header, Transactions: txs, Signatures: make(map[string][]byte) }
	// Hash calculated later by consensus engine after VRF fields set
	return block
}

// CalculateHash computes the hash of the block header.
func (b *Block) CalculateHash() []byte {
	var buf bytes.Buffer; encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(b.Header); if err != nil { utils.ErrorLogger.Panicf("Failed to encode block header for hashing: %v", err); return nil }
	return utils.CalculateHash(buf.Bytes())
}

// VerifyStructure checks Merkle root.
func (b *Block) VerifyStructure() bool {
    expectedMerkleRootNode := utils.NewMerkleTree(b.Transactions.Hashes()); var expectedMerkleRoot []byte // Uses TxList.Hashes()
    if expectedMerkleRootNode == nil { expectedMerkleRoot = utils.CalculateHash([]byte{}) } else { expectedMerkleRoot = expectedMerkleRootNode.Hash }
    if !bytes.Equal(b.Header.MerkleRoot, expectedMerkleRoot) {
		utils.WarnLogger.Printf("Block %d (%x) verify failed: Merkle root mismatch (Header: %x, Calculated: %x)", b.Header.Height, b.Hash, b.Header.MerkleRoot, expectedMerkleRoot)
		return false
	}
	return true
}