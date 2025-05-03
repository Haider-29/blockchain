package core

import (
	"bytes"
	"encoding/gob"
	"time"
    "fmt"

	"blockchain/crypto" // Updated import path
	"blockchain/utils"  // Updated import path
)

// BlockHeader contains metadata for the block.
type BlockHeader struct {
	Height        uint64
	Timestamp     int64
	PrevBlockHash []byte
	MerkleRoot    []byte // Merkle root of transactions in this block
	StateRoot     []byte // Global state root (e.g., hash of shard roots)
	Validator     string // Address of the validator/proposer
}

// Block represents a block in the blockchain.
type Block struct {
	Header       BlockHeader
	Transactions TxList
	Hash         []byte // Hash of the block header
	Signature    []byte // Signature of the block hash by the validator
}

// NewBlock creates a new block. State root comes from the state manager *after* applying txs.
// Validator signature is added after creation and consensus.
func NewBlock(height uint64, prevHash, stateRoot []byte, txs TxList, validatorAddr string) *Block {
	header := BlockHeader{
		Height:        height,
		Timestamp:     time.Now().UnixNano(),
		PrevBlockHash: prevHash,
		StateRoot:     stateRoot, // This MUST be the state root AFTER applying txs in this block
		Validator:     validatorAddr,
	}

	// Calculate Merkle root for transactions
    merkleTree := utils.NewMerkleTree(txs.Hashes())
    if merkleTree == nil {
         // This should only happen if txs.Hashes() returns an empty list AND NewMerkleTree handles it by returning nil.
         // We modified NewMerkleTree to return a default hash node, so this branch might be unreachable.
         utils.ErrorLogger.Printf("Merkle tree construction failed for block %d, using empty hash.", height)
         header.MerkleRoot = utils.CalculateHash([]byte{}) // Default empty hash
    } else {
         header.MerkleRoot = merkleTree.Hash
    }

	block := &Block{
		Header:       header,
		Transactions: txs,
	}
	block.Hash = block.CalculateHash() // Calculate hash after header is populated

	return block
}

// CalculateHash computes the hash of the block header.
func (b *Block) CalculateHash() []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	// Ensure consistent encoding
	err := encoder.Encode(b.Header)
	if err != nil {
		utils.ErrorLogger.Panicf("Failed to encode block header for hashing: %v", err)
		return nil
	}
	return utils.CalculateHash(buf.Bytes())
}

// Sign the block hash using the validator's private key.
func (b *Block) Sign(validatorWallet *crypto.Wallet) error {
    if validatorWallet == nil || validatorWallet.PrivateKey == nil {
        return fmt.Errorf("invalid validator wallet provided for signing")
    }
    if validatorWallet.Address != b.Header.Validator {
        return fmt.Errorf("block validator mismatch: expected %s, signing as %s", b.Header.Validator, validatorWallet.Address)
    }
    if b.Hash == nil {
        return fmt.Errorf("cannot sign block with nil hash")
    }
	sig, err := validatorWallet.PrivateKey.Sign(b.Hash)
	if err != nil {
		return err
	}
	b.Signature = sig
	return nil
}


// VerifySignature checks the block's validator signature.
func (b *Block) VerifySignature() bool {
	if b.Signature == nil || b.Header.Validator == "" || b.Hash == nil {
		// utils.WarnLogger.Printf("Block %x verify failed: Missing signature, validator address, or hash", b.Hash)
		return false
	}

	// Find the validator's public key (assuming wallet store access or public key registry)
	// In a real P2P network, the public key might be part of the validator's identity data.
	validatorWallet := crypto.GetWallet(b.Header.Validator) // Simplified access
	if validatorWallet == nil || validatorWallet.PublicKey == nil {
		utils.ErrorLogger.Printf("Block %x verify failed: Validator %s public key not found", b.Hash, b.Header.Validator)
		// TODO: Need a way to get validator public keys, maybe store them in state or a registry?
		return false // Cannot verify without public key
	}

	return validatorWallet.PublicKey.Verify(b.Hash, b.Signature)
}

// VerifyStructure checks basic structural integrity (e.g., Merkle root calculation).
func (b *Block) VerifyStructure() bool {
    // Recalculate Merkle root from transactions and compare
    expectedMerkleRootNode := utils.NewMerkleTree(b.Transactions.Hashes())
    var expectedMerkleRoot []byte
    if expectedMerkleRootNode == nil {
        // Consistent with NewMerkleTree behavior for empty data
        expectedMerkleRoot = utils.CalculateHash([]byte{})
    } else {
        expectedMerkleRoot = expectedMerkleRootNode.Hash
    }


    if !bytes.Equal(b.Header.MerkleRoot, expectedMerkleRoot) {
        utils.WarnLogger.Printf("Block %d (%x) verify failed: Merkle root mismatch (Header: %x, Calculated: %x)",
            b.Header.Height, b.Hash, b.Header.MerkleRoot, expectedMerkleRoot)
        return false
    }
    // Add more checks if needed (e.g., timestamp sanity relative to previous block - done in consensus)
    return true
}