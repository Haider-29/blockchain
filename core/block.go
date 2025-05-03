package core

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time" // Keep time import

	"blockchain/crypto" // Keep crypto import
	"blockchain/utils"
)

// BlockHeader contains metadata for the block.
type BlockHeader struct {
	Height        uint64
	Timestamp     int64
	PrevBlockHash []byte
	MerkleRoot    []byte // Merkle root of transactions in this block
	StateRoot     []byte // Global state root after applying txs in this block
	Validator     string // Address of the validator/proposer

	// --- ADDED VRF Fields ---
	VrfOutput     []byte // Output of the VRF proving leadership eligibility
	VrfProof      []byte // Proof associated with the VRF output
}

// Block represents a block in the blockchain.
type Block struct {
	Header       BlockHeader
	Transactions TxList
	Hash         []byte // Hash of the block header
	Signature    []byte // Signature of the block hash by the validator
}

// NewBlock creates a new block instance.
// VRF fields are set *after* this by the consensus engine before signing.
func NewBlock(height uint64, prevHash, stateRoot []byte, txs TxList, validatorAddr string) *Block {
	header := BlockHeader{
		Height:        height,
		Timestamp:     time.Now().UnixNano(),
		PrevBlockHash: prevHash,
		StateRoot:     stateRoot,
		Validator:     validatorAddr,
		// VrfOutput and VrfProof are nil initially
	}
	merkleTree := utils.NewMerkleTree(txs.Hashes())
    if merkleTree == nil { header.MerkleRoot = utils.CalculateHash([]byte{}) } else { header.MerkleRoot = merkleTree.Hash }

	block := &Block{
		Header:       header,
		Transactions: txs,
		// Hash and Signature are set after header population (including VRF)
	}
	// Initial hash calculation before VRF/Sig might be useful but hash MUST be recalculated after final header state.
	// block.Hash = block.CalculateHash() // Calculate hash here or after VRF is set? Let's calculate AFTER VRF/Sig.
	return block
}

// CalculateHash computes the hash of the block header.
// IMPORTANT: This should be called AFTER all header fields, including VRF fields and potentially signature placeholders, are set.
func (b *Block) CalculateHash() []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	// Ensure consistent encoding order if gob isn't guaranteed (e.g., use custom marshalling)
	err := encoder.Encode(b.Header)
	if err != nil {
		utils.ErrorLogger.Panicf("Failed to encode block header for hashing: %v", err)
		return nil // Unreachable
	}
	return utils.CalculateHash(buf.Bytes())
}

// Sign the block hash using the validator's private key.
// Assumes block.Hash has been calculated based on the *final* header state.
func (b *Block) Sign(validatorWallet *crypto.Wallet) error {
	if validatorWallet == nil || validatorWallet.PrivateKey == nil { return fmt.Errorf("invalid validator wallet provided for signing") }
	if validatorWallet.Address != b.Header.Validator { return fmt.Errorf("block validator mismatch: expected %s, signing as %s", b.Header.Validator, validatorWallet.Address) }
	if b.Hash == nil { // Ensure hash is calculated before signing
		// This suggests an issue in the calling code (consensus propose)
		return fmt.Errorf("cannot sign block with nil hash - call CalculateHash after setting VRF fields")
	}
	sig, err := validatorWallet.PrivateKey.Sign(b.Hash)
	if err != nil { return err }
	b.Signature = sig
	return nil
}

// VerifySignature checks the block's validator signature against the block hash.
func (b *Block) VerifySignature() bool {
	if b.Signature == nil || b.Header.Validator == "" || b.Hash == nil { return false }
	// Re-calculate hash based on received header to ensure integrity
	// This is crucial to prevent verifying a signature against a hash that doesn't match the header content.
	currentHeaderHash := b.CalculateHash()
	if !bytes.Equal(b.Hash, currentHeaderHash) {
		utils.WarnLogger.Printf("Block %d (%x) VerifySignature failed: Provided hash %x does not match calculated header hash %x", b.Header.Height, b.Hash, b.Hash, currentHeaderHash)
		return false
	}

	validatorWallet := crypto.GetWallet(b.Header.Validator)
	if validatorWallet == nil || validatorWallet.PublicKey == nil {
		utils.ErrorLogger.Printf("Block %x verify failed: Validator %s public key not found", b.Hash, b.Header.Validator)
		return false
	}
	// Verify the signature against the confirmed block hash
	return validatorWallet.PublicKey.Verify(b.Hash, b.Signature)
}

// VerifyStructure checks basic structural integrity like the Merkle root.
func (b *Block) VerifyStructure() bool {
    expectedMerkleRootNode := utils.NewMerkleTree(b.Transactions.Hashes()); var expectedMerkleRoot []byte
    if expectedMerkleRootNode == nil { expectedMerkleRoot = utils.CalculateHash([]byte{}) } else { expectedMerkleRoot = expectedMerkleRootNode.Hash }
    if !bytes.Equal(b.Header.MerkleRoot, expectedMerkleRoot) {
		utils.WarnLogger.Printf("Block %d (%x) verify failed: Merkle root mismatch (Header: %x, Calculated: %x)", b.Header.Height, b.Hash, b.Header.MerkleRoot, expectedMerkleRoot)
		return false
	}
	// We don't check VRF presence here; that's consensus validation's job.
	return true
}