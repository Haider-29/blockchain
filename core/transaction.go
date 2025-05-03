package core

import (
	"bytes"
	"encoding/gob"
	"time"
    // "encoding/binary" // No longer needed here
    "fmt" // Keep for errors

	"blockchain/crypto" // Keep
	"blockchain/utils"  // Ensure this import exists and is correct
)

// Transaction represents a state change operation.
type Transaction struct {
	ID        []byte // Hash of the transaction (excluding ID and Signature)
	From      string // Sender address
	To        string // Recipient address / Contract address / Data key
	Value     uint64 // Amount or data identifier
	Data      []byte // Optional payload for smart contracts or data storage
	Nonce     uint64 // Sender account nonce for replay protection
	Timestamp int64
	Signature []byte // Signature of the transaction hash by the sender
	PublicKey []byte // Sender's public key bytes (for verification)

	// ShardHint is calculated based on From/To address or Data key
	ShardHint uint32
}


// NewTransaction creates a new transaction.
// Nonce must be managed externally (e.g., by the sender's account state).
// numShards is needed to calculate the hint correctly.
func NewTransaction(fromWallet *crypto.Wallet, to string, value uint64, nonce uint64, data []byte, numShards uint32) (*Transaction, error) {
	// Validate inputs
    if fromWallet == nil || fromWallet.PrivateKey == nil {
        return nil, fmt.Errorf("invalid sender wallet provided (nil or no private key)")
    }
    if numShards == 0 {
        return nil, fmt.Errorf("number of shards cannot be zero")
    }

    // Initialize transaction struct
	tx := &Transaction{
		From:      fromWallet.Address,
		To:        to,
		Value:     value,
		Nonce:     nonce,
		Data:      data,
		Timestamp: time.Now().UnixNano(),
		PublicKey: fromWallet.PublicKey.Bytes(),
		// ShardHint will be set below
	}

	// Calculate shard hint using the function moved to utils
	shardHint, err := utils.CalculateShardHint(to, numShards) // Updated Call to utils package
    if err != nil {
        // Decide how to handle error during tx creation.
        // Returning the error is generally safer than defaulting.
        return nil, fmt.Errorf("failed to calculate shard hint for recipient %s: %w", to, err)
    }
    tx.ShardHint = shardHint // Assign calculated hint


	// Calculate transaction ID (hash) *before* signing
	tx.ID = tx.CalculateHash()
    if tx.ID == nil {
        // CalculateHash panics on encoding error, so this might not be reachable
        // unless CalculateHash is changed to return errors.
        return nil, fmt.Errorf("failed to calculate transaction hash")
    }

	// Sign the transaction ID using the sender's private key
	sig, err := fromWallet.PrivateKey.Sign(tx.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction %x: %w", tx.ID, err)
	}
	tx.Signature = sig // Assign the signature

	// Return the fully formed and signed transaction
	return tx, nil
}

// CalculateHash computes the transaction hash (used for ID and signing).
// Ensures ID and Signature are nil during hashing for consistency.
func (tx *Transaction) CalculateHash() []byte {
	// Create a copy to avoid modifying the original tx
    txCopy := *tx
	// Explicitly nil out fields not part of the hash definition
    txCopy.ID = nil
	txCopy.Signature = nil

	// Use gob encoding for serialization before hashing.
	// Consider alternatives like JSON (with ordered keys) or protobuf for better
	// cross-language/version compatibility if needed.
    var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(txCopy)
	if err != nil {
        // Encoding basic Go types with gob should generally not fail.
        // If it does, it might indicate a deeper issue (e.g., memory). Panic might be appropriate here.
		utils.ErrorLogger.Panicf("CRITICAL: Failed to gob encode transaction for hashing: %v", err)
		return nil // Unreachable due to panic
	}
	// Return the SHA256 hash of the serialized data
    return utils.CalculateHash(buf.Bytes())
}


// Verify checks the transaction's signature and hash integrity.
func (tx *Transaction) Verify() bool {
	// Check for essential components
    if tx == nil || tx.PublicKey == nil || tx.Signature == nil || len(tx.ID) == 0 {
		// utils.WarnLogger.Printf("Verify Tx failed: Missing public key, signature, or ID")
		return false
	}

	// Reconstruct the public key from bytes
	pubKey, err := crypto.PublicKeyFromBytes(tx.PublicKey)
	if err != nil {
		utils.WarnLogger.Printf("Verify Tx %x... failed: Cannot reconstruct public key: %v", tx.ID[:4], err)
		return false
	}

	// Recalculate the hash of the transaction content (excluding signature/ID)
	txHash := tx.CalculateHash()
    if txHash == nil {
        // Should not happen if CalculateHash panics on error
        utils.WarnLogger.Printf("Verify Tx %x... failed: Could not recalculate hash", tx.ID[:4])
        return false
    }

	// Verify that the stored ID matches the recalculated hash (integrity check)
	if !bytes.Equal(tx.ID, txHash) {
		utils.WarnLogger.Printf("Verify Tx %x... failed: Stored ID (%x...) mismatch with calculated hash (%x...)", tx.ID[:4], tx.ID[:4], txHash[:4])
		return false
	}

	// Verify the signature against the recalculated hash using the reconstructed public key
	isValid := pubKey.Verify(txHash, tx.Signature)
	if !isValid {
		// utils.WarnLogger.Printf("Verify Tx %x... failed: Invalid signature", tx.ID[:4])
	}
	// Return the signature verification result
    return isValid
}


// TxList is a slice of transactions.
type TxList []*Transaction

// Hashes returns a slice of transaction hashes (IDs) from a TxList.
func (txl TxList) Hashes() [][]byte {
    // Pre-allocate slice for efficiency
	hashes := make([][]byte, 0, len(txl))
	for i, tx := range txl {
        // Ensure transaction and its ID are not nil before accessing
        if tx == nil || tx.ID == nil {
             // This indicates a problem upstream where nil tx was added to the list.
             // Panic might be appropriate to catch this programming error early.
             utils.ErrorLogger.Panicf("Nil transaction or transaction ID encountered at index %d while getting hashes from TxList", i)
             continue // Or handle more gracefully depending on context
        }
		hashes = append(hashes, tx.ID)
	}
	return hashes
}

// Note: CalculateShardHint function definition is REMOVED from this file.