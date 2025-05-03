package core

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"
	// "crypto/elliptic" // Not needed here

	"blockchain/crypto"
	"blockchain/utils"
)

// Transaction represents a state change operation.
type Transaction struct {
	ID        []byte
	From      string
	To        string
	Value     uint64
	Data      []byte
	Nonce     uint64
	Timestamp int64
	Signature []byte
	PublicKey []byte
	ShardHint uint32
}

// NewTransaction creates a new transaction.
func NewTransaction(fromWallet *crypto.Wallet, to string, value uint64, nonce uint64, data []byte, numShards uint32) (*Transaction, error) {
	if fromWallet == nil || fromWallet.PrivateKey == nil { return nil, fmt.Errorf("invalid sender wallet provided") }
	if numShards == 0 { return nil, fmt.Errorf("number of shards cannot be zero") }
	tx := &Transaction{ From: fromWallet.Address, To: to, Value: value, Nonce: nonce, Data: data, Timestamp: time.Now().UnixNano(), PublicKey: fromWallet.PublicKey.Bytes() }
	shardHint, err := utils.CalculateShardHint(to, numShards); if err != nil { return nil, fmt.Errorf("failed to calculate shard hint: %w", err) }
	tx.ShardHint = shardHint
	tx.ID = tx.CalculateHash(); if tx.ID == nil { return nil, fmt.Errorf("failed to calculate transaction hash") }
	sig, err := fromWallet.PrivateKey.Sign(tx.ID); if err != nil { return nil, fmt.Errorf("failed to sign transaction %x: %w", tx.ID, err) }
	tx.Signature = sig
	return tx, nil
}

// CalculateHash computes the transaction hash.
func (tx *Transaction) CalculateHash() []byte {
	txCopy := *tx; txCopy.ID = nil; txCopy.Signature = nil
	var buf bytes.Buffer; encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(txCopy); if err != nil { utils.ErrorLogger.Panicf("Failed to encode transaction for hashing: %v", err); return nil }
	return utils.CalculateHash(buf.Bytes())
}

// Verify the transaction signature and integrity.
func (tx *Transaction) Verify() bool {
	if tx == nil || tx.PublicKey == nil || tx.Signature == nil || len(tx.ID) == 0 { return false }
	pubKey, err := crypto.PublicKeyFromBytes(tx.PublicKey); if err != nil { utils.WarnLogger.Printf("Verify Tx %x... failed: Cannot reconstruct public key: %v", tx.ID[:4], err); return false }
	txHash := tx.CalculateHash(); if txHash == nil { utils.WarnLogger.Printf("Verify Tx %x failed: Could not recalculate hash", tx.ID); return false }
	if !bytes.Equal(tx.ID, txHash) { utils.WarnLogger.Printf("Verify Tx %x... failed: Stored ID (%x...) mismatch with calculated hash (%x...)", tx.ID[:4], tx.ID[:4], txHash[:4]); return false }
	isValid := pubKey.Verify(txHash, tx.Signature)
	if !isValid { /* utils.WarnLogger.Printf("Verify Tx %x... failed: Invalid signature", tx.ID[:4]) */ }
	return isValid
}

// --- TxList Type and Hashes Method REMOVED FROM HERE ---
// // TxList is a slice of transactions.
// type TxList []*Transaction
// // Hashes returns a slice of transaction hashes (IDs).
// func (txl TxList) Hashes() [][]byte { /* ... implementation removed ... */ }