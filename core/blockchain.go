package core

import (
	"bytes"
	"encoding/gob" // Needed for nonce decoding in validation
	"encoding/hex" // Needed for TxPool methods
	"fmt"
	"sync"

	// State import removed
	"blockchain/utils"
	// crypto import removed
)

// Blockchain manages the chain of blocks and state.
type Blockchain struct {
	Blocks       []*Block
	state        StateManager // Use the interface type defined in core/interfaces.go
	Genesis      *Block
	txPool       *TransactionPool // Use the TransactionPool defined below
	lock         sync.RWMutex     // Keep internal lock field (lowercase)
	nodeID       string           // Keep internal nodeID field (lowercase)
}

// NewBlockchain creates a new blockchain instance with a genesis block.
func NewBlockchain(stateMgr StateManager, genesis *Block, nodeID string) (*Blockchain, error) {
	if stateMgr == nil { return nil, fmt.Errorf("state manager (interface) cannot be nil") }
	if genesis == nil { return nil, fmt.Errorf("genesis block cannot be nil") }
	initialStateRoot := stateMgr.CalculateGlobalStateRoot()
	if !bytes.Equal(genesis.Header.StateRoot, initialStateRoot) {
		utils.ErrorLogger.Printf("[%s] Genesis block state root (%x) does not match initial state manager root (%x)", nodeID, genesis.Header.StateRoot, initialStateRoot)
		return nil, fmt.Errorf("genesis state root mismatch (Header: %x, Calculated: %x). Ensure initial state is correct.", genesis.Header.StateRoot, initialStateRoot)
	}
	bc := &Blockchain{
		Blocks:  make([]*Block, 0, 100),
		state:   stateMgr,
		Genesis: genesis,
		txPool:  NewTransactionPool(),
		nodeID:  nodeID, // Assign to lowercase internal field
		// lock is implicitly initialized
	}
	bc.Blocks = append(bc.Blocks, genesis)
	utils.InfoLogger.Printf("[%s] Blockchain initialized. Genesis: %x, Height: %d", bc.nodeID, genesis.Hash, genesis.Header.Height) // Use lowercase field
	return bc, nil // Return *Blockchain, error
}

// validateTxPoolAdmission performs read-only checks before adding to mempool.
func (bc *Blockchain) validateTxPoolAdmission(tx *Transaction) error {
	if tx == nil { return fmt.Errorf("cannot validate nil tx") }
	if tx.From == "" { return fmt.Errorf("transaction has empty 'From' address") }
	nonceKey := tx.From + "_nonce"
	nonceBytes, found := bc.state.Get(nonceKey)
	currentNonce := uint64(0)
	if found {
		decoder := gob.NewDecoder(bytes.NewReader(nonceBytes))
		err := decoder.Decode(&currentNonce) // Corrected variable
		if err != nil {
			utils.ErrorLogger.Printf("[%s] Mempool Validation: Failed to decode nonce for address %s (data: %x): %v", bc.nodeID, tx.From, nonceBytes, err) // Use lowercase field
			return fmt.Errorf("failed to decode current nonce for sender %s", tx.From)
		}
	}
	if tx.Nonce != currentNonce { return fmt.Errorf("invalid nonce for pool admission: expected %d, got %d", currentNonce, tx.Nonce) }
	return nil // Return error
}

// AddTransaction adds a transaction to the memory pool after verification.
func (bc *Blockchain) AddTransaction(tx *Transaction) error {
	if tx == nil { return fmt.Errorf("cannot add nil transaction to pool") }
	if !tx.Verify() { return fmt.Errorf("invalid transaction signature or data integrity") }
	err := bc.validateTxPoolAdmission(tx) // Nonce check removed previously
	if err != nil {
		utils.WarnLogger.Printf("[%s] Tx %x... rejected from mempool: %v", bc.nodeID, tx.ID[:4], err) // Use lowercase field
		return fmt.Errorf("transaction failed pool validation: %w", err)
	}
	err = bc.txPool.Add(tx)
	if err != nil {
		if !bytes.Contains([]byte(err.Error()), []byte("already in pool")) { utils.WarnLogger.Printf("[%s] Failed to add Tx %x to pool: %v", bc.nodeID, tx.ID, err) } // Use lowercase field
		return err
	}
	utils.DebugLogger.Printf("[%s] Added Tx %x (Nonce %d) to mempool (Pool size: %d)", bc.nodeID, tx.ID[:4], tx.Nonce, bc.txPool.Count()) // Use lowercase field
	return nil // Return error
}

// GetPendingTransactions retrieves executable transactions from the pool.
func (bc *Blockchain) GetPendingTransactions(maxCount int) TxList {
	if bc.state == nil { utils.ErrorLogger.Printf("[%s] GetPendingTransactions: Blockchain has nil state manager!", bc.nodeID); return make(TxList, 0) } // Use lowercase field
	return bc.txPool.GetPending(maxCount, bc.state) // Return TxList
}

// AddBlock validates and adds a new block to the chain.
func (bc *Blockchain) AddBlock(block *Block) error {
	bc.lock.Lock() // Use lowercase field
	defer bc.lock.Unlock() // Use lowercase field
	if block == nil { return fmt.Errorf("cannot add nil block") }
	lastBlock := bc.getLastBlockInternal()
	if lastBlock == nil && block.Header.Height != 0 { return fmt.Errorf("cannot add block %d to empty chain (only genesis)", block.Header.Height) }
	if lastBlock != nil {
		if !bytes.Equal(block.Header.PrevBlockHash, lastBlock.Hash) { return fmt.Errorf("[%s] Block %d (%x) links to invalid previous hash %x (expected %x)", bc.nodeID, block.Header.Height, block.Hash, block.Header.PrevBlockHash, lastBlock.Hash) } // Use lowercase field
		if block.Header.Height != lastBlock.Header.Height+1 { return fmt.Errorf("[%s] Block %d (%x) has invalid height (expected %d)", bc.nodeID, block.Header.Height, block.Hash, lastBlock.Header.Height+1) } // Use lowercase field
	}
	calculatedHash := block.CalculateHash()
	if !bytes.Equal(block.Hash, calculatedHash) { return fmt.Errorf("[%s] Block %d (%x) has inconsistent hash (header hash calculates to: %x)", bc.nodeID, block.Header.Height, block.Hash, calculatedHash) } // Use lowercase field
	// VerifySignature call removed
	if !block.VerifyStructure() { return fmt.Errorf("[%s] Block %d (%x) has invalid structure (e.g., Merkle root mismatch)", bc.nodeID, block.Header.Height, block.Hash) } // Use lowercase field
	err := bc.state.ApplyBlock(block)
	if err != nil { return fmt.Errorf("[%s] Block %d (%x) failed state transition via state manager: %w", bc.nodeID, block.Header.Height, block.Hash, err) } // Use lowercase field
	newStateRoot := bc.state.CalculateGlobalStateRoot()
	if !bytes.Equal(block.Header.StateRoot, newStateRoot) {
		utils.ErrorLogger.Printf("[%s] CRITICAL: Block %d (%x) State Root MISMATCH! Header: %x, Calculated After Apply: %x", bc.nodeID, block.Header.Height, block.Hash, block.Header.StateRoot, newStateRoot) // Use lowercase field
		return fmt.Errorf("[%s] Block %d state root mismatch (header: %x, calculated: %x) - STATE MAY BE CORRUPT", bc.nodeID, block.Header.Height, block.Header.StateRoot, newStateRoot) // Use lowercase field
	}
	bc.Blocks = append(bc.Blocks, block)
	utils.InfoLogger.Printf("[%s] === Appended Block %d (%x) | Prev: %x... | State: %x... | Txs: %d ===", bc.nodeID, block.Header.Height, block.Hash[:6], block.Header.PrevBlockHash[:6], block.Header.StateRoot[:6], len(block.Transactions)) // Use lowercase field
	bc.txPool.Remove(block.Transactions)
	return nil // Return error
}

// LastBlock returns the most recent block in the chain.
func (bc *Blockchain) LastBlock() *Block {
	bc.lock.RLock() // Use lowercase field
	defer bc.lock.RUnlock() // Use lowercase field
	if len(bc.Blocks) == 0 { return nil }
	return bc.Blocks[len(bc.Blocks)-1] // Return *Block
}

// getLastBlockInternal gets the last block, assumes lock is held.
func (bc *Blockchain) getLastBlockInternal() *Block {
	if len(bc.Blocks) == 0 { return nil }
	return bc.Blocks[len(bc.Blocks)-1] // Return *Block
}

// GetBlockByHeight returns a block at a specific height.
func (bc *Blockchain) GetBlockByHeight(height uint64) (*Block, bool) {
	bc.lock.RLock() // Use lowercase field
	defer bc.lock.RUnlock() // Use lowercase field
	if height < uint64(len(bc.Blocks)) { return bc.Blocks[height], true }
	return nil, false // Return *Block, bool
}

// GetBlockByHash returns a block with a specific hash.
func (bc *Blockchain) GetBlockByHash(hash []byte) (*Block, bool) {
	bc.lock.RLock() // Use lowercase field
	defer bc.lock.RUnlock() // Use lowercase field
	for i := len(bc.Blocks) - 1; i >= 0; i-- { if bc.Blocks[i] != nil && bytes.Equal(bc.Blocks[i].Hash, hash) { return bc.Blocks[i], true } }; return nil, false // Return *Block, bool
}

// GetHeight returns the height of the last block.
func (bc *Blockchain) GetHeight() uint64 { lastBlock := bc.LastBlock(); if lastBlock == nil { return ^uint64(0) }; return lastBlock.Header.Height } // Return uint64

// GetNumShards returns the number of shards.
func (bc *Blockchain) GetNumShards() uint32 { if bc.state == nil { utils.WarnLogger.Printf("[%s] GetNumShards called but state manager is nil", bc.nodeID); return 0 }; return bc.state.GetNumShards() } // Return uint32

// --- Transaction Pool (Mempool) ---
type TransactionPool struct {
	pending map[string]*Transaction
	lock    sync.RWMutex
}
func NewTransactionPool() *TransactionPool { return &TransactionPool{ pending: make(map[string]*Transaction), } } // Return *TransactionPool
func (tp *TransactionPool) Add(tx *Transaction) error { tp.lock.Lock(); defer tp.lock.Unlock(); if tx == nil || tx.ID == nil { return fmt.Errorf("cannot add nil transaction or transaction with nil ID") }; txID := hex.EncodeToString(tx.ID); if _, exists := tp.pending[txID]; exists { return fmt.Errorf("transaction %s already in pool", txID) }; tp.pending[txID] = tx; utils.DebugLogger.Printf("TxPool Add: Added %s... (Nonce %d) Pool size now %d", txID[:8], tx.Nonce, len(tp.pending)); return nil } // Return error
func (tp *TransactionPool) Remove(txs TxList) { tp.lock.Lock(); defer tp.lock.Unlock(); count := 0; if len(txs) == 0 { return }; for _, tx := range txs { if tx == nil || tx.ID == nil { continue }; txID := hex.EncodeToString(tx.ID); if _, exists := tp.pending[txID]; exists { delete(tp.pending, txID); count++ } }; if count > 0 { utils.DebugLogger.Printf("TxPool: Removed %d confirmed transactions (Pool size: %d)", count, len(tp.pending)) } } // No return
func (tp *TransactionPool) GetPending(maxCount int, state StateManager) TxList { tp.lock.RLock(); defer tp.lock.RUnlock(); if state == nil { utils.ErrorLogger.Println("TxPool GetPending: Called without state manager, cannot check nonces."); return make(TxList, 0) }; poolSize := len(tp.pending); utils.DebugLogger.Printf("TxPool GetPending: Called. Pool size: %d. Max count: %d. Checking nonces...", poolSize, maxCount); if maxCount <= 0 || poolSize == 0 { return make(TxList, 0) }; executableTxs := make(TxList, 0, maxCount); senderNextNonce := make(map[string]uint64); for _, tx := range tp.pending { if tx == nil || tx.From == "" { continue }; if len(executableTxs) >= maxCount { break }; expectedNonce, known := senderNextNonce[tx.From]; if !known { nonceKey := tx.From + "_nonce"; nonceBytes, found := state.Get(nonceKey); currentNonce := uint64(0); if found { decoder := gob.NewDecoder(bytes.NewReader(nonceBytes)); err := decoder.Decode(&currentNonce); if err != nil { utils.ErrorLogger.Printf("TxPool GetPending: Failed decode nonce for %s, skipping sender's txs: %v", tx.From, err); senderNextNonce[tx.From] = ^uint64(0); continue } }; expectedNonce = currentNonce; senderNextNonce[tx.From] = expectedNonce } else if expectedNonce == ^uint64(0) { continue }; if tx.Nonce == expectedNonce { executableTxs = append(executableTxs, tx); senderNextNonce[tx.From] = expectedNonce + 1; utils.DebugLogger.Printf("TxPool GetPending: Including Tx %s... (Nonce %d)", hex.EncodeToString(tx.ID[:4]), tx.Nonce); if len(executableTxs) >= maxCount { break } } else { utils.DebugLogger.Printf("TxPool GetPending: Skipping Tx %s... (Nonce %d != Expected %d)", hex.EncodeToString(tx.ID[:4]), tx.Nonce, expectedNonce) } }; utils.DebugLogger.Printf("TxPool GetPending: Returning %d executable transactions.", len(executableTxs)); return executableTxs } // Return TxList
func (tp *TransactionPool) Count() int { tp.lock.RLock(); defer tp.lock.RUnlock(); return len(tp.pending) } // Return int