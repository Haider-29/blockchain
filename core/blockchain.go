package core

import (
	"bytes"
	"encoding/hex" // Keep for TxPool methods if used there
	"fmt"
	"sync"

	// "blockchain/state" // REMOVED
	"blockchain/utils"
    // "blockchain/crypto" // REMOVE if not used (e.g., if state validation in AddTransaction is removed/commented out)
)

// Blockchain manages the chain of blocks and state.
type Blockchain struct {
	Blocks       []*Block
	state        StateManager     // Use the interface type defined in core/interfaces.go
	Genesis      *Block
	txPool       *TransactionPool // Use the TransactionPool defined below
	lock         sync.RWMutex
	nodeID       string
}

// NewBlockchain creates a new blockchain instance with a genesis block.
// It now accepts the StateManager interface.
func NewBlockchain(stateMgr StateManager, genesis *Block, nodeID string) (*Blockchain, error) {
    // Validate inputs
    if stateMgr == nil {
        return nil, fmt.Errorf("state manager (interface) cannot be nil")
    }
    if genesis == nil {
        return nil, fmt.Errorf("genesis block cannot be nil")
    }
    // Basic check: Ensure genesis state root matches the one calculated by the provided manager
    initialStateRoot := stateMgr.CalculateGlobalStateRoot()
    if !bytes.Equal(genesis.Header.StateRoot, initialStateRoot) {
        utils.ErrorLogger.Printf("[%s] Genesis block state root (%x) does not match initial state manager root (%x)",
            nodeID, genesis.Header.StateRoot, initialStateRoot)
        return nil, fmt.Errorf("genesis state root mismatch (Header: %x, Calculated: %x). Ensure initial state is correct.",
            genesis.Header.StateRoot, initialStateRoot)
    }


	bc := &Blockchain{
		Blocks:       make([]*Block, 0, 100), // Pre-allocate capacity
		state:        stateMgr,               // Assign the provided implementation
		Genesis:      genesis,
		txPool:       NewTransactionPool(), // Create a new TxPool instance
		nodeID:       nodeID,
	}
    bc.Blocks = append(bc.Blocks, genesis) // Add the genesis block

	utils.InfoLogger.Printf("[%s] Blockchain initialized. Genesis: %x, Height: %d", nodeID, genesis.Hash, genesis.Header.Height)
	return bc, nil
}

// AddTransaction adds a transaction to the memory pool after basic verification.
func (bc *Blockchain) AddTransaction(tx *Transaction) error {
    if tx == nil {
        return fmt.Errorf("cannot add nil transaction to pool")
    }
	if !tx.Verify() {
		return fmt.Errorf("invalid transaction signature or data integrity")
	}

	// Optional state validation (requires Get method in StateManager interface)
	// Example:
	// nonceBytes, found := bc.state.Get(tx.From + "_nonce") // Assuming Get exists on interface
	// if found { ... compare nonce ... } else { ... handle new account ... }

	err := bc.txPool.Add(tx) // Add to the blockchain's txPool instance
	if err != nil {
        // Log only if it's not a duplicate error (already handled by Add)
		if !bytes.Contains([]byte(err.Error()), []byte("already in pool")) {
             utils.WarnLogger.Printf("[%s] Failed to add Tx %x to pool: %v", bc.nodeID, tx.ID, err)
        }
		return err
	}
	utils.DebugLogger.Printf("[%s] Added Tx %x to mempool (Pool size: %d)", bc.nodeID, tx.ID, bc.txPool.Count())
	return nil
}

// GetPendingTransactions returns transactions from the pool for block creation.
func (bc *Blockchain) GetPendingTransactions(maxCount int) TxList {
	return bc.txPool.GetPending(maxCount)
}

// AddBlock validates and adds a new block to the chain.
func (bc *Blockchain) AddBlock(block *Block) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

    if block == nil { return fmt.Errorf("cannot add nil block") }

	lastBlock := bc.getLastBlockInternal()

	// --- Basic Header & Structure Validations (remain the same) ---
	if !bytes.Equal(block.Header.PrevBlockHash, lastBlock.Hash) {
		return fmt.Errorf("[%s] Block %d (%x) links to invalid previous hash %x (expected %x)",
			bc.nodeID, block.Header.Height, block.Hash, block.Header.PrevBlockHash, lastBlock.Hash)
	}
	if block.Header.Height != lastBlock.Header.Height+1 {
		return fmt.Errorf("[%s] Block %d (%x) has invalid height (expected %d)",
			bc.nodeID, block.Header.Height, block.Hash, lastBlock.Header.Height+1)
	}
    calculatedHash := block.CalculateHash()
    if !bytes.Equal(block.Hash, calculatedHash) {
        return fmt.Errorf("[%s] Block %d (%x) has inconsistent hash (header hash calculates to: %x)",
            bc.nodeID, block.Header.Height, block.Hash, calculatedHash)
    }
	if !block.VerifySignature() {
        // Allow unsigned genesis block if it matches
        if !(block.Header.Height == 0 && bytes.Equal(block.Hash, bc.Genesis.Hash)) {
		    return fmt.Errorf("[%s] Block %d (%x) has invalid validator signature from %s",
                bc.nodeID, block.Header.Height, block.Hash, block.Header.Validator)
        }
	}
    if !block.VerifyStructure() {
         return fmt.Errorf("[%s] Block %d (%x) has invalid structure (e.g., Merkle root mismatch)",
            bc.nodeID, block.Header.Height, block.Hash)
    }

	// --- State Transition Validation (Using Interface) ---
	err := bc.state.ApplyBlock(block) // Use the interface method
	if err != nil {
		return fmt.Errorf("[%s] Block %d (%x) failed state transition via state manager: %w", bc.nodeID, block.Header.Height, block.Hash, err)
	}
	newStateRoot := bc.state.CalculateGlobalStateRoot() // Use the interface method
	if !bytes.Equal(block.Header.StateRoot, newStateRoot) {
		utils.ErrorLogger.Printf("[%s] CRITICAL: Block %d (%x) State Root MISMATCH! Header: %x, Calculated After Apply: %x",
			bc.nodeID, block.Header.Height, block.Hash, block.Header.StateRoot, newStateRoot)
		return fmt.Errorf("[%s] Block %d state root mismatch (header: %x, calculated: %x) - STATE MAY BE CORRUPT",
			bc.nodeID, block.Header.Height, block.Header.StateRoot, newStateRoot)
	}

	// --- Block Accepted ---
	bc.Blocks = append(bc.Blocks, block)
	utils.InfoLogger.Printf("[%s] === Appended Block %d (%x) | Prev: %x... | State: %x... | Txs: %d ===",
		bc.nodeID, block.Header.Height, block.Hash[:6], block.Header.PrevBlockHash[:6], block.Header.StateRoot[:6], len(block.Transactions))
	bc.txPool.Remove(block.Transactions) // Remove from the blockchain's txPool
	return nil
}

// LastBlock returns the most recent block in the chain (read-only access).
func (bc *Blockchain) LastBlock() *Block {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
    if len(bc.Blocks) == 0 { return nil } // Handle empty chain case
	return bc.Blocks[len(bc.Blocks)-1]
}

// getLastBlockInternal is used internally when write lock is already held.
func (bc *Blockchain) getLastBlockInternal() *Block {
    if len(bc.Blocks) == 0 { return nil } // Handle empty chain case
    return bc.Blocks[len(bc.Blocks)-1]
}

// GetBlockByHeight returns a block at a specific height.
func (bc *Blockchain) GetBlockByHeight(height uint64) (*Block, bool) {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	if height < uint64(len(bc.Blocks)) {
		return bc.Blocks[height], true
	}
	return nil, false
}

// GetBlockByHash returns a block with a specific hash.
func (bc *Blockchain) GetBlockByHash(hash []byte) (*Block, bool) {
    bc.lock.RLock()
    defer bc.lock.RUnlock()
    // Inefficient linear scan for simplicity. A map[string]*Block would be faster.
    for i := len(bc.Blocks) - 1; i >= 0; i-- {
        if bc.Blocks[i] != nil && bytes.Equal(bc.Blocks[i].Hash, hash) {
            return bc.Blocks[i], true
        }
    }
    return nil, false
}

// GetHeight returns the height of the last block in the chain.
func (bc *Blockchain) GetHeight() uint64 {
    lastBlock := bc.LastBlock() // Use locking getter
    if lastBlock == nil { return ^uint64(0) } // Return max uint64 if no blocks (or -1 conceptually)
    return lastBlock.Header.Height
}

// GetNumShards uses the interface method on the embedded state manager.
func (bc *Blockchain) GetNumShards() uint32 {
    if bc.state == nil {
        utils.WarnLogger.Printf("[%s] GetNumShards called but state manager is nil", bc.nodeID)
        return 0 // Or default shard count?
    }
    return bc.state.GetNumShards() // Call interface method
}


// --- Transaction Pool (Mempool) --- (Single Definition)

// TransactionPool holds pending transactions. Needs to be thread-safe.
type TransactionPool struct {
	pending map[string]*Transaction // Map tx ID (hex) -> Transaction
	lock    sync.RWMutex
}

// NewTransactionPool creates a new transaction pool.
func NewTransactionPool() *TransactionPool {
	return &TransactionPool{
		pending: make(map[string]*Transaction),
	}
}

// Add adds a transaction to the pool if it's not already present.
func (tp *TransactionPool) Add(tx *Transaction) error {
	tp.lock.Lock()
	defer tp.lock.Unlock()
    if tx == nil || tx.ID == nil { return fmt.Errorf("cannot add nil transaction or transaction with nil ID") }
	txID := hex.EncodeToString(tx.ID)
	if _, exists := tp.pending[txID]; exists { return fmt.Errorf("transaction %s already in pool", txID) }
	// TODO: Implement pool size limits, eviction policies (e.g., based on fees/nonce)
	tp.pending[txID] = tx
	// utils.DebugLogger.Printf("TxPool: Added %s", txID)
	return nil
}

// Remove removes confirmed transactions (those included in a block) from the pool.
func (tp *TransactionPool) Remove(txs TxList) {
	tp.lock.Lock()
	defer tp.lock.Unlock()
	count := 0
	for _, tx := range txs {
        if tx == nil || tx.ID == nil { continue } // Skip nil transactions/IDs
		txID := hex.EncodeToString(tx.ID)
		if _, exists := tp.pending[txID]; exists {
			delete(tp.pending, txID)
			count++
		}
	}
	if count > 0 {
		utils.DebugLogger.Printf("TxPool: Removed %d confirmed transactions (Pool size: %d)", count, len(tp.pending))
	}
}

// GetPending returns a list of transactions ready for block creation.
// A real pool would apply ordering logic (e.g., by fee, nonce).
func (tp *TransactionPool) GetPending(maxCount int) TxList {
	tp.lock.RLock()
	defer tp.lock.RUnlock()

    if maxCount <= 0 || len(tp.pending) == 0 {
        return make(TxList, 0) // Return empty slice
    }

	// Simple iteration (no specific ordering).
    // Allocate slice with appropriate capacity.
    capacity := maxCount
    if len(tp.pending) < maxCount {
        capacity = len(tp.pending)
    }
	txs := make(TxList, 0, capacity)

	count := 0
	for _, tx := range tp.pending {
		// TODO: Add validation here? Ensure tx is still valid w.r.t current state?
        // Usually done by proposer just before including in a block.
		txs = append(txs, tx)
		count++
        if count >= maxCount {
			break
		}
	}
	// utils.DebugLogger.Printf("TxPool: Retrieved %d pending transactions (max %d)", len(txs), maxCount)
	return txs
}

// Count returns the number of pending transactions.
func (tp *TransactionPool) Count() int {
    tp.lock.RLock()
    defer tp.lock.RUnlock()
    return len(tp.pending)
}

// --- REMOVE THE DUPLICATED CODE THAT WAS HERE ---