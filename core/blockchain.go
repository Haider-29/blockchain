package core

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"sync"

	"blockchain/utils"
	// StateManager interface defined in interfaces.go
)

// Blockchain manages the chain of blocks and state.
type Blockchain struct {
	Blocks       []*Block
	state        StateManager // Interface type
	Genesis      *Block
	txPool       *TransactionPool
	lock         sync.RWMutex
	nodeID       string
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
		nodeID:  nodeID,
	}
	bc.Blocks = append(bc.Blocks, genesis)
	utils.InfoLogger.Printf("[%s] Blockchain initialized. Genesis: %x, Height: %d", nodeID, genesis.Hash, genesis.Header.Height)
	return bc, nil
}

// validateTxPoolAdmission - REMOVED Nonce Check. Only performs basic static checks.
func (bc *Blockchain) validateTxPoolAdmission(tx *Transaction) error {
	if tx == nil { return fmt.Errorf("cannot validate nil tx") }
	if tx.From == "" { return fmt.Errorf("transaction has empty 'From' address") }
	// --- NONCE CHECK REMOVED FROM HERE ---
	// --- Optional: Add other STATIC checks here ---
	return nil
}

// AddTransaction adds a transaction to the memory pool after verification.
// Nonce validation moved to GetPendingTransactions.
func (bc *Blockchain) AddTransaction(tx *Transaction) error {
	if tx == nil { return fmt.Errorf("cannot add nil transaction to pool") }

	// 1. Basic cryptographic verification
	if !tx.Verify() { return fmt.Errorf("invalid transaction signature or data integrity") }

	// 2. Optional Static validation (signature format, etc.)
	// err := bc.validateTxPoolAdmission(tx)
	// if err != nil {
	// 	 utils.WarnLogger.Printf("[%s] Tx %x... rejected from mempool (static validation): %v", bc.nodeID, tx.ID[:4], err)
	// 	 return fmt.Errorf("transaction failed pool validation: %w", err)
	// }

	// 3. Add to pool (pool accepts potentially future nonces now)
	err := bc.txPool.Add(tx)
	if err != nil {
		// Don't warn again for duplicates, Add handles that log
		if !bytes.Contains([]byte(err.Error()), []byte("already in pool")) {
			utils.WarnLogger.Printf("[%s] Failed to add Tx %x to pool: %v", bc.nodeID, tx.ID, err)
		}
		return err
	}

	utils.DebugLogger.Printf("[%s] Added Tx %x (Nonce %d) to mempool (Pool size: %d)", bc.nodeID, tx.ID[:4], tx.Nonce, bc.txPool.Count())
	return nil
}

// GetPendingTransactions retrieves executable transactions from the pool.
// Passes the state manager down to txPool's GetPending for nonce checking.
func (bc *Blockchain) GetPendingTransactions(maxCount int) TxList {
	// Pass the state manager interface for nonce checking
	if bc.state == nil {
		utils.ErrorLogger.Printf("[%s] GetPendingTransactions: Blockchain has nil state manager!", bc.nodeID)
		return make(TxList, 0)
	}
	return bc.txPool.GetPending(maxCount, bc.state) // Pass state
}

// AddBlock validates and adds a new block to the chain.
func (bc *Blockchain) AddBlock(block *Block) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	if block == nil { return fmt.Errorf("cannot add nil block") }
	lastBlock := bc.getLastBlockInternal()
	if lastBlock == nil && block.Header.Height != 0 { return fmt.Errorf("cannot add block %d to empty chain (only genesis)", block.Header.Height) }
	if lastBlock != nil {
		if !bytes.Equal(block.Header.PrevBlockHash, lastBlock.Hash) { return fmt.Errorf("[%s] Block %d (%x) links to invalid previous hash %x (expected %x)", bc.nodeID, block.Header.Height, block.Hash, block.Header.PrevBlockHash, lastBlock.Hash) }
		if block.Header.Height != lastBlock.Header.Height+1 { return fmt.Errorf("[%s] Block %d (%x) has invalid height (expected %d)", bc.nodeID, block.Header.Height, block.Hash, lastBlock.Header.Height+1) }
	}
	calculatedHash := block.CalculateHash()
	if !bytes.Equal(block.Hash, calculatedHash) { return fmt.Errorf("[%s] Block %d (%x) has inconsistent hash (header hash calculates to: %x)", bc.nodeID, block.Header.Height, block.Hash, calculatedHash) }
	if !block.VerifySignature() { if !(block.Header.Height == 0 && bytes.Equal(block.Hash, bc.Genesis.Hash)) { return fmt.Errorf("[%s] Block %d (%x) has invalid validator signature from %s", bc.nodeID, block.Header.Height, block.Hash, block.Header.Validator) } }
	if !block.VerifyStructure() { return fmt.Errorf("[%s] Block %d (%x) has invalid structure (e.g., Merkle root mismatch)", bc.nodeID, block.Header.Height, block.Hash) }
	err := bc.state.ApplyBlock(block) // Apply block state changes
	if err != nil { return fmt.Errorf("[%s] Block %d (%x) failed state transition via state manager: %w", bc.nodeID, block.Header.Height, block.Hash, err) }
	newStateRoot := bc.state.CalculateGlobalStateRoot() // Verify resulting state root
	if !bytes.Equal(block.Header.StateRoot, newStateRoot) {
		utils.ErrorLogger.Printf("[%s] CRITICAL: Block %d (%x) State Root MISMATCH! Header: %x, Calculated After Apply: %x", bc.nodeID, block.Header.Height, block.Hash, block.Header.StateRoot, newStateRoot)
		return fmt.Errorf("[%s] Block %d state root mismatch (header: %x, calculated: %x) - STATE MAY BE CORRUPT", bc.nodeID, block.Header.Height, block.Header.StateRoot, newStateRoot)
	}
	bc.Blocks = append(bc.Blocks, block) // Block accepted
	utils.InfoLogger.Printf("[%s] === Appended Block %d (%x) | Prev: %x... | State: %x... | Txs: %d ===", bc.nodeID, block.Header.Height, block.Hash[:6], block.Header.PrevBlockHash[:6], block.Header.StateRoot[:6], len(block.Transactions))
	bc.txPool.Remove(block.Transactions) // Remove from this blockchain's txPool
	return nil
}

// LastBlock returns the most recent block in the chain.
func (bc *Blockchain) LastBlock() *Block {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	if len(bc.Blocks) == 0 { return nil }
	return bc.Blocks[len(bc.Blocks)-1]
}

// getLastBlockInternal gets the last block, assumes lock is held.
func (bc *Blockchain) getLastBlockInternal() *Block {
	if len(bc.Blocks) == 0 { return nil }
	return bc.Blocks[len(bc.Blocks)-1]
}

// GetBlockByHeight returns a block at a specific height.
func (bc *Blockchain) GetBlockByHeight(height uint64) (*Block, bool) {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	if height < uint64(len(bc.Blocks)) { return bc.Blocks[height], true }
	return nil, false
}

// GetBlockByHash returns a block with a specific hash.
func (bc *Blockchain) GetBlockByHash(hash []byte) (*Block, bool) {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	for i := len(bc.Blocks) - 1; i >= 0; i-- { if bc.Blocks[i] != nil && bytes.Equal(bc.Blocks[i].Hash, hash) { return bc.Blocks[i], true } }; return nil, false
}

// GetHeight returns the height of the last block.
func (bc *Blockchain) GetHeight() uint64 { lastBlock := bc.LastBlock(); if lastBlock == nil { return ^uint64(0) }; return lastBlock.Header.Height }

// GetNumShards returns the number of shards.
func (bc *Blockchain) GetNumShards() uint32 { if bc.state == nil { return 0 }; return bc.state.GetNumShards() }

// --- Transaction Pool (Mempool) ---

// TransactionPool holds pending transactions.
type TransactionPool struct {
	pending map[string]*Transaction
	lock    sync.RWMutex
}

// NewTransactionPool creates a new transaction pool.
func NewTransactionPool() *TransactionPool {
	return &TransactionPool{
		pending: make(map[string]*Transaction),
	}
}

// Add adds a transaction to the pool.
func (tp *TransactionPool) Add(tx *Transaction) error {
	tp.lock.Lock()
	defer tp.lock.Unlock()
	if tx == nil || tx.ID == nil { return fmt.Errorf("cannot add nil transaction or transaction with nil ID") }
	txID := hex.EncodeToString(tx.ID)
	if _, exists := tp.pending[txID]; exists { return fmt.Errorf("transaction %s already in pool", txID) }
	tp.pending[txID] = tx
	utils.DebugLogger.Printf("TxPool Add: Added %s... (Nonce %d) Pool size now %d", txID[:8], tx.Nonce, len(tp.pending))
	return nil
}

// Remove removes confirmed transactions from the pool.
func (tp *TransactionPool) Remove(txs TxList) {
	tp.lock.Lock()
	defer tp.lock.Unlock()
	count := 0
	if len(txs) == 0 { return } // No transactions to remove
	for _, tx := range txs {
		if tx == nil || tx.ID == nil { continue }
		txID := hex.EncodeToString(tx.ID)
		if _, exists := tp.pending[txID]; exists { delete(tp.pending, txID); count++ }
	}
	if count > 0 { utils.DebugLogger.Printf("TxPool: Removed %d confirmed transactions (Pool size: %d)", count, len(tp.pending)) }
}

// GetPending selects executable transactions based on current state nonce.
func (tp *TransactionPool) GetPending(maxCount int, state StateManager) TxList {
	tp.lock.RLock()
	defer tp.lock.RUnlock()

	if state == nil {
		utils.ErrorLogger.Println("TxPool GetPending: Called without state manager, cannot check nonces.")
		return make(TxList, 0)
	}

	poolSize := len(tp.pending)
	utils.DebugLogger.Printf("TxPool GetPending: Called. Pool size: %d. Max count: %d. Checking nonces...", poolSize, maxCount)

	if maxCount <= 0 || poolSize == 0 { return make(TxList, 0) }

	executableTxs := make(TxList, 0, maxCount)
	senderNextNonce := make(map[string]uint64) // Cache expected nonce

	// It's better to iterate in a somewhat deterministic order if possible,
	// although map iteration isn't guaranteed. For simulation, this is okay.
	// A real pool might use multiple lists (e.g., ordered by fee).
	for _, tx := range tp.pending {
		if tx == nil || tx.From == "" { continue }
		if len(executableTxs) >= maxCount { break } // Stop if we have enough

		expectedNonce, known := senderNextNonce[tx.From]
		if !known {
			// Fetch nonce from state for this sender
			nonceKey := tx.From + "_nonce"
			nonceBytes, found := state.Get(nonceKey)
			currentNonce := uint64(0)
			if found {
				decoder := gob.NewDecoder(bytes.NewReader(nonceBytes))
				err := decoder.Decode(&currentNonce)
				if err != nil {
					utils.ErrorLogger.Printf("TxPool GetPending: Failed decode nonce for %s, skipping sender's txs: %v", tx.From, err)
					senderNextNonce[tx.From] = ^uint64(0) // Mark as invalid
					continue
				}
			}
			expectedNonce = currentNonce
			senderNextNonce[tx.From] = expectedNonce
		} else if expectedNonce == ^uint64(0) { // Skip if nonce decode failed previously
            continue
        }


		if tx.Nonce == expectedNonce {
			executableTxs = append(executableTxs, tx)
			senderNextNonce[tx.From] = expectedNonce + 1 // Expect next nonce for this sender
			utils.DebugLogger.Printf("TxPool GetPending: Including Tx %s... (Nonce %d)", hex.EncodeToString(tx.ID[:4]), tx.Nonce)
		} else {
             utils.DebugLogger.Printf("TxPool GetPending: Skipping Tx %s... (Nonce %d != Expected %d)", hex.EncodeToString(tx.ID[:4]), tx.Nonce, expectedNonce)
        }
	}

	// TODO: Sort executableTxs by nonce (primary) and maybe fee (secondary)?

	utils.DebugLogger.Printf("TxPool GetPending: Returning %d executable transactions.", len(executableTxs))
	return executableTxs
}

// Count returns the number of pending transactions.
func (tp *TransactionPool) Count() int {
	tp.lock.RLock()
	defer tp.lock.RUnlock()
	return len(tp.pending)
}