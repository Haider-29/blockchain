package state

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sync"

	"blockchain/core"
	"blockchain/utils"
)

var _ core.StateManager = (*StateManager)(nil)

type StateManager struct {
	Shards map[uint32]*Shard
	mutex  sync.RWMutex
}

func NewStateManager() *StateManager {
	sm := &StateManager{
		Shards: make(map[uint32]*Shard, NUM_SHARDS),
	}
	for i := uint32(0); i < NUM_SHARDS; i++ {
		sm.Shards[i] = NewShard(i)
	}
	utils.InfoLogger.Printf("Initialized State Manager with %d shards", NUM_SHARDS)
	return sm
}

// --- ADDED Snapshot Method ---

func (sm *StateManager) Snapshot() (*StateManager, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	if sm.Shards == nil { return nil, fmt.Errorf("cannot snapshot nil Shards map") }

	newShards := make(map[uint32]*Shard, len(sm.Shards))
	for id, originalShard := range sm.Shards {
		if originalShard == nil { return nil, fmt.Errorf("cannot snapshot: found nil shard instance for ID %d", id) }
		shardCopy, err := originalShard.Copy()
		if err != nil { return nil, fmt.Errorf("failed to copy shard %d during snapshot: %w", id, err) }
		newShards[id] = shardCopy
	}

	snapshotSM := &StateManager{ Shards: newShards }
	utils.DebugLogger.Printf("Created StateManager snapshot.")
	return snapshotSM, nil
}


// --- Methods implementing the core.StateManager interface ---

// ApplyBlock applies transactions sequentially to the COMMITTED state.
// WARNING: This is NOT ATOMIC across shards if a transaction fails mid-block.
func (sm *StateManager) ApplyBlock(block *core.Block) error {
	if block == nil { return fmt.Errorf("cannot apply nil block") }
	utils.DebugLogger.Printf("ApplyBlock %d: Applying %d txs to committed state...", block.Header.Height, len(block.Transactions))

	for i, tx := range block.Transactions {
		// Apply directly using the mutating helper which looks up shards internally
		err := sm.applyTransactionMutatingState(tx) // Use the correct internal helper
		if err != nil {
			utils.ErrorLogger.Printf("CRITICAL: Failed to apply transaction %d (%x) in block %d: %v. BLOCK APPLICATION FAILED. STATE MAY BE INCONSISTENT.", i, tx.ID[:4], block.Header.Height, err)
			// Cannot easily roll back previous txs in this simple model
			return fmt.Errorf("block %d application failed at tx %d (%x): %w", block.Header.Height, i, tx.ID[:4], err)
		}
	}
	utils.DebugLogger.Printf("Successfully applied all state changes for block %d (%x)", block.Header.Height, block.Hash[:6])
	return nil
}

// CalculateGlobalStateRoot calculates root based on COMMITTED state.
func (sm *StateManager) CalculateGlobalStateRoot() []byte {
	sm.mutex.RLock(); defer sm.mutex.RUnlock()
	if sm.Shards == nil || len(sm.Shards) == 0 { return utils.CalculateHash([]byte{}) }
	if uint32(len(sm.Shards)) != NUM_SHARDS { utils.ErrorLogger.Panicf("Inconsistency: StateManager has %d shards, but NUM_SHARDS constant is %d", len(sm.Shards), NUM_SHARDS) }
	shardRoots := make([][]byte, NUM_SHARDS)
	for i := uint32(0); i < NUM_SHARDS; i++ {
		shard, ok := sm.Shards[i]; if !ok { utils.ErrorLogger.Panicf("CRITICAL: Shard %d not found", i) }
		shardRoots[i] = shard.GetStateRoot(); if shardRoots[i] == nil { shardRoots[i] = utils.CalculateHash([]byte{}) }
	}
	globalStateTree := utils.NewMerkleTree(shardRoots); if globalStateTree == nil { utils.ErrorLogger.Panicf("CRITICAL: Failed to create Merkle tree for global state root") }
	return globalStateTree.Hash
}

// GetNumShards returns the configured number of shards.
func (sm *StateManager) GetNumShards() uint32 { return NUM_SHARDS }

// Get retrieves from the COMMITTED state.
func (sm *StateManager) Get(key string) ([]byte, bool) {
	sm.mutex.RLock()
	shard, err := sm.getShardForKeyNoLock(key)
	sm.mutex.RUnlock()
	if err != nil { return nil, false }
	return shard.Get(key)
}

// SimulateApplyTransactions now uses Snapshotting for isolation.
func (sm *StateManager) SimulateApplyTransactions(txs []*core.Transaction) ([]byte, error) {
    if sm == nil { return nil, fmt.Errorf("cannot simulate on nil StateManager") }
    utils.DebugLogger.Printf("[SIM] Creating snapshot for simulating %d txs...", len(txs))

	// 1. Create snapshot
	snapshotSM, err := sm.Snapshot()
	if err != nil { return nil, fmt.Errorf("simulation failed: could not create state snapshot: %w", err) }

    // 2. Apply transactions to the SNAPSHOT's state manager
    utils.DebugLogger.Printf("[SIM] Applying %d txs to snapshot...", len(txs))
    for i, tx := range txs {
        // Apply using the snapshot's mutating method
        err := snapshotSM.applyTransactionMutatingState(tx)
        if err != nil {
            utils.WarnLogger.Printf("[SIM] Simulation failed applying tx %d (%x) to snapshot: %v", i, tx.ID[:4], err)
            return nil, fmt.Errorf("simulation failed applying tx %x: %w", tx.ID, err)
        }
    }

    // 3. Calculate the state root FROM THE SNAPSHOT
	simulatedRoot := snapshotSM.CalculateGlobalStateRoot()
    utils.DebugLogger.Printf("[SIM] Simulation successful. Predicted root from snapshot: %x", simulatedRoot[:4])

	return simulatedRoot, nil // Return predicted root, nil error
}


// --- Internal Helper Methods ---

// getShardForKeyNoLock looks up shard without locking StateManager mutex.
func (sm *StateManager) getShardForKeyNoLock(key string) (*Shard, error) {
	shardID, err := utils.CalculateShardHint(key, NUM_SHARDS)
	if err != nil { return nil, fmt.Errorf("failed to determine shard for key '%s': %w", key, err) }
	shard, ok := sm.Shards[shardID] // Access map directly (caller holds lock)
	if !ok { return nil, fmt.Errorf("internal error: shard %d instance not found (key: %s)", shardID, key) }
	return shard, nil
}

// getCurrentNonceFromShard gets nonce by reading directly from a given shard instance.
func (sm *StateManager) getCurrentNonceFromShard(address string, shard *Shard) (uint64, error) {
	if shard == nil { return 0, fmt.Errorf("cannot get nonce from nil shard") }
	nonceKey := address + "_nonce"
	nonceBytes, found := shard.Get(nonceKey) // Call Get on the specific shard
	if !found { return 0, nil } // Default nonce 0, nil error
	var currentNonce uint64
	decoder := gob.NewDecoder(bytes.NewReader(nonceBytes))
	err := decoder.Decode(&currentNonce) // Use correct variable
	if err != nil { return 0, fmt.Errorf("failed to decode stored nonce for %s in shard %d: %w", address, shard.ID, err) }
	return currentNonce, nil
}

// setNextNonceInShard sets nonce by writing directly to a given shard instance.
func (sm *StateManager) setNextNonceInShard(address string, nextNonce uint64, shard *Shard) error {
	if shard == nil { return fmt.Errorf("cannot set nonce in nil shard") }
	nonceKey := address + "_nonce"
	var nonceBuf bytes.Buffer
	encoder := gob.NewEncoder(&nonceBuf)
	err := encoder.Encode(nextNonce)
	if err != nil { return fmt.Errorf("failed to encode next nonce %d for %s: %w", nextNonce, address, err) }
	return shard.Put(nonceKey, nonceBuf.Bytes())
}

// applyTransactionMutatingState applies tx to the *committed* state (or snapshot state).
// Looks up shards within the receiver (sm), assumes caller handles locking for map access.
func (sm *StateManager) applyTransactionMutatingState(tx *core.Transaction) error {
     if tx == nil { return fmt.Errorf("cannot apply nil transaction") }
     if tx.From == "" { return fmt.Errorf("transaction has empty 'From' address") }

	 // --- Determine shards without map lock (caller must hold) ---
     targetShard, err := sm.getShardForKeyNoLock(tx.To)
     if err != nil { return fmt.Errorf("ApplyTx: Cannot get target shard for tx %x: %w", tx.ID, err) }
     nonceShard, err := sm.getShardForKeyNoLock(tx.From + "_nonce")
     if err != nil { return fmt.Errorf("ApplyTx: Cannot get nonce shard for tx %x: %w", tx.ID, err) }

     // --- Nonce Validation (operates on specific nonceShard) ---
     currentNonce, err := sm.getCurrentNonceFromShard(tx.From, nonceShard)
     if err != nil { return fmt.Errorf("nonce validation failed for tx %x from %s: %w", tx.ID, tx.From, err) }
     if tx.Nonce != currentNonce { return fmt.Errorf("invalid nonce for tx %x from %s: expected %d, got %d", tx.ID, tx.From, currentNonce, tx.Nonce) }

     // --- Execution Phase (operates on specific targetShard) ---
     targetKey := tx.To
     var valueToStore []byte
     if len(tx.Data) > 0 { valueToStore = tx.Data } else {
         var valBuf bytes.Buffer; enc := gob.NewEncoder(&valBuf)
         if errEnc := enc.Encode(tx.Value); errEnc != nil { return fmt.Errorf("failed to encode value for tx %x: %w", tx.ID, errEnc) }
         valueToStore = valBuf.Bytes()
     }
     err = targetShard.Put(targetKey, valueToStore) // Use shard's Put
     if err != nil { return fmt.Errorf("failed to put state for tx %x key %s: %w", tx.ID, targetKey, err) }

     // --- Update Nonce State (operates on specific nonceShard) ---
     nextNonce := currentNonce + 1
     err = sm.setNextNonceInShard(tx.From, nextNonce, nonceShard) // Use shard-specific setter
     if err != nil { return fmt.Errorf("failed to update nonce for tx %x: %w", tx.ID, err) }

     return nil
}

// applyTransactionToCopies is REMOVED
// revertSimulationChanges is REMOVED


// --- Public methods for direct access (Put, Delete) need locking ---
func (sm *StateManager) Put(key string, value []byte) error {
	sm.mutex.RLock(); shard, err := sm.getShardForKeyNoLock(key); sm.mutex.RUnlock()
	if err != nil { return err }
	return shard.Put(key, value)
}
func (sm *StateManager) Delete(key string) error {
	sm.mutex.RLock(); shard, err := sm.getShardForKeyNoLock(key); sm.mutex.RUnlock()
	if err != nil { return err }
	return shard.Delete(key)
}