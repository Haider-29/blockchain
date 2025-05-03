package state

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sync"

	// Keep core import for *core.Transaction and *core.Block types used in method signatures
	"blockchain/core"
	"blockchain/utils"
)

// Compile-time check to ensure *StateManager implements the core.StateManager interface.
// If the interface changes in core, this line will cause a compile error here.
var _ core.StateManager = (*StateManager)(nil)

// StateManager handles the sharded global state.
type StateManager struct {
	Shards map[uint32]*Shard // Map shard ID -> Shard instance
	mutex  sync.RWMutex      // Protects the Shards map itself if dynamic sharding were added. Currently read-only after init.
}


// NewStateManager initializes the state manager with a fixed number of shards defined by NUM_SHARDS.
func NewStateManager() *StateManager {
	sm := &StateManager{
		// Initialize the map with the expected capacity
        Shards: make(map[uint32]*Shard, NUM_SHARDS),
	}
	// Create each shard instance
    for i := uint32(0); i < NUM_SHARDS; i++ {
		sm.Shards[i] = NewShard(i)
	}
	utils.InfoLogger.Printf("Initialized State Manager with %d shards", NUM_SHARDS)
	return sm
} // <--- Correctly returns sm


// --- Methods implementing the core.StateManager interface ---

// ApplyBlock applies all transactions within a given block sequentially.
// This method now fulfills the core.StateManager interface requirement.
// WARNING: STILL LACKS ATOMICITY in this simplified implementation.
func (sm *StateManager) ApplyBlock(block *core.Block) error {
    if block == nil { return fmt.Errorf("cannot apply nil block") }
	utils.DebugLogger.Printf("Applying state changes for block %d (%x) with %d transactions...", block.Header.Height, block.Hash[:6], len(block.Transactions))

	// Create a *copy* of the state to apply changes to, or implement proper rollback.
	// For this simple simulation, we still apply directly, accepting the lack of atomicity.
	// A real implementation would use snapshots here.

	for i, tx := range block.Transactions {
		// Use the PUBLIC methods (Put/Delete/Get) to apply the transaction logic.
        // This ensures the same logic is used as external callers and avoids
        // needing an exported internal apply method.
		err := sm.applyTransactionUsingPublicMethods(tx) // Use helper that calls Put/Get etc.
		if err != nil {
			utils.ErrorLogger.Printf("CRITICAL: Failed to apply transaction %d (%x) in block %d: %v. BLOCK APPLICATION FAILED. STATE MAY BE INCONSISTENT.", i, tx.ID[:4], block.Header.Height, err)
			// *** ROLLBACK MECHANISM NEEDED HERE FOR PRODUCTION ***
			return fmt.Errorf("block %d application failed at tx %d (%x): %w", block.Header.Height, i, tx.ID[:4], err)
		}
	}
	utils.DebugLogger.Printf("Successfully applied all state changes for block %d (%x)", block.Header.Height, block.Hash[:6])
	return nil
}

// CalculateGlobalStateRoot computes the single root hash representing the combined state of all shards.
// This method now fulfills the core.StateManager interface requirement.
func (sm *StateManager) CalculateGlobalStateRoot() []byte {
	// Check if state manager is initialized
    if sm.Shards == nil || len(sm.Shards) == 0 {
        utils.WarnLogger.Println("Calculating global state root with zero shards or uninitialized manager.")
		return utils.CalculateHash([]byte{}) // Return hash of empty data
	}
    // Ensure we handle the expected number of shards consistently.
    if uint32(len(sm.Shards)) != NUM_SHARDS {
        utils.ErrorLogger.Panicf("Inconsistency: StateManager has %d shards, but NUM_SHARDS constant is %d", len(sm.Shards), NUM_SHARDS)
        // Panic makes return unreachable, but for clarity:
        // return nil
    }

	// Collect the state root from each shard. Order matters for deterministic global root.
	shardRoots := make([][]byte, NUM_SHARDS) // Slice size matches the constant
	for i := uint32(0); i < NUM_SHARDS; i++ {
        // Look up the shard; should exist if initialized correctly.
        shard, ok := sm.Shards[i]
        if !ok {
            // This indicates a critical initialization or corruption issue.
            utils.ErrorLogger.Panicf("CRITICAL: Shard %d not found in StateManager map during global state root calculation", i)
            // return nil // Unreachable due to panic
        }

        // Get the shard's current state root (provides a copy).
		shardRoots[i] = shard.GetStateRoot()

        // Handle unlikely case where a shard's root is nil (e.g., calculation error within shard).
        if shardRoots[i] == nil {
            utils.ErrorLogger.Printf("Warning: Shard %d returned a nil state root during global calculation. Using empty hash as placeholder.", i)
            // Use a deterministic placeholder (hash of empty data) to prevent nil pointers later.
            shardRoots[i] = utils.CalculateHash([]byte{})
        }
	}

	// Construct a Merkle tree using the collected shard roots as leaves.
    // This provides a more robust aggregation than simple concatenation.
    globalStateTree := utils.NewMerkleTree(shardRoots)
    if globalStateTree == nil {
         // NewMerkleTree should handle empty input, but panic if it returns nil unexpectedly otherwise.
         utils.ErrorLogger.Panicf("CRITICAL: Failed to create Merkle tree for global state root calculation (Input roots count: %d)", len(shardRoots))
         // return nil // Unreachable due to panic
    }

    // The root of this Merkle tree is the global state root.
	globalRoot := globalStateTree.Hash
	// utils.DebugLogger.Printf("Calculated Global State Root: %x", globalRoot)
	return globalRoot
} // <--- Correctly returns globalRoot


// GetNumShards returns the configured number of shards.
// This method now fulfills the core.StateManager interface requirement.
func (sm *StateManager) GetNumShards() uint32 {
    return NUM_SHARDS
}


// --- Internal Helper Methods (Not part of the interface, but used by interface methods) ---

// getShardForKey remains an internal helper
func (sm *StateManager) getShardForKey(key string) (*Shard, error) {
	// Calculate the shard ID using the function moved to utils
    shardID, err := utils.CalculateShardHint(key, NUM_SHARDS)
    if err != nil {
        // Log the error and return it, preventing operation on wrong/no shard
         utils.ErrorLogger.Printf("Error calculating shard hint for key '%s': %v. Cannot determine shard.", key, err)
         return nil, fmt.Errorf("failed to determine shard for key '%s': %w", key, err)
    }

    // Look up the shard instance in the manager's map
	shard, ok := sm.Shards[shardID]
    if !ok {
        // This indicates a serious internal inconsistency (e.g., NUM_SHARDS mismatch or map corruption)
        // Panic might be justified here as the system state is undefined.
        utils.ErrorLogger.Panicf("CRITICAL INCONSISTENCY: Shard %d calculated for key '%s' does not exist in StateManager's map", shardID, key)
        // return nil, fmt.Errorf("internal error: shard %d instance not found", shardID) // Should be unreachable due to panic
    }
	// Return the found shard instance and nil error
    return shard, nil
} // <--- Correctly returns shard, nil


// applyTransactionUsingPublicMethods applies a transaction's logic by calling
// the public Get/Put methods of the StateManager itself.
// This is the logic that ApplyBlock will execute for each transaction.
func (sm *StateManager) applyTransactionUsingPublicMethods(tx *core.Transaction) error {
     if tx == nil { return fmt.Errorf("cannot apply nil transaction") }

     // --- Validation Phase (using Get) ---
     // Example: Check Nonce
     // nonceKey := tx.From + "_nonce"
     // nonceBytes, found := sm.Get(nonceKey)
     // currentNonce := uint64(0)
     // if found { /* decode nonceBytes into currentNonce */ }
     // if tx.Nonce != currentNonce { return fmt.Errorf("invalid nonce") }

     // Example: Check Balance (if Value > 0)
     // if tx.Value > 0 {
     //     balanceKey := tx.From + "_balance"
     //     balanceBytes, found := sm.Get(balanceKey)
     //     // ... check if found and balance >= tx.Value ...
     // }

     // --- Execution Phase (using Put/Delete) ---
     // Simple KV store example: Put data at 'To' address
     targetKey := tx.To
     var valueToStore []byte
     if len(tx.Data) > 0 { valueToStore = tx.Data } else {
         var valBuf bytes.Buffer
         enc := gob.NewEncoder(&valBuf)
         if errEnc := enc.Encode(tx.Value); errEnc != nil {
              return fmt.Errorf("failed to encode value for tx %x: %w", tx.ID, errEnc)
         }
         valueToStore = valBuf.Bytes()
     }
     err := sm.Put(targetKey, valueToStore) // Use public Put method
     if err != nil {
         return fmt.Errorf("failed to put state for tx %x key %s: %w", tx.ID, targetKey, err)
     }

     // Example: Update Nonce
     // nextNonceBytes := // encode tx.Nonce + 1
     // sm.Put(nonceKey, nextNonceBytes)

     // Example: Update Balances
     // sm.Put(balanceKey, newSenderBalanceBytes)
     // sm.Put(tx.To + "_balance", newReceiverBalanceBytes)

     // utils.DebugLogger.Printf("Applied Tx %x using public methods", tx.ID) // Logged by ApplyBlock summary
     return nil
}


// --- Public methods for direct access (OPTIONAL - Not part of core.StateManager interface by default) ---

// Get retrieves a value directly (might be useful for external queries).
func (sm *StateManager) Get(key string) ([]byte, bool) {
	shard, err := sm.getShardForKey(key)
	if err != nil { return nil, false }
	return shard.Get(key)
}

// Put updates/inserts a value directly (use with caution outside block application).
func (sm *StateManager) Put(key string, value []byte) error {
	shard, err := sm.getShardForKey(key)
	if err != nil { return err }
	shard.Put(key, value) // This calls the shard's Put, which recalculates root
    return nil
}

// Delete removes a value directly (use with caution outside block application).
func (sm *StateManager) Delete(key string) error {
	shard, err := sm.getShardForKey(key)
    if err != nil { return err }
	shard.Delete(key) // This calls the shard's Delete, which recalculates root
    return nil
}


// --- REMOVE THE DUPLICATED CODE SECTION LABELED "Implementation details copied" ---
// // --- Implementation details copied from previous correct version ---
// func NewStateManager() *StateManager { /* ... */ }               // DUPLICATE REMOVED
// func (sm *StateManager) getShardForKey(key string) (*Shard, error) { /* ... */ } // DUPLICATE REMOVED
// func (sm *StateManager) CalculateGlobalStateRoot() []byte { /* ... */ } // DUPLICATE REMOVED