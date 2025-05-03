package state

import (
	// "bytes" // Not needed directly now
	// "encoding/gob" // Not needed directly now
	// "sort" // Not needed for SMT
	"sync"
	"fmt" // Added for error formatting

	"blockchain/utils"
)

// NUM_SHARDS constant remains the same...
const NUM_SHARDS uint32 = 4

// Shard represents a partition of the state using an SMT.
type Shard struct {
	ID    uint32
	tree  *utils.SMT // Use the Sparse Merkle Tree
	mutex sync.RWMutex // Protects access to the SMT instance (tree field)
}

// NewShard creates a new, empty shard with an initialized SMT.
func NewShard(id uint32) *Shard {
	s := &Shard{
		ID:   id,
		tree: utils.NewSMT(), // Initialize the SMT
	}
	// Initial root is handled by SMT's NewSMT() -> Root() method.
	utils.DebugLogger.Printf("Shard %d initialized with SMT root: %x", id, s.tree.Root())
	return s
}

// Get retrieves a value from the shard using the SMT.
// NOTE: The current simplified SMT's Get only proves existence, doesn't return the value.
// This will need to be addressed if actual value retrieval is needed later.
func (s *Shard) Get(key string) ([]byte, bool) {
	s.mutex.RLock() // SMT methods are internally locked, but lock here protects tree pointer swap if needed later
	defer s.mutex.RUnlock()

	// SMT Get currently returns ErrKeyNotFound or nil error (if hash exists).
	// It doesn't return the value itself.
	_, err := s.tree.Get([]byte(key)) // Use SMT Get
	if err == utils.ErrKeyNotFound {
		return nil, false // Key not found
	}
	if err != nil {
		// Log other potential errors from SMT Get if they were implemented
		utils.ErrorLogger.Printf("Shard %d: Error during SMT Get for key '%s': %v", s.ID, key, err)
		return nil, false
	}

	// If Get succeeds (nil error), it means the key *exists* (or existed) in the tree structure.
	// But we cannot return the value with the current simple SMT.
	// For now, return nil and true to indicate presence.
	// TODO: Enhance SMT to store and retrieve actual values.
	utils.WarnLogger.Printf("Shard %d: SMT Get found key '%s', but cannot return value (implementation limitation).", s.ID, key)
	return nil, true // Indicate key *presence* but value unavailable
}

// Put inserts or updates a value in the shard's SMT.
func (s *Shard) Put(key string, value []byte) error {
	s.mutex.Lock() // SMT methods are internally locked, but lock here protects tree pointer swap if needed later
	defer s.mutex.Unlock()

	err := s.tree.Update([]byte(key), value) // Use SMT Update
	if err != nil {
		utils.ErrorLogger.Printf("Shard %d: Failed SMT Update for key '%s': %v", s.ID, key, err)
		return fmt.Errorf("SMT update failed: %w", err)
	}
	// utils.DebugLogger.Printf("Shard %d: SMT Put key '%s', new root %x", s.ID, key, s.tree.Root()[:4])
	return nil
}

// Delete removes a key from the shard's SMT by setting its value to nil.
func (s *Shard) Delete(key string) error {
	s.mutex.Lock() // SMT methods are internally locked, but lock here protects tree pointer swap if needed later
	defer s.mutex.Unlock()

	err := s.tree.Delete([]byte(key)) // Use SMT Delete (which is Update with nil)
	if err != nil {
		utils.ErrorLogger.Printf("Shard %d: Failed SMT Delete for key '%s': %v", s.ID, key, err)
		return fmt.Errorf("SMT delete failed: %w", err)
	}
	// utils.DebugLogger.Printf("Shard %d: SMT Delete key '%s', new root %x", s.ID, key, s.tree.Root()[:4])
	return nil
}

// GetStateRoot returns the current root hash of the shard's SMT.
func (s *Shard) GetStateRoot() []byte {
	s.mutex.RLock() // SMT methods are internally locked, but lock here protects tree pointer swap if needed later
	defer s.mutex.RUnlock()
	// Return a copy? SMT Root() should already return a safe copy or immutable slice.
	return s.tree.Root()
}

// GetStateData is problematic with SMTs as iterating all *set* keys can be complex.
// Return nil for now, or implement full iteration if needed (complex).
func (s *Shard) GetStateData() map[string][]byte {
    utils.WarnLogger.Printf("Shard %d: GetStateData called, but full state dump is not efficiently supported by simplified SMT. Returning nil.", s.ID)
	// TODO: Implement SMT iteration if required for state sync simulation.
    // This would likely involve traversing the tree and collecting non-empty leaves.
	return nil
}

// SetStateAndRecalculate clears the current SMT and rebuilds it from the provided map.
// Used for state sync simulation or testing.
func (s *Shard) SetStateAndRecalculate(newState map[string][]byte) error {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    // Create a new empty tree
    s.tree = utils.NewSMT()

    // Insert all key-value pairs from the newState map
    // Sort keys for potentially more deterministic insertion order (though SMT should handle any order)
    // keys := make([]string, 0, len(newState))
    // for k := range newState { keys = append(keys, k) }
    // sort.Strings(keys)
    // for _, k := range keys { ... }

    // Insert without sorting (SMT handles path)
    count := 0
    for k, v := range newState {
        err := s.tree.Update([]byte(k), v) // Use SMT Update
        if err != nil {
             utils.ErrorLogger.Printf("Shard %d: Failed SMT Update during SetStateAndRecalculate for key '%s': %v", s.ID, k, err)
             // Continue processing others? Or return error immediately? Let's return error.
             return fmt.Errorf("failed rebuilding SMT state for key %s: %w", k, err)
        }
        count++
    }

    utils.DebugLogger.Printf("Shard %d: Rebuilt SMT state from map (%d items). New root: %x", s.ID, count, s.tree.Root())
    return nil
}

// Remove internal recalculateMerkleRoot as SMT handles updates internally.
// func (s *Shard) recalculateMerkleRoot() { ... } // REMOVED