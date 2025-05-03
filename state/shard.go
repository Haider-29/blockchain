package state

import (
	"bytes"
	// "encoding/gob" // Not used directly here anymore
	"fmt"
	"sync"

	"blockchain/utils"
)

const NUM_SHARDS uint32 = 4

type Shard struct {
	ID    uint32
	tree  *utils.SMT
	mutex sync.RWMutex
}

// NewShard creates a new, empty shard with an initialized SMT.
func NewShard(id uint32) *Shard {
	s := &Shard{
		ID:   id,
		tree: utils.NewSMT(),
	}
	utils.DebugLogger.Printf("Shard %d initialized with SMT root: %x", id, s.tree.Root())
	return s // Returns *Shard
}

// Copy creates a new Shard instance with a distinct copy of the SMT.
// Uses SMT's Copy method.
func (s *Shard) Copy() (*Shard, error) {
	s.mutex.RLock()
	originalTree := s.tree
	s.mutex.RUnlock()
	if originalTree == nil { return nil, fmt.Errorf("cannot copy shard %d with nil SMT", s.ID) }

	copiedTree := originalTree.Copy() // SMT Copy handles deep copy
	if copiedTree == nil { return nil, fmt.Errorf("failed to copy SMT for shard %d (returned nil)", s.ID) }

	newShard := &Shard{ ID: s.ID, tree: copiedTree } // Create new shard wrapper

	// Optional: Verify root hash consistency after copy
	if !bytes.Equal(originalTree.Root(), newShard.tree.Root()) {
		 utils.ErrorLogger.Printf("Shard %d: Root hash mismatch after SMT copy! Original: %x, Copy: %x", s.ID, originalTree.Root(), newShard.tree.Root())
		 return nil, fmt.Errorf("SMT copy failed root verification for shard %d", s.ID) // Fail on mismatch
	}

	utils.DebugLogger.Printf("Shard %d copied using SMT Copy.", s.ID)
	return newShard, nil // Returns *Shard, error
}

// Get retrieves a value from the shard using the SMT's Get method.
func (s *Shard) Get(key string) ([]byte, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if s.tree == nil { return nil, false } // Handle nil tree case
	value, err := s.tree.Get([]byte(key))
	if err == utils.ErrKeyNotFound { return nil, false } // Not found
	if err != nil { utils.ErrorLogger.Printf("Shard %d: Error during SMT Get for key '%s': %v", s.ID, key, err); return nil, false } // Other error
	// Key exists, return the value (which might be nil if deleted) and true
	return value, true
}

// Put inserts or updates a value in the shard's SMT.
func (s *Shard) Put(key string, value []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.tree == nil { return fmt.Errorf("cannot Put on nil SMT tree for shard %d", s.ID) }
	err := s.tree.Update([]byte(key), value)
	if err != nil {
		utils.ErrorLogger.Printf("Shard %d: Failed SMT Update for key '%s': %v", s.ID, key, err)
		return fmt.Errorf("SMT update failed: %w", err)
	}
	return nil // Returns error
}

// Delete removes a key from the shard's SMT.
func (s *Shard) Delete(key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.tree == nil { return fmt.Errorf("cannot Delete on nil SMT tree for shard %d", s.ID) }
	err := s.tree.Delete([]byte(key))
	if err != nil {
		utils.ErrorLogger.Printf("Shard %d: Failed SMT Delete for key '%s': %v", s.ID, key, err)
		return fmt.Errorf("SMT delete failed: %w", err)
	}
	return nil // Returns error
}

// GetStateRoot returns the current root hash of the shard's SMT.
func (s *Shard) GetStateRoot() []byte {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if s.tree == nil { return utils.CalculateHash([]byte{}) } // Return empty hash if tree is nil
	return s.tree.Root() // Returns []byte
}

// GetStateData remains problematic / TODO...
func (s *Shard) GetStateData() map[string][]byte {
	utils.WarnLogger.Printf("Shard %d: GetStateData called, but full state dump is not efficiently supported by simplified SMT. Returning nil.", s.ID)
	return nil // Returns map[string][]byte (nil in this case)
}

// SetStateAndRecalculate clears the current SMT and rebuilds it from the provided map.
func (s *Shard) SetStateAndRecalculate(newState map[string][]byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.tree = utils.NewSMT() // Create a new empty tree
	count := 0
	for k, v := range newState {
		err := s.tree.Update([]byte(k), v)
		if err != nil {
			utils.ErrorLogger.Printf("Shard %d: Failed SMT Update during SetStateAndRecalculate for key '%s': %v", s.ID, k, err)
			return fmt.Errorf("failed rebuilding SMT state for key %s: %w", k, err) // Returns error
		}
		count++
	}
	utils.DebugLogger.Printf("Shard %d: Rebuilt SMT state from map (%d items). New root: %x", s.ID, count, s.tree.Root())
	return nil // Returns error (nil on success)
}