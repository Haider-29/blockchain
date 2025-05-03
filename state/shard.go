package state

import (
	"bytes"
	"encoding/gob"
	"sort"
	"sync"

	"blockchain/utils"
)

// NUM_SHARDS constant remains the same...
const NUM_SHARDS uint32 = 4

// Shard struct remains the same...
type Shard struct {
	ID         uint32
	State      map[string][]byte
	MerkleRoot []byte
	mutex      sync.RWMutex
}

// NewShard remains the same...
func NewShard(id uint32) *Shard {
	s := &Shard{
		ID:    id,
		State: make(map[string][]byte),
	}
	s.recalculateMerkleRoot()
	return s
}

// Get remains the same...
func (s *Shard) Get(key string) ([]byte, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	value, ok := s.State[key]
	if ok {
		valCopy := make([]byte, len(value))
		copy(valCopy, value)
		return valCopy, true
	}
	return nil, false
}

// Put remains the same...
func (s *Shard) Put(key string, value []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
    valueCopy := make([]byte, len(value))
    copy(valueCopy, value)
	s.State[key] = valueCopy
	s.recalculateMerkleRoot() // Internal call ok
}

// Delete remains the same...
func (s *Shard) Delete(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, exists := s.State[key]
    if exists {
        delete(s.State, key)
        s.recalculateMerkleRoot() // Internal call ok
    }
}

// recalculateMerkleRoot remains unexported (internal detail)
func (s *Shard) recalculateMerkleRoot() {
	// ... implementation remains the same ...
	if len(s.State) == 0 { s.MerkleRoot = utils.CalculateHash([]byte{}); return }
	keys := make([]string, 0, len(s.State))
	for k := range s.State { keys = append(keys, k) }
	sort.Strings(keys)
	var dataToHash [][]byte
	var kvBuf bytes.Buffer
	encoder := gob.NewEncoder(&kvBuf)
	for _, k := range keys {
		v := s.State[k]
		kvBuf.Reset()
		err := encoder.Encode(k); if err != nil { utils.ErrorLogger.Panicf("Shard %d: Failed encode key '%s': %v", s.ID, k, err); continue }
		err = encoder.Encode(v); if err != nil { utils.ErrorLogger.Panicf("Shard %d: Failed encode value for key '%s': %v", s.ID, k, err); continue }
		dataToHash = append(dataToHash, utils.CalculateHash(kvBuf.Bytes()))
	}
	merkleTree := utils.NewMerkleTree(dataToHash)
    if merkleTree != nil { s.MerkleRoot = merkleTree.Hash } else { s.MerkleRoot = utils.CalculateHash([]byte{}) }
}

// GetStateRoot remains the same...
func (s *Shard) GetStateRoot() []byte {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	rootCopy := make([]byte, len(s.MerkleRoot))
	copy(rootCopy, s.MerkleRoot)
	return rootCopy
}

// GetStateData remains the same...
func (s *Shard) GetStateData() map[string][]byte {
    s.mutex.RLock()
    defer s.mutex.RUnlock()
    stateCopy := make(map[string][]byte, len(s.State))
    for k, v := range s.State {
        valCopy := make([]byte, len(v))
        copy(valCopy, v)
        stateCopy[k] = valCopy
    }
    return stateCopy
}

// SetStateAndRecalculate (NEW EXPORTED METHOD)
// This method is primarily for testing or state synchronization/simulation scenarios
// where the entire state of a shard needs to be replaced and the root recalculated.
func (s *Shard) SetStateAndRecalculate(newState map[string][]byte) {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    // Replace the internal state map. The input map should ideally be a deep copy
    // if the caller might modify it later, but GetStateData already returns copies.
    s.State = newState
    // Trigger internal recalculation based on the new state.
    s.recalculateMerkleRoot() // Call the unexported method
    utils.DebugLogger.Printf("Shard %d: Set new state (%d items) and recalculated root: %x", s.ID, len(s.State), s.MerkleRoot)
}