package core

// StateManager defines the interface that the Blockchain requires
// for interacting with the underlying state storage and execution layer.
// This breaks the direct import cycle between core and state packages.
type StateManager interface {
	// ApplyBlock applies the transactions in a block to the state.
	// It must be atomic or handle its own rollback on error.
	// It takes a *Block defined within this core package.
	ApplyBlock(block *Block) error

	// CalculateGlobalStateRoot computes the single root hash representing
	// the entire state across all shards after the latest block application.
	CalculateGlobalStateRoot() []byte

	// GetNumShards returns the configured number of shards in the state manager.
	GetNumShards() uint32

	// --- Optional: Add direct state access if needed by Blockchain ---
	// Get retrieves a value for a key directly from the state.
	// Get(key string) ([]byte, bool)

	// Put inserts or updates a value for a key directly in the state.
	// Put(key string, value []byte) error
}