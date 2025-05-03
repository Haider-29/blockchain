package core

// StateManager defines the interface that the Blockchain requires
// for interacting with the underlying state storage and execution layer.
type StateManager interface {
	// ApplyBlock applies the transactions in a block to the state COMMITTED state.
	// It must be atomic or handle its own rollback on error.
	ApplyBlock(block *Block) error

	// CalculateGlobalStateRoot computes the single root hash representing
	// the entire COMMITTED state across all shards.
	CalculateGlobalStateRoot() []byte

	// GetNumShards returns the configured number of shards in the state manager.
	GetNumShards() uint32

	// Get retrieves a value for a key directly from the COMMITTED state.
	Get(key string) ([]byte, bool)

	// SimulateApplyTransactions simulates applying transactions without committing changes.
	// It returns the predicted global state root hash that *would* result
	// if these transactions were applied successfully, or an error if simulation fails
	// (e.g., due to an invalid transaction like a bad nonce during simulation).
	SimulateApplyTransactions(txs []*Transaction) (rootHash []byte, err error)
}