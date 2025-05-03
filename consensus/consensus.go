package consensus

import (
	"blockchain/core"   // Updated import path
	"blockchain/crypto" // Updated import path
)

// ConsensusEngine defines the interface for consensus algorithms.
type ConsensusEngine interface {
	// Propose creates a new block proposal if the conditions are met (e.g., it's the node's turn).
	// It needs access to pending transactions and the current chain state (last block, state root).
	// The stateRoot passed should be the one calculated *after* applying the proposed transactions.
	// Returns the proposed block (signed by the validator) or an error (e.g., not turn, validation failed).
	Propose(transactions core.TxList, lastBlock *core.Block, stateRoot []byte, validatorWallet *crypto.Wallet) (*core.Block, error)

	// Validate checks if a received block is valid according to consensus rules.
	// This complements the basic structural/signature checks in core.Block.
	// It typically involves checking proposer rights based on the last block or height,
	// voting thresholds (for BFT), difficulty (for PoW), etc.
	Validate(block *core.Block, lastBlock *core.Block) error

	// GetCurrentValidators returns the list of active validator addresses/IDs.
	// In dynamic systems (not this simplified PoA), this might change over time based on staking/voting.
	GetCurrentValidators() []string

    // Name returns the name of the consensus engine.
    Name() string
}