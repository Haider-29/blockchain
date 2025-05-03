package consensus

import (
	"blockchain/core"
	"blockchain/crypto"
)

// ConsensusEngine defines the interface for consensus algorithms.
type ConsensusEngine interface {
	// Propose creates a block proposal if conditions met (e.g., leader election).
	// Includes transactions, uses lastBlock for context, stateRoot is predicted root after txs.
	// Returns signed block or error.
	Propose(transactions core.TxList, lastBlock *core.Block, stateRoot []byte, validatorWallet *crypto.Wallet) (*core.Block, error)

	// Validate checks consensus-specific rules (e.g., leader eligibility, voting).
	Validate(block *core.Block, lastBlock *core.Block) error

	// GetCurrentValidators returns active validator addresses/IDs.
	GetCurrentValidators() []string

	// Name returns the name of the consensus engine.
    Name() string
}