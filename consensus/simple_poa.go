package consensus

import (
	"fmt"
	"time"

	"blockchain/core"   // Updated import path
	"blockchain/crypto" // Updated import path
	"blockchain/utils"  // Updated import path
    "bytes" // Needed for comparing genesis hash
)

// SimplePoA implements a basic Proof-of-Authority consensus.
// Authority set is fixed at creation. Leader rotates round-robin based on block height.
type SimplePoA struct {
	Validators []string // List of authorized validator addresses (ordered list matters for rotation)
	NodeWallet *crypto.Wallet // Wallet of the node running this engine instance
    genesisHash []byte // Store genesis hash to allow skipping validation for it
}

// NewSimplePoA creates a new PoA engine.
func NewSimplePoA(validators []string, nodeWallet *crypto.Wallet, genesisBlock *core.Block) (*SimplePoA, error) {
	if nodeWallet == nil || nodeWallet.PrivateKey == nil {
         // ErrorLogger might not be initialized yet if called very early. Return error instead.
         // utils.ErrorLogger.Panic("Node wallet cannot be nil or lack private key for SimplePoA consensus")
         return nil, fmt.Errorf("node wallet cannot be nil or lack private key for SimplePoA consensus")
	}
    if len(validators) == 0 {
        // Allow running without validators? Might be useful for single-node testing.
        utils.WarnLogger.Println("Initializing SimplePoA with zero validators.")
        // return nil, fmt.Errorf("validator list cannot be empty for SimplePoA")
    }
    if genesisBlock == nil {
        return nil, fmt.Errorf("genesis block cannot be nil for SimplePoA initialization")
    }

	// Check if the node running this engine is actually in the validator set
    isValidator := false
    for _, v := range validators {
        if v == nodeWallet.Address {
            isValidator = true
            break
        }
    }
    if !isValidator && len(validators) > 0 { // Only warn if validators exist but we're not one
         utils.WarnLogger.Printf("Node %s is not in the validator set for SimplePoA.", nodeWallet.Address)
    }

	return &SimplePoA{
		Validators: validators,
		NodeWallet: nodeWallet,
        genesisHash: genesisBlock.Hash,
	}, nil
}

// Propose creates a new block if it's this node's turn based on height.
// stateRoot is the expected root *after* applying the transactions.
func (poa *SimplePoA) Propose(transactions core.TxList, lastBlock *core.Block, stateRoot []byte, validatorWallet *crypto.Wallet) (*core.Block, error) {
    if len(poa.Validators) == 0 {
        return nil, fmt.Errorf("cannot propose block: no validators defined")
    }
    if validatorWallet == nil || validatorWallet.PrivateKey == nil {
        return nil, fmt.Errorf("propose called with invalid validator wallet")
    }
	if validatorWallet.Address != poa.NodeWallet.Address {
		 return nil, fmt.Errorf("propose called with wallet (%s) different from engine's node wallet (%s)", validatorWallet.Address, poa.NodeWallet.Address)
	}
    if lastBlock == nil {
        return nil, fmt.Errorf("last block cannot be nil for proposing")
    }

	// Determine the expected proposer for the *next* block height
    nextHeight := lastBlock.Header.Height + 1
	expectedProposerIndex := int(nextHeight) % len(poa.Validators)
    expectedProposer := poa.Validators[expectedProposerIndex]

	// Check if it's our turn
	if poa.NodeWallet.Address != expectedProposer {
		// utils.DebugLogger.Printf("Not my turn to propose height %d. Expected: %s, Me: %s", nextHeight, expectedProposer, poa.NodeWallet.Address)
		return nil, fmt.Errorf("not validator's turn to propose height %d (expected %s)", nextHeight, expectedProposer)
	}

	// Create the new block with the provided state root
	newBlock := core.NewBlock(
		nextHeight,
		lastBlock.Hash,
		stateRoot, // Use the pre-calculated state root after applying txs
		transactions,
		poa.NodeWallet.Address, // Proposer is this node
	)
    if newBlock == nil {
        return nil, fmt.Errorf("failed to create new block instance")
    }

	// Sign the block (block hash is calculated within NewBlock)
	err := newBlock.Sign(poa.NodeWallet)
	if err != nil {
		utils.ErrorLogger.Printf("Failed to sign proposed block %d: %v", newBlock.Header.Height, err)
		return nil, fmt.Errorf("failed to sign block: %w", err)
	}

	utils.InfoLogger.Printf("[%s] Proposing Block %d (%x)", poa.NodeWallet.Address, newBlock.Header.Height, newBlock.Hash)

	return newBlock, nil
}

// Validate checks if the block was proposed by the correct validator for its height
// and satisfies other PoA rules (like timestamp).
func (poa *SimplePoA) Validate(block *core.Block, lastBlock *core.Block) error {
    if block == nil {
        return fmt.Errorf("cannot validate nil block")
    }
    // Allow genesis block without strict validation against proposer list/last block
    if block.Header.Height == 0 && bytes.Equal(block.Hash, poa.genesisHash) {
        utils.DebugLogger.Printf("Skipping PoA proposer/timestamp validation for Genesis block %x", block.Hash)
        return nil
    }

    // If not genesis, lastBlock must be provided
    if lastBlock == nil {
         return fmt.Errorf("last block cannot be nil for validating non-genesis block %d", block.Header.Height)
    }

    // Check height sequencing relative to lastBlock
    if block.Header.Height != lastBlock.Header.Height + 1 {
        return fmt.Errorf("block height %d does not follow last block height %d", block.Header.Height, lastBlock.Header.Height)
    }

    // --- Proposer Validation ---
	if len(poa.Validators) == 0 {
        if block.Header.Validator != "" { // Allow empty validator if no validators are set? Risky.
            return fmt.Errorf("block %d has validator %s but no validators are configured", block.Header.Height, block.Header.Validator)
        }
        // If no validators, maybe anyone can propose? Or no blocks allowed?
        utils.WarnLogger.Printf("Validating block %d with no PoA validators configured.", block.Header.Height)
        // Skip proposer check if validator list is empty for now.
	} else {
        // Determine expected proposer based on the block's height
        expectedProposerIndex := int(block.Header.Height) % len(poa.Validators)
        expectedProposer := poa.Validators[expectedProposerIndex]

        if block.Header.Validator != expectedProposer {
            return fmt.Errorf("invalid proposer for block %d: expected %s, got %s",
                block.Header.Height, expectedProposer, block.Header.Validator)
        }
    }


	// --- Timestamp Validation ---
	if block.Header.Timestamp <= lastBlock.Header.Timestamp {
		 return fmt.Errorf("block %d timestamp (%d) not after previous block %d (%d)", block.Header.Height, block.Header.Timestamp, lastBlock.Header.Height, lastBlock.Header.Timestamp)
	}
    // Check against current time (allow some clock skew, e.g., 10 seconds)
    maxSkew := 10 * time.Second
    currentTime := time.Now().UnixNano()
    if block.Header.Timestamp > currentTime + maxSkew.Nanoseconds() {
         return fmt.Errorf("block %d timestamp (%d) is too far in the future (current: %d)", block.Header.Height, block.Header.Timestamp, currentTime)
    }
    // Optional: Check if timestamp is not too far in the past? Might reject valid blocks during sync.
    // minTime := currentTime - (60 * time.Second).Nanoseconds() // e.g., reject blocks older than 1 min?
    // if block.Header.Timestamp < minTime { ... }


	// utils.DebugLogger.Printf("Block %d PoA validation passed (Proposer: %s)", block.Header.Height, block.Header.Validator)
	return nil // PoA validation passed
}

// GetCurrentValidators returns the fixed list of validators.
func (poa *SimplePoA) GetCurrentValidators() []string {
	// Return a copy to prevent external modification
	validatorsCopy := make([]string, len(poa.Validators))
	copy(validatorsCopy, poa.Validators)
	return validatorsCopy
}

// Name returns the name of the consensus engine.
func (poa *SimplePoA) Name() string {
    return "Simple Proof-of-Authority (Round-Robin)"
}