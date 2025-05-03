package consensus

import (
	"bytes"
	"encoding/binary" // Needed for comparing VRF outputs as numbers and generating seed
	"fmt"
	"time"

	"blockchain/core"
	"blockchain/crypto" // Needs crypto package for keys and VRF calls
	"blockchain/utils"
)

// SimplePoA now uses simulated VRF for leader election instead of round-robin.
type SimplePoA struct {
	Validators  []string        // List of authorized validator addresses (order might matter for tie-breaking)
	NodeWallet  *crypto.Wallet  // Wallet of the node running this instance
	genesisHash []byte
}

// NewSimplePoA initializes the PoA engine.
func NewSimplePoA(validators []string, nodeWallet *crypto.Wallet, genesisBlock *core.Block) (*SimplePoA, error) {
	if nodeWallet == nil || nodeWallet.PrivateKey == nil { return nil, fmt.Errorf("node wallet cannot be nil or lack private key") }
	if len(validators) == 0 { utils.WarnLogger.Println("Initializing SimplePoA with zero validators.") }
	if genesisBlock == nil { return nil, fmt.Errorf("genesis block cannot be nil") }
	isValidator := false; for _, v := range validators { if v == nodeWallet.Address { isValidator = true; break } }; if !isValidator && len(validators) > 0 { utils.WarnLogger.Printf("Node %s is not in the validator set.", nodeWallet.Address) }
	return &SimplePoA{ Validators: validators, NodeWallet: nodeWallet, genesisHash: genesisBlock.Hash }, nil
}

// getVRFInputSeed generates a deterministic seed for VRF evaluation for a given block height.
func (poa *SimplePoA) getVRFInputSeed(lastBlock *core.Block, height uint64) []byte {
    if lastBlock == nil { // Should only happen for height 1, use genesis hash
        if height == 1 {
             heightBytes := make([]byte, 8)
             binary.BigEndian.PutUint64(heightBytes, height)
             seedData := append(poa.genesisHash, heightBytes...) // Use genesis hash for first block VRF seed
	         return utils.CalculateHash(seedData)
        }
        // This case should not be reached if lastBlock logic is correct elsewhere
         utils.ErrorLogger.Panicf("getVRFInputSeed called with nil lastBlock for height %d > 1", height)
         return nil
    }
    heightBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(heightBytes, height)
    seedData := append(lastBlock.Hash, heightBytes...)
	return utils.CalculateHash(seedData) // H(prevHash || height)
}


// Propose uses VRF to determine leader and create block.
func (poa *SimplePoA) Propose(transactions core.TxList, lastBlock *core.Block, stateRoot []byte, validatorWallet *crypto.Wallet) (*core.Block, error) {
    if len(poa.Validators) == 0 { return nil, fmt.Errorf("cannot propose: no validators defined") }
	if validatorWallet.Address != poa.NodeWallet.Address { return nil, fmt.Errorf("propose called with incorrect validator wallet") }
	// lastBlock can be nil only when proposing height 1 after genesis
    if lastBlock == nil && len(poa.Validators) > 0 && validatorWallet.Address != poa.Validators[1 % len(poa.Validators)] {
        // Special handling for first block proposal if needed, or rely on VRF seed using genesis
        // Let's assume VRF works even for height 1 using genesis hash as seed base
    }
     if lastBlock == nil && validatorWallet.Address == "" { // Cannot determine height without lastBlock
         return nil, fmt.Errorf("last block is nil, cannot determine proposal height")
     }

    var nextHeight uint64
    if lastBlock != nil {
        nextHeight = lastBlock.Header.Height + 1
    } else {
        nextHeight = 1 // Proposing the first block after genesis
    }

	vrfInput := poa.getVRFInputSeed(lastBlock, nextHeight)

	// --- VRF Leader Election Simulation ---
	var lowestOutput []byte = nil
	var leaderAddress string = ""
    var leaderProof []byte = nil // Proof corresponding to the lowest output found

	for _, validatorAddr := range poa.Validators {
        valWallet := crypto.GetWallet(validatorAddr) // Assumes access to wallet info
        if valWallet == nil || valWallet.PrivateKey == nil {
             utils.ErrorLogger.Printf("[VRF Propose H:%d] Failed to get private key for validator %s. Skipping.", nextHeight, validatorAddr)
             continue
        }

		output, proof, err := crypto.EvaluateVRF(valWallet.PrivateKey, vrfInput)
		if err != nil {
			utils.ErrorLogger.Printf("[VRF Propose H:%d] Failed to evaluate VRF for %s: %v", nextHeight, validatorAddr, err)
			continue
		}

		// Determine leader: lowest VRF output wins
		if leaderAddress == "" || bytes.Compare(output, lowestOutput) < 0 {
			lowestOutput = output
			leaderAddress = validatorAddr
            leaderProof = proof
		}
	}

    if leaderAddress == "" {
        return nil, fmt.Errorf("failed to determine VRF leader for height %d", nextHeight)
    }
	utils.DebugLogger.Printf("[VRF Propose H:%d] Leader determined: %s (Output: %x...)", nextHeight, leaderAddress, lowestOutput[:4])

	// Check if *this* node is the elected leader
	if poa.NodeWallet.Address != leaderAddress {
		return nil, fmt.Errorf("not validator's turn (VRF Leader: %s)", leaderAddress)
	}

	// --- We are the Leader ---
    // Use the output/proof we determined belong to us (the lowest)
    myOutput := lowestOutput
    myProof := leaderProof

	// Create the block *without* signature first
	prevHash := poa.genesisHash // Default for block 1
    if lastBlock != nil {
        prevHash = lastBlock.Hash
    }
	newBlock := core.NewBlock(nextHeight, prevHash, stateRoot, transactions, poa.NodeWallet.Address)
    if newBlock == nil { return nil, fmt.Errorf("failed to create new block instance") }

    // Add VRF details to header
    newBlock.Header.VrfOutput = myOutput
    newBlock.Header.VrfProof = myProof

    // Calculate the FINAL block hash *after* all header fields are set
    newBlock.Hash = newBlock.CalculateHash()

	// Sign the final block hash
	err := newBlock.Sign(poa.NodeWallet)
	if err != nil { return nil, fmt.Errorf("failed to sign block: %w", err) }

	utils.InfoLogger.Printf("[%s] Proposing Block %d (%x) as VRF Leader", poa.NodeWallet.Address, newBlock.Header.Height, newBlock.Hash)
	return newBlock, nil
}

// Validate checks block proposer using VRF verification.
func (poa *SimplePoA) Validate(block *core.Block, lastBlock *core.Block) error {
	if block == nil { return fmt.Errorf("cannot validate nil block") }
	// Allow genesis block without VRF check
    if block.Header.Height == 0 && bytes.Equal(block.Hash, poa.genesisHash) { return nil }
    // Need lastBlock for VRF input seed calculation (except maybe block 1?)
	if lastBlock == nil && block.Header.Height != 1 { return fmt.Errorf("last block cannot be nil for validating non-genesis block %d", block.Header.Height)}
	if lastBlock != nil && block.Header.Height != lastBlock.Header.Height+1 { return fmt.Errorf("block height mismatch") }


	// --- VRF Verification ---
	if block.Header.Validator == "" { return fmt.Errorf("block proposer (Validator) is empty") }
	if block.Header.VrfOutput == nil || block.Header.VrfProof == nil { return fmt.Errorf("block is missing VRF output or proof") }

	proposerWallet := crypto.GetWallet(block.Header.Validator)
	if proposerWallet == nil || proposerWallet.PublicKey == nil { return fmt.Errorf("cannot get public key for block proposer %s", block.Header.Validator) }
	proposerPubKey := proposerWallet.PublicKey

	vrfInput := poa.getVRFInputSeed(lastBlock, block.Header.Height) // Pass correct lastBlock (nil if height is 1)

	isValidProof := crypto.VerifyVRF(proposerPubKey, vrfInput, block.Header.VrfOutput, block.Header.VrfProof)
	if !isValidProof { return fmt.Errorf("invalid VRF proof for proposer %s and block %d", block.Header.Validator, block.Header.Height) }

	// --- SIMPLIFICATION: Skip explicit leader ranking check ---
	utils.DebugLogger.Printf("Block %d VRF proof validated for proposer %s.", block.Header.Height, block.Header.Validator)

	// --- Timestamp Validation ---
    // Need careful check for block 1 vs genesis timestamp
    var prevTimestamp int64 = 0 // Default for genesis case check
    if lastBlock != nil {
        prevTimestamp = lastBlock.Header.Timestamp
    } else if block.Header.Height == 1 {
        // Get genesis timestamp somehow - maybe pass genesis block to validate?
        // For now, assume block 1 timestamp > 0 is sufficient check against implicit genesis time
    } else {
         return fmt.Errorf("cannot validate timestamp without previous block context for block %d", block.Header.Height)
    }

	if block.Header.Timestamp <= prevTimestamp { return fmt.Errorf("block %d timestamp (%d) not after previous block/genesis (%d)", block.Header.Height, block.Header.Timestamp, prevTimestamp) }
    maxSkew := 10 * time.Second; currentTime := time.Now().UnixNano()
    if block.Header.Timestamp > currentTime + maxSkew.Nanoseconds() { return fmt.Errorf("block %d timestamp (%d) is too far in the future (current: %d)", block.Header.Height, block.Header.Timestamp, currentTime) }

	return nil
}

// GetCurrentValidators returns the fixed list of validators.
func (poa *SimplePoA) GetCurrentValidators() []string {
	validatorsCopy := make([]string, len(poa.Validators))
	copy(validatorsCopy, poa.Validators)
	return validatorsCopy
}

// Name returns the name of the consensus engine.
func (poa *SimplePoA) Name() string {
    return "Simple Proof-of-Authority (Simulated VRF Leader Election)"
}