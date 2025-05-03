package consensus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"blockchain/core"
	"blockchain/crypto"
	"blockchain/utils"
)

// --- BFT Threshold Constants ---
const validatorsN = 4
const faultyF = (validatorsN - 1) / 3
const quorumQ = 2*faultyF + 1


// SimplePoA uses simulated VRF and Threshold Signatures.
type SimplePoA struct {
	Validators  []string
	NodeWallet  *crypto.Wallet
	genesisHash []byte
	n           int
	f           int
	quorum      int
}

// NewSimplePoA initializes the PoA engine with threshold parameters.
func NewSimplePoA(validators []string, nodeWallet *crypto.Wallet, genesisBlock *core.Block) (*SimplePoA, error) {
	if nodeWallet == nil || nodeWallet.PrivateKey == nil { return nil, fmt.Errorf("node wallet cannot be nil or lack private key") }
	// Allow initializing with zero validators for testing/flexibility, but quorum will be 0.
	// if len(validators) == 0 { utils.WarnLogger.Println("Initializing SimplePoA with zero validators.") }
	if genesisBlock == nil { return nil, fmt.Errorf("genesis block cannot be nil") }

	nActual := len(validators)
    fActual := 0
    qActual := 0
    if nActual > 0 {
        if nActual < 4 {
             utils.WarnLogger.Printf("SimplePoA Warning: Configured with %d validators, need at least 4 for f=1 BFT threshold. Quorum calculations might be insufficient for guarantees.", nActual)
        }
        fActual = (nActual - 1) / 3 // Integer division gives floor
        qActual = 2*fActual + 1
    } else {
         utils.WarnLogger.Println("SimplePoA Warning: Initialized with zero validators, quorum set to 0.")
    }

    // --- REMOVED the check and warning about nodeWallet not being in the list ---
	// isValidator := false; for _, v := range validators { if v == nodeWallet.Address { isValidator = true; break } }
	// if !isValidator && nActual > 0 {
	//     // REMOVED: utils.WarnLogger.Printf("Node %s is not in the validator set.", nodeWallet.Address)
    // }
    // --- End Removal ---

	poa := &SimplePoA{
        Validators: validators, NodeWallet: nodeWallet, genesisHash: genesisBlock.Hash,
        n: nActual, f: fActual, quorum: qActual,
    }
	return poa, nil
}

// getVRFInputSeed generates a deterministic seed for VRF evaluation.
func (poa *SimplePoA) getVRFInputSeed(lastBlock *core.Block, height uint64) []byte {
    heightBytes := make([]byte, 8); binary.BigEndian.PutUint64(heightBytes, height)
    var seedData []byte
    if lastBlock == nil { // Only for height 1
        if height == 1 { seedData = append(poa.genesisHash, heightBytes...) } else { utils.ErrorLogger.Panicf("getVRFInputSeed called with nil lastBlock for height %d > 1", height); return nil }
    } else { seedData = append(lastBlock.Hash, heightBytes...) }
	return utils.CalculateHash(seedData)
}


// Propose uses VRF, creates block, collects threshold signatures.
func (poa *SimplePoA) Propose(transactions core.TxList, lastBlock *core.Block, stateRoot []byte, validatorWallet *crypto.Wallet) (*core.Block, error) {
    if len(poa.Validators) == 0 { return nil, fmt.Errorf("cannot propose: no validators defined") }
	if poa.quorum == 0 { return nil, fmt.Errorf("cannot propose: quorum is zero") }
	if validatorWallet.Address != poa.NodeWallet.Address { return nil, fmt.Errorf("propose called with incorrect validator wallet") }

    var nextHeight uint64 = 1; var prevHash []byte = poa.genesisHash
	if lastBlock != nil { nextHeight = lastBlock.Header.Height + 1; prevHash = lastBlock.Hash }
	vrfInput := poa.getVRFInputSeed(lastBlock, nextHeight)

	// --- VRF Leader Election ---
	var lowestOutput []byte = nil; var leaderAddress string = ""; var leaderProof []byte = nil
	for _, validatorAddr := range poa.Validators {
        valWallet := crypto.GetWallet(validatorAddr)
        if valWallet == nil || valWallet.PrivateKey == nil { utils.ErrorLogger.Printf("[VRF Propose H:%d] Wallet/Key missing for validator %s. Skipping.", nextHeight, validatorAddr); continue }
		output, proof, err := crypto.EvaluateVRF(valWallet.PrivateKey, vrfInput)
		if err != nil { utils.ErrorLogger.Printf("[VRF Propose H:%d] VRF eval failed for %s: %v", nextHeight, validatorAddr, err); continue }
		if leaderAddress == "" || bytes.Compare(output, lowestOutput) < 0 { lowestOutput = output; leaderAddress = validatorAddr; leaderProof = proof }
	}
    if leaderAddress == "" { return nil, fmt.Errorf("failed to determine VRF leader for height %d", nextHeight) }
	utils.DebugLogger.Printf("[VRF Propose H:%d] Leader determined: %s (Output: %x...)", nextHeight, leaderAddress, lowestOutput[:4])
	if poa.NodeWallet.Address != leaderAddress { return nil, fmt.Errorf("not validator's turn (VRF Leader: %s)", leaderAddress) }

	// --- We are the Leader ---
	myOutput := lowestOutput; myProof := leaderProof

	// 1. Create Unsigned Block Structure
	newBlock := core.NewBlock(nextHeight, prevHash, stateRoot, transactions, poa.NodeWallet.Address)
    if newBlock == nil { return nil, fmt.Errorf("failed to create new block instance") }
    newBlock.Header.VrfOutput = myOutput; newBlock.Header.VrfProof = myProof
    newBlock.Hash = newBlock.CalculateHash() // Calculate hash based on header WITH VRF info

	// 2. Simulate Signature Collection
	utils.DebugLogger.Printf("[%s H:%d] Collecting signatures for block %x...", poa.NodeWallet.Address, nextHeight, newBlock.Hash[:4])
	collectedSignatures := make(map[string][]byte); validSigners := 0
	for _, validatorAddr := range poa.Validators {
		valWallet := crypto.GetWallet(validatorAddr)
		if valWallet == nil || valWallet.PrivateKey == nil { utils.WarnLogger.Printf("[%s H:%d] Skipping signature from %s: Cannot find wallet/key.", poa.NodeWallet.Address, nextHeight, validatorAddr); continue }
		if !newBlock.VerifyStructure() { utils.WarnLogger.Printf("[%s H:%d] Validator %s found invalid structure, not signing.", poa.NodeWallet.Address, nextHeight, validatorAddr); continue }
		sig, err := valWallet.PrivateKey.Sign(newBlock.Hash)
		if err != nil { utils.ErrorLogger.Printf("[%s H:%d] Failed to get signature from %s: %v", poa.NodeWallet.Address, nextHeight, validatorAddr, err); continue }
		collectedSignatures[validatorAddr] = sig; validSigners++
		utils.DebugLogger.Printf("[%s H:%d] Collected signature from %s (%d/%d)", poa.NodeWallet.Address, nextHeight, validatorAddr, validSigners, poa.quorum)
	}

	// 3. Check if Quorum Reached
	if validSigners < poa.quorum { return nil, fmt.Errorf("failed to collect quorum (%d/%d) signatures for block %d", validSigners, poa.quorum, nextHeight) }

	// 4. Add Signatures to Block
	newBlock.Signatures = collectedSignatures

	utils.InfoLogger.Printf("[%s] Proposing Block %d (%x) as VRF Leader with %d signatures", poa.NodeWallet.Address, newBlock.Header.Height, newBlock.Hash, len(newBlock.Signatures))
	return newBlock, nil
}

// Validate checks VRF proof and Threshold Signatures.
func (poa *SimplePoA) Validate(block *core.Block, lastBlock *core.Block) error {
	if block == nil { return fmt.Errorf("cannot validate nil block") }
	if block.Header.Height == 0 && bytes.Equal(block.Hash, poa.genesisHash) { return nil } // Allow genesis
	if lastBlock == nil && block.Header.Height != 1 { return fmt.Errorf("last block cannot be nil for validating non-genesis block %d", block.Header.Height)}
	if lastBlock != nil && block.Header.Height != lastBlock.Header.Height+1 { return fmt.Errorf("block height mismatch") }
	if block.Hash == nil { return fmt.Errorf("block hash is nil") }

	// 1. VRF Verification
	if block.Header.Proposer == "" { return fmt.Errorf("block proposer is empty") }
	if block.Header.VrfOutput == nil || block.Header.VrfProof == nil { return fmt.Errorf("block is missing VRF output or proof") }
	proposerWallet := crypto.GetWallet(block.Header.Proposer); if proposerWallet == nil || proposerWallet.PublicKey == nil { return fmt.Errorf("cannot get public key for block proposer %s", block.Header.Proposer) }
	vrfInput := poa.getVRFInputSeed(lastBlock, block.Header.Height)
	isValidProof := crypto.VerifyVRF(proposerWallet.PublicKey, vrfInput, block.Header.VrfOutput, block.Header.VrfProof)
	if !isValidProof { return fmt.Errorf("invalid VRF proof for proposer %s and block %d", block.Header.Proposer, block.Header.Height) }
	utils.DebugLogger.Printf("Block %d VRF proof validated for proposer %s.", block.Header.Height, block.Header.Proposer)

	// 2. Threshold Signature Verification
	if block.Signatures == nil { return fmt.Errorf("block has nil Signatures map") }
	// Use the quorum calculated during initialization (poa.quorum)
	if len(block.Signatures) < poa.quorum { return fmt.Errorf("insufficient signatures: got %d, require %d", len(block.Signatures), poa.quorum) }

	validSignatureCount := 0; seenSigners := make(map[string]bool)
	for validatorAddr, signature := range block.Signatures {
		if seenSigners[validatorAddr] { return fmt.Errorf("duplicate signature from validator %s", validatorAddr) }
		isCurrentValidator := false; for _, v := range poa.Validators { if v == validatorAddr { isCurrentValidator = true; break } }
		if !isCurrentValidator { return fmt.Errorf("signature from non-validator %s", validatorAddr) }
		signerWallet := crypto.GetWallet(validatorAddr); if signerWallet == nil || signerWallet.PublicKey == nil { return fmt.Errorf("cannot get public key for signer %s", validatorAddr) }
		if !signerWallet.PublicKey.Verify(block.Hash, signature) { return fmt.Errorf("invalid signature from validator %s", validatorAddr) }
		validSignatureCount++; seenSigners[validatorAddr] = true
		utils.DebugLogger.Printf("Block %d Sig %d/%d verified from %s", block.Header.Height, validSignatureCount, poa.quorum, validatorAddr)
	}
	// Use poa.quorum for the check
	if validSignatureCount < poa.quorum { return fmt.Errorf("insufficient valid unique signatures: got %d, require %d", validSignatureCount, poa.quorum) }
	utils.DebugLogger.Printf("Block %d Threshold Signature (%d/%d) validation passed.", block.Header.Height, validSignatureCount, poa.quorum)

	// 3. Timestamp Validation
    var prevTimestamp int64 = 0; if lastBlock != nil { prevTimestamp = lastBlock.Header.Timestamp }
	if block.Header.Timestamp <= prevTimestamp { return fmt.Errorf("block %d timestamp (%d) not after previous (%d)", block.Header.Height, block.Header.Timestamp, prevTimestamp) }
    maxSkew := 10 * time.Second; currentTime := time.Now().UnixNano()
    if block.Header.Timestamp > currentTime + maxSkew.Nanoseconds() { return fmt.Errorf("block %d timestamp (%d) is too far in the future", block.Header.Height, block.Header.Timestamp) }

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
    return "Simple PoA (Simulated VRF + Threshold Sig)"
}