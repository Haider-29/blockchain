package p2p

import (
	"bytes"
	"encoding/gob" // Needed for calculateTentativeStateRoot simulation
	"fmt"
	"time"
    "sync"

	"blockchain/consensus"
	"blockchain/core"
	"blockchain/crypto"
	"blockchain/state"
	"blockchain/utils"
)

// Node represents a participant in the network.
type Node struct {
	ID           string
	Wallet       *crypto.Wallet
	Blockchain   *core.Blockchain
	StateManager *state.StateManager // Keep concrete type for simulation access
	Consensus    consensus.ConsensusEngine
	Broadcaster  NetworkBroadcaster // Use the interface type
	IsValidator  bool
    stopChan     chan struct{}
    wg           sync.WaitGroup
}

// NewNode creates a new network node instance.
func NewNode(
	idPrefix string,
	broadcaster NetworkBroadcaster, // Accept interface
	isValidator bool,
	validators []string,
	genesisBlock *core.Block,
) (*Node, error) {
	// Validate inputs
	if broadcaster == nil { return nil, fmt.Errorf("network broadcaster cannot be nil") }
	if genesisBlock == nil { return nil, fmt.Errorf("genesis block cannot be nil") }

	wallet := crypto.NewWallet()
	nodeID := fmt.Sprintf("%s-%s", idPrefix, wallet.Address[:6])

	stateMgr := state.NewStateManager()
    initialStateRoot := stateMgr.CalculateGlobalStateRoot()
    if !bytes.Equal(genesisBlock.Header.StateRoot, initialStateRoot) {
        return nil, fmt.Errorf("node %s: Genesis block state root (%x) does not match initial state manager root (%x)",
            nodeID, genesisBlock.Header.StateRoot, initialStateRoot)
    }

	bc, err := core.NewBlockchain(stateMgr, genesisBlock, nodeID)
    if err != nil { return nil, fmt.Errorf("failed to create blockchain for node %s: %w", nodeID, err) }

	consensusEngine, err := consensus.NewSimplePoA(validators, wallet, genesisBlock)
    if err != nil { return nil, fmt.Errorf("failed to create consensus engine for node %s: %w", nodeID, err) }

	node := &Node{
		ID:           nodeID,
		Wallet:       wallet,
		Blockchain:   bc,
		StateManager: stateMgr,
		Consensus:    consensusEngine,
		Broadcaster:  broadcaster, // Store the provided broadcaster interface
		IsValidator:  isValidator,
        stopChan:     make(chan struct{}),
	}
	utils.InfoLogger.Printf("Created Node: %s (Validator: %v, Addr: %s)", node.ID, node.IsValidator, node.Wallet.Address)
	return node, nil
}

// AssignValidatorWallet updates node identity for validators.
func (n *Node) AssignValidatorWallet(validatorWallet *crypto.Wallet, validators []string, genesisBlock *core.Block) error {
     if !n.IsValidator { return fmt.Errorf("cannot assign validator wallet to non-validator node %s", n.ID) }; if validatorWallet == nil { return fmt.Errorf("provided validator wallet is nil for node %s", n.ID) }
     oldID := n.ID; n.Wallet = validatorWallet; n.ID = n.Wallet.Address
     newConsensus, err := consensus.NewSimplePoA(validators, n.Wallet, genesisBlock); if err != nil { return fmt.Errorf("failed to re-initialize consensus for node %s with new wallet: %w", n.ID, err) }; n.Consensus = newConsensus
     newBC, err := core.NewBlockchain(n.StateManager, genesisBlock, n.ID); if err != nil { return fmt.Errorf("failed to re-initialize blockchain for node %s with new wallet: %w", n.ID, err) }; n.Blockchain = newBC
     utils.InfoLogger.Printf("Assigned validator wallet %s to node (previously %s)", n.ID, oldID)
     return nil
}

// CreateGenesisBlock creates the first block in the chain.
func CreateGenesisBlock(validators []string) *core.Block {
	txs := core.TxList{}; initialState := state.NewStateManager(); genesisStateRoot := initialState.CalculateGlobalStateRoot(); genesisValidator := "0xGENESIS"; genesisTimestamp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
    genesisBlock := core.NewBlock(0, []byte("genesis_prev_hash"), genesisStateRoot, txs, genesisValidator); genesisBlock.Header.Timestamp = genesisTimestamp; genesisBlock.Hash = genesisBlock.CalculateHash()
    utils.InfoLogger.Printf("Created Genesis Block: Hash %x, StateRoot: %x", genesisBlock.Hash, genesisBlock.Header.StateRoot); return genesisBlock
}

// Start the node's main loop.
func (n *Node) Start(blockTime time.Duration) {
	utils.InfoLogger.Printf("Node %s starting...", n.ID); n.wg.Add(1)
	go func() {
        defer n.wg.Done()
		if n.IsValidator {
			utils.InfoLogger.Printf("Node %s (Validator) starting proposal loop (Block Time: %s)...", n.ID, blockTime); ticker := time.NewTicker(blockTime); defer ticker.Stop()
			for { select { case <-ticker.C: n.tryProposeBlock(); case <-n.stopChan: utils.InfoLogger.Printf("Node %s stopping proposal loop.", n.ID); return } }
		} else {
			utils.InfoLogger.Printf("Node %s (Non-validator) started. Listening for network messages.", n.ID); <-n.stopChan; utils.InfoLogger.Printf("Node %s stopping listener.", n.ID); return
		}
	}()
}

// Stop signals the node to shut down.
func (n *Node) Stop() {
    utils.InfoLogger.Printf("Node %s shutting down...", n.ID)
    select { case <-n.stopChan: default: close(n.stopChan) }; n.wg.Wait(); /* Unregister called by main */ utils.InfoLogger.Printf("Node %s shutdown complete.", n.ID)
}

// tryProposeBlock attempts to create and broadcast a block.
func (n *Node) tryProposeBlock() {
	lastBlock := n.Blockchain.LastBlock(); if lastBlock == nil { utils.WarnLogger.Printf("[%s] Cannot propose: Last block is nil.", n.ID); return }
	pendingTxs := n.Blockchain.GetPendingTransactions(10)
    expectedStateRoot, err := n.calculateTentativeStateRoot(pendingTxs)
    if err != nil { utils.ErrorLogger.Printf("[%s] Failed to calculate tentative state root: %v. Skipping proposal.", n.ID, err); return }
	proposedBlock, err := n.Consensus.Propose(pendingTxs, lastBlock, expectedStateRoot, n.Wallet)
	if err != nil { if !bytes.Contains([]byte(err.Error()), []byte("not validator's turn")) { utils.WarnLogger.Printf("[%s] Consensus proposal failed: %v", n.ID, err) }; return }
    err = n.Blockchain.AddBlock(proposedBlock)
    if err != nil { utils.ErrorLogger.Printf("[%s] CRITICAL: Failed to add self-proposed block %d (%x) to own chain: %v", n.ID, proposedBlock.Header.Height, proposedBlock.Hash, err); return }
	n.Broadcaster.BroadcastBlock(n, proposedBlock) // Use interface
}

// calculateTentativeStateRoot simulates applying transactions to predict the state root.
func (n *Node) calculateTentativeStateRoot(txs core.TxList) ([]byte, error) {
    if n.StateManager == nil { return nil, fmt.Errorf("[%s] Cannot calculate tentative root: Node's StateManager is nil", n.ID) }
    originalValues := make(map[string][]byte); keysToRevert := make(map[string]bool)
    utils.DebugLogger.Printf("[%s] Calculating tentative root: Applying %d txs using public methods...", n.ID, len(txs))
    for _, tx := range txs {
        key := tx.To; keysToRevert[key] = true
        if _, stored := originalValues[key]; !stored { currentVal, _ := n.StateManager.Get(key); originalValues[key] = currentVal }
        // Simulate using public Put/Get/Delete
        var valueToStore []byte
        if len(tx.Data) > 0 { valueToStore = tx.Data } else {
            var valBuf bytes.Buffer
            enc := gob.NewEncoder(&valBuf) // Need encoding/gob import here
            if errEnc := enc.Encode(tx.Value); errEnc != nil {
                 n.revertTentativeChanges(originalValues, keysToRevert)
                 return nil, fmt.Errorf("[%s] failed simulating encode value for tx %x: %w", n.ID, tx.ID, errEnc)
            }
            valueToStore = valBuf.Bytes()
        }
        err := n.StateManager.Put(key, valueToStore) // Use PUBLIC Put
        if err != nil {
            utils.ErrorLogger.Printf("[%s] Error applying tx %x via Put to state for tentative root calculation: %v. Reverting attempted changes.", n.ID, tx.ID, err)
            n.revertTentativeChanges(originalValues, keysToRevert)
            return nil, fmt.Errorf("failed applying tx %x tentatively via Put: %w", tx.ID, err)
        }
    }
    tentativeRoot := n.StateManager.CalculateGlobalStateRoot()
    utils.DebugLogger.Printf("[%s] Tentative root calculated: %x", n.ID, tentativeRoot)
    n.revertTentativeChanges(originalValues, keysToRevert)
    utils.DebugLogger.Printf("[%s] Reverted tentative state changes.", n.ID)
    return tentativeRoot, nil
}

// revertTentativeChanges attempts to restore original values.
func (n *Node) revertTentativeChanges(originalValues map[string][]byte, keysModified map[string]bool) {
     if n.StateManager == nil { return }
     for key := range keysModified {
         originalValue, existed := originalValues[key]
         if !existed { utils.ErrorLogger.Printf("[%s] Revert Warning: Key '%s' was modified but no original value was stored.", n.ID, key); continue }
         var revertErr error
         if originalValue == nil { revertErr = n.StateManager.Delete(key) } else { revertErr = n.StateManager.Put(key, originalValue) } // Use public methods
         if revertErr != nil { utils.ErrorLogger.Printf("[%s] CRITICAL REVERT FAILED for key '%s': %v. State may be inconsistent.", n.ID, key, revertErr) }
     }
}

// HandleTransaction processes an incoming transaction.
func (n *Node) HandleTransaction(tx *core.Transaction) {
    if tx == nil { return }
	err := n.Blockchain.AddTransaction(tx)
	if err != nil { if !bytes.Contains([]byte(err.Error()), []byte("already in pool")) { utils.WarnLogger.Printf("[%s] Failed to add received Tx %x... to pool: %v", n.ID, tx.ID[:4], err) } }
}

// HandleBlock processes an incoming block.
func (n *Node) HandleBlock(block *core.Block) {
    if block == nil { return }
	utils.DebugLogger.Printf("[%s] Received Block %d (%x) from network validator %s", n.ID, block.Header.Height, block.Hash, block.Header.Validator)
    _, exists := n.Blockchain.GetBlockByHash(block.Hash); if exists { return }
    lastBlock := n.Blockchain.LastBlock()
    if lastBlock == nil { if block.Header.Height != 0 { return } } else { if block.Header.Height != lastBlock.Header.Height+1 { return }; if !bytes.Equal(block.Header.PrevBlockHash, lastBlock.Hash) { return } }
	err := n.Consensus.Validate(block, lastBlock); if err != nil { utils.WarnLogger.Printf("[%s] Block %d (%x) failed consensus validation: %v", n.ID, block.Header.Height, block.Hash, err); return }
	err = n.Blockchain.AddBlock(block); if err != nil { utils.WarnLogger.Printf("[%s] Failed to add block %d (%x) to chain: %v", n.ID, block.Header.Height, block.Hash, err) }
}

// --- REMOVE ALL DUPLICATED CODE BELOW THIS LINE ---
// // --- Implementation Details Copied (Ensure these match final working versions) ---
// func NewNode(...) (*Node, error) { /* ... */ }
// func (n *Node) AssignValidatorWallet(...) error { /* ... */ }
// func CreateGenesisBlock(...) *core.Block { /* ... */ }
// func (n *Node) Start(...) { /* ... */ }
// func (n *Node) Stop() { /* ... */ }
// func (n *Node) tryProposeBlock() { /* ... */ }
// func (n *Node) revertTentativeChanges(...) { /* ... */ } // Note: This one was also duplicated
// func (n *Node) HandleTransaction(...) { /* ... */ }
// func (n *Node) HandleBlock(...) { /* ... */ }