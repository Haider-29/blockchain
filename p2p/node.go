package p2p

import (
	"bytes"
	"encoding/gob" // Needed for calculateTentativeStateRoot simulation
	"fmt"
	"time"
    "sync"
    // "encoding/hex" // Not Used

	"blockchain/consensus"
	"blockchain/core"
	"blockchain/crypto"
	"blockchain/state" // Keep state import for creating StateManager instance
	"blockchain/utils"
)

// Node represents a participant in the network.
type Node struct {
	ID           string // Unique identifier (e.g., public key address or Node-X-Addr)
	Wallet       *crypto.Wallet
	Blockchain   *core.Blockchain // Holds the blockchain instance
	StateManager *state.StateManager // Keep concrete type for direct access if needed (e.g., state simulation)
	Consensus    consensus.ConsensusEngine
	Network      *Network // Reference to the simulated network
	IsValidator  bool
    stopChan     chan struct{} // Channel to signal shutdown
    wg           sync.WaitGroup // Waitgroup for goroutines
}

// NewNode creates a new network node instance.
// It initializes the node's state, blockchain, consensus engine, and wallet.
func NewNode(idPrefix string, network *Network, isValidator bool, validators []string, genesisBlock *core.Block) (*Node, error) {
    // Validate inputs
    if network == nil { return nil, fmt.Errorf("network cannot be nil") }
    if genesisBlock == nil { return nil, fmt.Errorf("genesis block cannot be nil") }

	wallet := crypto.NewWallet() // Each node gets its own wallet
	// Create a unique ID combining prefix and part of the address
    nodeID := fmt.Sprintf("%s-%s", idPrefix, wallet.Address[:6])

	// 1. Create the concrete StateManager instance
	stateMgr := state.NewStateManager()
    // Ensure stateMgr reflects genesis state (usually means starting empty matches genesis root)
    initialStateRoot := stateMgr.CalculateGlobalStateRoot()
    if !bytes.Equal(genesisBlock.Header.StateRoot, initialStateRoot) {
        return nil, fmt.Errorf("node %s: Genesis block state root (%x) does not match initial state manager root (%x)",
            nodeID, genesisBlock.Header.StateRoot, initialStateRoot)
    }


    // 2. Create the Blockchain, passing the concrete stateMgr where the interface is expected
	bc, err := core.NewBlockchain(stateMgr, genesisBlock, nodeID) // Pass concrete type
    if err != nil {
        return nil, fmt.Errorf("failed to create blockchain for node %s: %w", nodeID, err)
    }

	// 3. Create the Consensus engine
	consensusEngine, err := consensus.NewSimplePoA(validators, wallet, genesisBlock)
    if err != nil {
        // Clean up already created blockchain/state? Or just fail?
        return nil, fmt.Errorf("failed to create consensus engine for node %s: %w", nodeID, err)
    }

	// 4. Create the Node struct
	node := &Node{
		ID:           nodeID,
		Wallet:       wallet,
		Blockchain:   bc,       // Assign the created blockchain
		StateManager: stateMgr, // Store the concrete state manager instance
		Consensus:    consensusEngine,
		Network:      network,
		IsValidator:  isValidator,
        stopChan:     make(chan struct{}), // Initialize stop channel
	}
	utils.InfoLogger.Printf("Created Node: %s (Validator: %v, Addr: %s)", node.ID, node.IsValidator, node.Wallet.Address)
	return node, nil
} // <--- Correctly returns node, nil

// AssignValidatorWallet is used *after* NewNode if a specific pre-created wallet needs to be used for a validator.
// This updates the node's ID, Wallet, Consensus engine, and Blockchain instance to use the correct identity.
func (n *Node) AssignValidatorWallet(validatorWallet *crypto.Wallet, validators []string, genesisBlock *core.Block) error {
     if !n.IsValidator { return fmt.Errorf("cannot assign validator wallet to non-validator node %s", n.ID) }
     if validatorWallet == nil { return fmt.Errorf("provided validator wallet is nil for node %s", n.ID) }

     oldID := n.ID
     n.Wallet = validatorWallet
     n.ID = n.Wallet.Address // Validator nodes identified by their wallet address

     // Re-initialize consensus engine with the correct wallet
     newConsensus, err := consensus.NewSimplePoA(validators, n.Wallet, genesisBlock)
     if err != nil { return fmt.Errorf("failed to re-initialize consensus for node %s with new wallet: %w", n.ID, err) }
     n.Consensus = newConsensus

     // Re-initialize blockchain with correct ID and *existing* state manager instance
     // The state manager content doesn't change, just the blockchain wrapper's node ID.
     newBC, err := core.NewBlockchain(n.StateManager, genesisBlock, n.ID) // Pass existing StateManager
     if err != nil { return fmt.Errorf("failed to re-initialize blockchain for node %s with new wallet: %w", n.ID, err) }
     n.Blockchain = newBC

     utils.InfoLogger.Printf("Assigned validator wallet %s to node (previously %s)", n.ID, oldID)
     return nil
} // <--- Correctly returns nil


// CreateGenesisBlock creates the first block in the chain.
// Needs to be identical for all nodes.
func CreateGenesisBlock(validators []string) *core.Block {
	txs := core.TxList{}
	initialState := state.NewStateManager()
	genesisStateRoot := initialState.CalculateGlobalStateRoot()
	genesisValidator := "0xGENESIS"
	genesisTimestamp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
    genesisBlock := core.NewBlock(0, []byte("genesis_prev_hash"), genesisStateRoot, txs, genesisValidator)
    genesisBlock.Header.Timestamp = genesisTimestamp
    genesisBlock.Hash = genesisBlock.CalculateHash()
    utils.InfoLogger.Printf("Created Genesis Block: Hash %x, StateRoot: %x", genesisBlock.Hash, genesisBlock.Header.StateRoot)
	return genesisBlock
} // <--- Correctly returns genesisBlock

// Start the node's operations (e.g., proposing blocks if validator).
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
} // <--- Correctly has no return (launches goroutine)

// Stop signals the node to shut down its goroutines gracefully.
func (n *Node) Stop() {
    utils.InfoLogger.Printf("Node %s shutting down...", n.ID)
    select { case <-n.stopChan: default: close(n.stopChan) }; n.wg.Wait(); n.Network.UnregisterNode(n.ID); utils.InfoLogger.Printf("Node %s shutdown complete.", n.ID)
} // <--- Correctly has no return

// tryProposeBlock attempts to create and broadcast a new block if it's the node's turn.
func (n *Node) tryProposeBlock() {
	lastBlock := n.Blockchain.LastBlock(); if lastBlock == nil { utils.WarnLogger.Printf("[%s] Cannot propose: Last block is nil.", n.ID); return }
	pendingTxs := n.Blockchain.GetPendingTransactions(10)
    expectedStateRoot, err := n.calculateTentativeStateRoot(pendingTxs)
    if err != nil { utils.ErrorLogger.Printf("[%s] Failed to calculate tentative state root: %v. Skipping proposal.", n.ID, err); return }
	proposedBlock, err := n.Consensus.Propose(pendingTxs, lastBlock, expectedStateRoot, n.Wallet)
	if err != nil { if !bytes.Contains([]byte(err.Error()), []byte("not validator's turn")) { utils.WarnLogger.Printf("[%s] Consensus proposal failed: %v", n.ID, err) }; return }
    err = n.Blockchain.AddBlock(proposedBlock)
    if err != nil { utils.ErrorLogger.Printf("[%s] CRITICAL: Failed to add self-proposed block %d (%x) to own chain: %v", n.ID, proposedBlock.Header.Height, proposedBlock.Hash, err); return }
	n.Network.BroadcastBlock(n, proposedBlock)
} // <--- Correctly has no return

// calculateTentativeStateRoot simulates applying transactions to a temporary state copy
func (n *Node) calculateTentativeStateRoot(txs core.TxList) ([]byte, error) {
    tempStateMgrSim := state.NewStateManager()
    if n.StateManager == nil { return nil, fmt.Errorf("[%s] Cannot calculate tentative root: Node's StateManager is nil", n.ID) }
    for shardID, currentShard := range n.StateManager.Shards {
        copiedStateData := currentShard.GetStateData()
        tempShard, ok := tempStateMgrSim.Shards[shardID]
        if !ok { return nil, fmt.Errorf("[%s] internal error: temporary shard %d not found during state copy", n.ID, shardID) }
        tempShard.SetStateAndRecalculate(copiedStateData)
    }
    // Optional Sanity Check: Compare initial roots
    // ...
    for _, tx := range txs {
        targetKey := tx.To
        var valueToStore []byte
        if len(tx.Data) > 0 { valueToStore = tx.Data } else {
            var valBuf bytes.Buffer
            enc := gob.NewEncoder(&valBuf)
            if errEnc := enc.Encode(tx.Value); errEnc != nil { return nil, fmt.Errorf("[%s] failed simulating encode value for tx %x: %w", n.ID, tx.ID, errEnc) }
            valueToStore = valBuf.Bytes()
        }
        err := tempStateMgrSim.Put(targetKey, valueToStore) // Use public Put on temp manager
        if err != nil { return nil, fmt.Errorf("failed applying tx %x to temp state via Put: %w", tx.ID, err) }
    }
    finalTempRoot := tempStateMgrSim.CalculateGlobalStateRoot()
    return finalTempRoot, nil
} // <--- Correctly returns []byte, error


// HandleTransaction receives a transaction from the network.
func (n *Node) HandleTransaction(tx *core.Transaction) {
    if tx == nil { return }
	err := n.Blockchain.AddTransaction(tx)
	if err != nil { if !bytes.Contains([]byte(err.Error()), []byte("already in pool")) { utils.WarnLogger.Printf("[%s] Failed to add received Tx %x... to pool: %v", n.ID, tx.ID[:4], err) } }
} // <--- Correctly has no return

// HandleBlock receives a block from the network.
func (n *Node) HandleBlock(block *core.Block) {
    if block == nil { return }
	utils.DebugLogger.Printf("[%s] Received Block %d (%x) from network validator %s", n.ID, block.Header.Height, block.Hash, block.Header.Validator)
    _, exists := n.Blockchain.GetBlockByHash(block.Hash); if exists { utils.DebugLogger.Printf("[%s] Ignoring block %d (%x): Already have this block.", n.ID, block.Header.Height, block.Hash); return }
    lastBlock := n.Blockchain.LastBlock()
    if lastBlock == nil {
        if block.Header.Height != 0 { utils.WarnLogger.Printf("[%s] Received block %d (%x) but local last block is nil.", n.ID, block.Header.Height, block.Hash); return }
    } else {
        if block.Header.Height != lastBlock.Header.Height+1 { if block.Header.Height > lastBlock.Header.Height + 1 { utils.WarnLogger.Printf("[%s] Received block %d (%x) from future? Current height %d. Needs sync.", n.ID, block.Header.Height, block.Hash, lastBlock.Header.Height) } else { utils.DebugLogger.Printf("[%s] Ignoring block %d (%x): Height %d not sequential (current: %d).", n.ID, block.Header.Height, block.Hash, block.Header.Height, lastBlock.Header.Height) }; return }
        if !bytes.Equal(block.Header.PrevBlockHash, lastBlock.Hash) { utils.WarnLogger.Printf("[%s] Ignoring block %d (%x): PrevHash %x does not match local last block hash %x.", n.ID, block.Header.Height, block.Hash, block.Header.PrevBlockHash, lastBlock.Hash); return }
    }
	err := n.Consensus.Validate(block, lastBlock); if err != nil { utils.WarnLogger.Printf("[%s] Block %d (%x) failed consensus validation: %v", n.ID, block.Header.Height, block.Hash, err); return }
	err = n.Blockchain.AddBlock(block); if err != nil { utils.WarnLogger.Printf("[%s] Failed to add block %d (%x) to chain: %v", n.ID, block.Header.Height, block.Hash, err) }
} // <--- Correctly has no return


// --- REMOVE THE DUPLICATED CODE SECTION LABELED "Implementation Details Copied" ---
// // --- Implementation Details Copied (No Changes Here) ---
// // (NewNode, AssignValidatorWallet, CreateGenesisBlock, Start, Stop, tryProposeBlock, HandleTransaction, HandleBlock implementations)
// func NewNode(...) (*Node, error) { /* ... */ } // DUPLICATE REMOVED
// func (n *Node) AssignValidatorWallet(...) error { /* ... */ } // DUPLICATE REMOVED
// func CreateGenesisBlock(...) *core.Block { /* ... */ } // DUPLICATE REMOVED
// func (n *Node) Start(...) { /* ... */ } // DUPLICATE REMOVED
// func (n *Node) Stop() { /* ... */ } // DUPLICATE REMOVED
// func (n *Node) tryProposeBlock() { /* ... */ } // DUPLICATE REMOVED
// func (n *Node) HandleTransaction(...) { /* ... */ } // DUPLICATE REMOVED
// func (n *Node) HandleBlock(...) { /* ... */ } // DUPLICATE REMOVED