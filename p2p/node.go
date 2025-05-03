package p2p

import (
	"bytes"
	"encoding/hex" // Needed for debug logs
	"fmt"
	"sync"
	"time"

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
	StateManager *state.StateManager
	Consensus    consensus.ConsensusEngine
	Broadcaster  NetworkBroadcaster // Interface type
	IsValidator  bool

	stopChan     chan struct{}
	wg           sync.WaitGroup
}

// NewNode creates a new network node instance.
func NewNode(
	idPrefix string,
	broadcaster NetworkBroadcaster,
	isValidator bool,
	validators []string,
	genesisBlock *core.Block,
) (*Node, error) {
	if broadcaster == nil {
		return nil, fmt.Errorf("network broadcaster cannot be nil")
	}
	if genesisBlock == nil {
		return nil, fmt.Errorf("genesis block cannot be nil")
	}

	wallet := crypto.NewWallet()
	nodeID := fmt.Sprintf("%s-%s", idPrefix, wallet.Address[:6])

	stateMgr := state.NewStateManager()
	// Verify initial state root matches genesis
	initialStateRoot := stateMgr.CalculateGlobalStateRoot()
	if !bytes.Equal(genesisBlock.Header.StateRoot, initialStateRoot) {
		return nil, fmt.Errorf("node %s: Genesis block state root (%x) does not match initial state manager root (%x)", nodeID, genesisBlock.Header.StateRoot, initialStateRoot)
	}

	// Create blockchain instance
	bc, err := core.NewBlockchain(stateMgr, genesisBlock, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to create blockchain for node %s: %w", nodeID, err)
	}

	// Create consensus engine instance
	consensusEngine, err := consensus.NewSimplePoA(validators, wallet, genesisBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create consensus engine for node %s: %w", nodeID, err)
	}

	// Create the node struct
	node := &Node{
		ID:           nodeID,
		Wallet:       wallet,
		Blockchain:   bc,
		StateManager: stateMgr,
		Consensus:    consensusEngine,
		Broadcaster:  broadcaster,
		IsValidator:  isValidator,
		stopChan:     make(chan struct{}),
	}
	utils.InfoLogger.Printf("Created Node: %s (Validator: %v, Addr: %s)", node.ID, node.IsValidator, node.Wallet.Address)
	return node, nil
}

// AssignValidatorWallet updates node identity for validators.
func (n *Node) AssignValidatorWallet(validatorWallet *crypto.Wallet, validators []string, genesisBlock *core.Block) error {
	if !n.IsValidator {
		return fmt.Errorf("cannot assign validator wallet to non-validator node %s", n.ID)
	}
	if validatorWallet == nil {
		return fmt.Errorf("provided validator wallet is nil for node %s", n.ID)
	}

	oldID := n.ID
	n.Wallet = validatorWallet
	n.ID = n.Wallet.Address // Use wallet address as ID for validators

	// Re-initialize consensus engine with the assigned wallet
	newConsensus, err := consensus.NewSimplePoA(validators, n.Wallet, genesisBlock)
	if err != nil {
		return fmt.Errorf("failed to re-initialize consensus for node %s with new wallet: %w", n.ID, err)
	}
	n.Consensus = newConsensus

	// Re-initialize blockchain with correct ID and *existing* state manager instance
	newBC, err := core.NewBlockchain(n.StateManager, genesisBlock, n.ID)
	if err != nil {
		return fmt.Errorf("failed to re-initialize blockchain for node %s with new wallet: %w", n.ID, err)
	}
	n.Blockchain = newBC

	utils.InfoLogger.Printf("Assigned validator wallet %s to node (previously %s)", n.ID, oldID)
	return nil
}

// CreateGenesisBlock creates the first block in the chain.
func CreateGenesisBlock(validators []string) *core.Block {
	txs := core.TxList{}
	initialState := state.NewStateManager()
	genesisStateRoot := initialState.CalculateGlobalStateRoot()
	// Use Proposer field name consistently
	genesisProposer := "0xGENESIS"
	genesisTimestamp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	// Pass proposer address to NewBlock
	genesisBlock := core.NewBlock(0, []byte("genesis_prev_hash"), genesisStateRoot, txs, genesisProposer)
	genesisBlock.Header.Timestamp = genesisTimestamp
	// Genesis has no VRF fields or Signatures map populated in this simple setup
	genesisBlock.Hash = genesisBlock.CalculateHash() // Calculate final hash
	utils.InfoLogger.Printf("Created Genesis Block: Hash %x, StateRoot: %x", genesisBlock.Hash, genesisBlock.Header.StateRoot)
	return genesisBlock
}

// Start the node's main loop (proposal or listening).
func (n *Node) Start(blockTime time.Duration) {
	utils.InfoLogger.Printf("Node %s starting...", n.ID)
	n.wg.Add(1) // Increment waitgroup counter for this goroutine
	go func() {
		defer n.wg.Done() // Decrement counter when goroutine exits
		if n.IsValidator {
			// Validator loop
			utils.InfoLogger.Printf("Node %s (Validator) starting proposal loop (Block Time: %s)...", n.ID, blockTime)
			ticker := time.NewTicker(blockTime)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					n.tryProposeBlock()
				case <-n.stopChan: // Listen for stop signal
					utils.InfoLogger.Printf("Node %s stopping proposal loop.", n.ID)
					return // Exit goroutine
				}
			}
		} else {
			// Non-validator loop (just listens)
			utils.InfoLogger.Printf("Node %s (Non-validator) started. Listening for network messages.", n.ID)
			<-n.stopChan // Wait indefinitely until stop signal
			utils.InfoLogger.Printf("Node %s stopping listener.", n.ID)
			return // Exit goroutine
		}
	}()
}

// Stop signals the node to shut down gracefully.
func (n *Node) Stop() {
	utils.InfoLogger.Printf("Node %s shutting down...", n.ID)
	// Use select to prevent panic if channel is already closed
	select {
	case <-n.stopChan:
		// Already closed
	default:
		close(n.stopChan) // Signal all goroutines listening on stopChan
	}
	n.wg.Wait() // Wait for launched goroutines (like the Start loop) to finish
	// Unregistration is handled by main loop now via Network object
	utils.InfoLogger.Printf("Node %s shutdown complete.", n.ID)
}

// tryProposeBlock attempts to create and broadcast a block using the snapshot simulation strategy.
func (n *Node) tryProposeBlock() {
	lastBlock := n.Blockchain.LastBlock()
	if lastBlock == nil {
		utils.WarnLogger.Printf("[%s] Cannot propose: Last block is nil.", n.ID)
		return
	}

	// 1. Get pending executable transactions (already nonce-checked)
	pendingTxs := n.Blockchain.GetPendingTransactions(10) // Arbitrary limit
	logPrefix := fmt.Sprintf("[%s H:%d]", n.ID, lastBlock.Header.Height+1) // Log prefix for clarity

	if len(pendingTxs) > 0 {
		txIDs := make([]string, len(pendingTxs))
		for i, tx := range pendingTxs { txIDs[i] = hex.EncodeToString(tx.ID[:4]) + "..." }
		utils.DebugLogger.Printf("%s tryProposeBlock: Got %d EXECUTA BLE pending txs: %v", logPrefix, len(pendingTxs), txIDs)
	} else {
		utils.DebugLogger.Printf("%s tryProposeBlock: No executable pending txs found.", logPrefix)
	}

	// 2. Simulate applying these transactions to get the expected state root
	if n.StateManager == nil { utils.ErrorLogger.Printf("%s Cannot propose: StateManager is nil.", logPrefix); return }
	expectedStateRoot, simErr := n.StateManager.SimulateApplyTransactions(pendingTxs)
	if simErr != nil {
		// Simulation should ideally only fail on critical errors now (like decode), not simple nonce issues
		utils.ErrorLogger.Printf("%s CRITICAL: Simulation failed for already validated txs: %v. Skipping proposal.", logPrefix, simErr)
		return
	}
	utils.DebugLogger.Printf("%s Simulation successful. Expected State Root: %x...", logPrefix, expectedStateRoot[:4])

	// 3. Call consensus engine to propose the block structure (includes leader check & signing)
	// Pass the accurately predicted state root.
	proposedBlock, err := n.Consensus.Propose(pendingTxs, lastBlock, expectedStateRoot, n.Wallet)
	if err != nil {
		// Log only if it's not the expected "not my turn" or leader determination error
		if !bytes.Contains([]byte(err.Error()), []byte("not validator's turn")) && !bytes.Contains([]byte(err.Error()), []byte("failed to determine VRF leader")) {
			utils.WarnLogger.Printf("%s Consensus proposal failed: %v", logPrefix, err)
		}
		return // Not our turn or another proposal error
	}
	// If Propose returns nil error, we are the leader and have a signed block proposal
	utils.DebugLogger.Printf("%s Proposed block (%x) with %d txs and header state root %x", logPrefix, proposedBlock.Hash[:4], len(proposedBlock.Transactions), proposedBlock.Header.StateRoot[:4])

	// 4. Attempt to add the proposed block LOCALLY. AddBlock validates everything again.
	// This should now succeed if the simulation and consensus logic were correct.
	err = n.Blockchain.AddBlock(proposedBlock)
	if err != nil {
		// This indicates a potential bug or race condition if it fails now.
		utils.ErrorLogger.Printf("%s CRITICAL: Self-proposed block (%x) REJECTED locally DESPITE successful simulation & proposal: %v", logPrefix, proposedBlock.Hash, err)
		// State might be inconsistent if ApplyBlock wasn't perfectly atomic.
		return
	}

	// 5. If AddBlock succeeded locally, the block IS valid.
	utils.DebugLogger.Printf("%s Self-proposed block (%x) accepted locally.", logPrefix, proposedBlock.Hash[:4])

	// 6. Broadcast the locally validated block
	utils.DebugLogger.Printf("%s Broadcasting locally validated block (%x)...", logPrefix, proposedBlock.Hash[:4])
	n.Broadcaster.BroadcastBlock(n, proposedBlock) // Use interface
}

// HandleTransaction processes an incoming transaction.
func (n *Node) HandleTransaction(tx *core.Transaction) {
	if tx == nil { return }
	// Add to local pool (allows future nonces, checks signature etc.)
	err := n.Blockchain.AddTransaction(tx)
	if err == nil {
		// Optional: Re-broadcast to ensure propagation? Depends on P2P strategy.
		// utils.DebugLogger.Printf("[%s] Re-broadcasting Tx %x...", n.ID, tx.ID[:4])
		// n.Broadcaster.BroadcastTransaction(n, tx)
	} else {
		// Log only if error wasn't "already in pool" or a validation error (which AddTransaction logs)
		if !bytes.Contains([]byte(err.Error()), []byte("already in pool")) && !bytes.Contains([]byte(err.Error()), []byte("pool validation")) {
			utils.WarnLogger.Printf("[%s] Failed to add received Tx %x... to pool: %v", n.ID, tx.ID[:4], err)
		}
	}
}

// HandleBlock processes an incoming block.
func (n *Node) HandleBlock(block *core.Block) {
	if block == nil { return } // Ignore nil blocks
	logPrefix := fmt.Sprintf("[%s]", n.ID)

	utils.DebugLogger.Printf("%s Received Block %d (%x) from network proposer %s", logPrefix, block.Header.Height, block.Hash, block.Header.Proposer) // Use Proposer

	// Check if block is already known
	_, exists := n.Blockchain.GetBlockByHash(block.Hash)
	if exists {
		utils.DebugLogger.Printf("%s Ignoring block %d (%x): Already have this block.", logPrefix, block.Header.Height, block.Hash)
		return
	}

	// Check sequence relative to local chain
	lastBlock := n.Blockchain.LastBlock()
	if lastBlock == nil { // Local chain is empty (only genesis)
		if block.Header.Height != 0 { // Only accept genesis if local chain is empty
			// Or maybe height 1 if genesis isn't broadcast? Depends on protocol. Let's reject > 0 for now.
			utils.WarnLogger.Printf("%s Received block %d (%x) but local chain is empty (expecting genesis).", logPrefix, block.Header.Height, block.Hash)
			return
		}
		// If height is 0, proceed to validation (allows receiving genesis from network)
	} else { // We have existing blocks
		// Check Height is exactly next
		if block.Header.Height != lastBlock.Header.Height+1 {
			if block.Header.Height > lastBlock.Header.Height+1 {
				utils.WarnLogger.Printf("%s Received block %d (%x) from future? Current height %d. Needs sync.", logPrefix, block.Header.Height, block.Hash, lastBlock.Header.Height)
				// TODO: Implement block synchronization logic
			} else {
				// Block is from the past or same height, ignore.
				utils.DebugLogger.Printf("%s Ignoring block %d (%x): Height %d not sequential (current: %d).", logPrefix, block.Header.Height, block.Hash, block.Header.Height, lastBlock.Header.Height)
			}
			return
		}
		// Check Parent Hash matches
		if !bytes.Equal(block.Header.PrevBlockHash, lastBlock.Hash) {
			utils.WarnLogger.Printf("%s Ignoring block %d (%x): PrevHash %x does not match local last block hash %x.", logPrefix, block.Header.Height, block.Hash, block.Header.PrevBlockHash, lastBlock.Hash)
			// TODO: Handle fork detection
			return
		}
	}

	// Consensus Validation (VRF, Threshold Sig, Timestamp checks)
	// Pass lastBlock (which could be nil if validating genesis)
	err := n.Consensus.Validate(block, lastBlock)
	if err != nil {
		utils.WarnLogger.Printf("%s Block %d (%x) from proposer %s failed consensus validation: %v", logPrefix, block.Header.Height, block.Hash, block.Header.Proposer, err)
		return
	}

	// Full Block Validation & State Commit
	// AddBlock performs structure checks, applies transactions, verifies final state root.
	err = n.Blockchain.AddBlock(block)
	if err != nil {
		utils.WarnLogger.Printf("%s Failed to add block %d (%x) from proposer %s to chain: %v", logPrefix, block.Header.Height, block.Hash, block.Header.Proposer, err)
		// State might be inconsistent if ApplyBlock wasn't atomic and failed mid-way.
	}
	// If successful, AddBlock logs the append message.
}