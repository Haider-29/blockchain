package p2p

import (
	"bytes"
	//"encoding/gob" // No longer needed directly here
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
	if broadcaster == nil { return nil, fmt.Errorf("network broadcaster cannot be nil") }
	if genesisBlock == nil { return nil, fmt.Errorf("genesis block cannot be nil") }
	wallet := crypto.NewWallet()
	nodeID := fmt.Sprintf("%s-%s", idPrefix, wallet.Address[:6])
	stateMgr := state.NewStateManager()
    initialStateRoot := stateMgr.CalculateGlobalStateRoot()
    if !bytes.Equal(genesisBlock.Header.StateRoot, initialStateRoot) { return nil, fmt.Errorf("node %s: Genesis block state root (%x) does not match initial state manager root (%x)", nodeID, genesisBlock.Header.StateRoot, initialStateRoot) }
	bc, err := core.NewBlockchain(stateMgr, genesisBlock, nodeID)
    if err != nil { return nil, fmt.Errorf("failed to create blockchain for node %s: %w", nodeID, err) }
	consensusEngine, err := consensus.NewSimplePoA(validators, wallet, genesisBlock)
    if err != nil { return nil, fmt.Errorf("failed to create consensus engine for node %s: %w", nodeID, err) }
	node := &Node{ ID: nodeID, Wallet: wallet, Blockchain: bc, StateManager: stateMgr, Consensus: consensusEngine, Broadcaster: broadcaster, IsValidator: isValidator, stopChan: make(chan struct{}) }
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
    utils.InfoLogger.Printf("Created Genesis Block: Hash %x, StateRoot: %x", genesisBlock.Hash, genesisBlock.Header.StateRoot);
	return genesisBlock
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

// tryProposeBlock uses SimulateApplyTransactions to get the expected state root.
func (n *Node) tryProposeBlock() {
	lastBlock := n.Blockchain.LastBlock();
    if lastBlock == nil { utils.WarnLogger.Printf("[%s] Cannot propose: Last block is nil.", n.ID); return }

    // 1. Get pending transactions - NOW filters by current nonce
	pendingTxs := n.Blockchain.GetPendingTransactions(10)

    // --- Debug Log ---
    if len(pendingTxs) > 0 {
        txIDs := make([]string, len(pendingTxs))
        for i, tx := range pendingTxs { txIDs[i] = hex.EncodeToString(tx.ID[:4]) + "..." }
        utils.DebugLogger.Printf("[%s] tryProposeBlock: Got %d EXECUTA BLE pending txs for block %d: %v", n.ID, len(pendingTxs), lastBlock.Header.Height+1, txIDs)
    } else {
         utils.DebugLogger.Printf("[%s] tryProposeBlock: No executable pending txs found for block %d.", n.ID, lastBlock.Header.Height+1)
    }

    // 2. Simulate applying these executable transactions
    if n.StateManager == nil { utils.ErrorLogger.Printf("[%s] Cannot propose: StateManager is nil.", n.ID); return }
    expectedStateRoot, simErr := n.StateManager.SimulateApplyTransactions(pendingTxs)
    if simErr != nil {
         utils.ErrorLogger.Printf("[%s] CRITICAL: Simulation failed for already validated txs (block %d): %v. Skipping proposal.", n.ID, lastBlock.Header.Height+1, simErr)
         return
    }
    utils.DebugLogger.Printf("[%s] Simulation successful for block %d. Expected State Root: %x...", n.ID, lastBlock.Header.Height+1, expectedStateRoot[:4])


	// 3. Call consensus engine to propose the block structure using the *predicted* state root
	proposedBlock, err := n.Consensus.Propose(pendingTxs, lastBlock, expectedStateRoot, n.Wallet)
	if err != nil {
		if !bytes.Contains([]byte(err.Error()), []byte("not validator's turn")) {
			utils.WarnLogger.Printf("[%s] Consensus proposal failed for height %d: %v", n.ID, lastBlock.Header.Height+1, err)
		}
		return
	}
    utils.DebugLogger.Printf("[%s] Proposed block %d (%x) with %d txs and header state root %x", n.ID, proposedBlock.Header.Height, proposedBlock.Hash[:4], len(proposedBlock.Transactions), proposedBlock.Header.StateRoot[:4])

    // 4. Attempt to add the proposed block LOCALLY. AddBlock validates everything again.
    err = n.Blockchain.AddBlock(proposedBlock)
    if err != nil {
        utils.ErrorLogger.Printf("[%s] CRITICAL: Self-proposed block %d (%x) REJECTED locally DESPITE successful simulation: %v", n.ID, proposedBlock.Header.Height, proposedBlock.Hash, err)
        return
    }

    // 5. If AddBlock succeeded locally, the block IS valid.
    utils.DebugLogger.Printf("[%s] Self-proposed block %d (%x) accepted locally.", n.ID, proposedBlock.Header.Height, proposedBlock.Hash[:4])

	// 6. Broadcast the locally validated block
    utils.DebugLogger.Printf("[%s] Broadcasting locally validated block %d (%x)...", n.ID, proposedBlock.Header.Height, proposedBlock.Hash[:4])
	n.Broadcaster.BroadcastBlock(n, proposedBlock) // Use interface
}

// HandleTransaction processes an incoming transaction.
func (n *Node) HandleTransaction(tx *core.Transaction) {
    if tx == nil { return }
	err := n.Blockchain.AddTransaction(tx) // Add to local pool (now allows future nonces)
	if err == nil {
        // Optional: Re-broadcast via interface if logic requires it?
    } else {
        if !bytes.Contains([]byte(err.Error()), []byte("already in pool")) {
             utils.WarnLogger.Printf("[%s] Failed to add received Tx %x... to pool: %v", n.ID, tx.ID[:4], err)
        }
    }
}

// HandleBlock processes an incoming block.
func (n *Node) HandleBlock(block *core.Block) {
    if block == nil { return }
	utils.DebugLogger.Printf("[%s] Received Block %d (%x) from network validator %s", n.ID, block.Header.Height, block.Hash, block.Header.Validator)
    _, exists := n.Blockchain.GetBlockByHash(block.Hash); if exists { utils.DebugLogger.Printf("[%s] Ignoring block %d (%x): Already have this block.", n.ID, block.Header.Height, block.Hash); return }
    lastBlock := n.Blockchain.LastBlock()
    if lastBlock == nil { if block.Header.Height != 0 { utils.WarnLogger.Printf("[%s] Received block %d (%x) but local chain is empty (expecting genesis).", n.ID, block.Header.Height, block.Hash); return }
    } else {
        if block.Header.Height != lastBlock.Header.Height+1 { if block.Header.Height > lastBlock.Header.Height + 1 { utils.WarnLogger.Printf("[%s] Received block %d (%x) from future? Current height %d. Needs sync.", n.ID, block.Header.Height, block.Hash, lastBlock.Header.Height) } else { utils.DebugLogger.Printf("[%s] Ignoring block %d (%x): Height %d not sequential (current: %d).", n.ID, block.Header.Height, block.Hash, block.Header.Height, lastBlock.Header.Height) }; return }
        if !bytes.Equal(block.Header.PrevBlockHash, lastBlock.Hash) { utils.WarnLogger.Printf("[%s] Ignoring block %d (%x): PrevHash %x does not match local last block hash %x.", n.ID, block.Header.Height, block.Hash, block.Header.PrevBlockHash, lastBlock.Hash); return }
    }
	err := n.Consensus.Validate(block, lastBlock); if err != nil { utils.WarnLogger.Printf("[%s] Block %d (%x) failed consensus validation: %v", n.ID, block.Header.Height, block.Hash, err); return }
	err = n.Blockchain.AddBlock(block); if err != nil { utils.WarnLogger.Printf("[%s] Failed to add block %d (%x) to chain: %v", n.ID, block.Header.Height, block.Hash, err) }
}