package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	// Consensus not needed
	"blockchain/core"
	"blockchain/crypto"
	"blockchain/p2p" // Keep p2p import
    "blockchain/state"
	"blockchain/utils"
)

func main() {
	os.Setenv("LOG_LEVEL", "DEBUG")
	utils.InfoLogger.Println("--- Starting Simplified Blockchain Simulation ---")

	// --- Configuration ---
	numNodes := 5
	numValidators := 3
	blockTime := 3 * time.Second
    rand.Seed(time.Now().UnixNano())
	if numValidators <= 0 { utils.ErrorLogger.Fatal("Number of validators must be positive.") }
	if numValidators > numNodes { utils.ErrorLogger.Fatal("Number of validators cannot exceed number of nodes.") }

	// --- Setup Validators ---
	validatorWallets := make([]*crypto.Wallet, numValidators)
	validatorAddrs := make([]string, numValidators)
	utils.InfoLogger.Printf("Creating %d Validator Wallets...", numValidators)
	for i := 0; i < numValidators; i++ { wallet := crypto.NewWallet(); validatorWallets[i] = wallet; validatorAddrs[i] = wallet.Address }
    utils.InfoLogger.Printf("Validator Set Addresses: %v", validatorAddrs)

	// --- Create Genesis Block ---
    genesisBlock := p2p.CreateGenesisBlock(validatorAddrs)

	// --- Create Network & Nodes ---
	network := p2p.NewNetwork() // Create the concrete network
	nodes := make([]*p2p.Node, numNodes)
	utils.InfoLogger.Printf("Creating %d Network Nodes (%d Validators)...", numNodes, numValidators)
	for i := 0; i < numNodes; i++ {
		isValidator := i < numValidators
		nodePrefix := "Node"; if isValidator { nodePrefix = "Validator" }

        // Create the node, passing the concrete network where the interface is expected
		node, err := p2p.NewNode(nodePrefix, network, isValidator, validatorAddrs, genesisBlock) // Pass concrete network
        if err != nil { utils.ErrorLogger.Fatalf("Failed to create node %d: %v", i, err) }
		nodes[i] = node

        if isValidator {
            err := node.AssignValidatorWallet(validatorWallets[i], validatorAddrs, genesisBlock)
            if err != nil { utils.ErrorLogger.Fatalf("Failed to assign validator wallet to node %d (%s): %v", i, node.ID, err) }
        }

		// Register node using concrete network method
        err = network.RegisterNode(node)
        if err != nil { utils.ErrorLogger.Printf("Failed to register node %s: %v", node.ID, err) }
	}

	// --- Start Nodes ---
    utils.InfoLogger.Println("Starting all nodes...")
	for _, node := range nodes { node.Start(blockTime) }

	// --- Simulate Transaction Generation ---
    utils.InfoLogger.Println("Starting transaction simulator...")
	txSimulatorStopChan := make(chan struct{})
	go func() {
        defer utils.InfoLogger.Println("Transaction simulator loop exited.")
        if numNodes == 0 { return }
        senderNodeIndex := rand.Intn(numNodes); senderWallet := nodes[senderNodeIndex].Wallet; senderNode := nodes[senderNodeIndex]
        utils.InfoLogger.Printf("Transaction simulator using sender: %s (%s)", senderNode.ID, senderWallet.Address)
		nonceMap := make(map[string]uint64); senderAddr := senderWallet.Address; nonceMap[senderAddr] = 0
        var numShards uint32 = state.NUM_SHARDS
        if len(nodes) > 0 && nodes[0].Blockchain != nil {
             fetchedNumShards := nodes[0].Blockchain.GetNumShards()
             if fetchedNumShards > 0 { numShards = fetchedNumShards
             } else { if numShards > 0 { utils.WarnLogger.Printf("Warning: GetNumShards returned 0, falling back to state.NUM_SHARDS (%d)", numShards) } }
        } else if len(nodes) == 0 { utils.WarnLogger.Printf("Warning: No nodes available to determine shard count, using default from state: %d", numShards)
        } else { utils.WarnLogger.Printf("Warning: Node 0 or its blockchain is nil, using default shard count from state: %d", numShards) }
        if numShards == 0 { utils.ErrorLogger.Fatal("Cannot proceed: Effective number of shards is zero.") }
        utils.InfoLogger.Printf("Transaction simulator using Number of Shards: %d", numShards)
		for {
			select {
            case <-txSimulatorStopChan: utils.InfoLogger.Println("Stopping transaction simulator."); return
            case <-time.After(time.Duration(rand.Intn(3000)+500) * time.Millisecond):
                recipientNodeIndex := rand.Intn(numNodes); recipientAddr := nodes[recipientNodeIndex].Wallet.Address
                value := uint64(rand.Intn(100) + 1); data := []byte(fmt.Sprintf("Payload from %s @ %d", senderNode.ID, time.Now().Unix()))
                currentNonce := nonceMap[senderAddr]
                tx, err := core.NewTransaction(senderWallet, recipientAddr, value, currentNonce, data, numShards)
                if err != nil { utils.ErrorLogger.Printf("[%s] Simulator: Failed to create transaction (Nonce: %d): %v", senderNode.ID, currentNonce, err); continue }
                utils.InfoLogger.Printf("==> [%s] Created Tx: %s... (To: %s..., Nonce: %d, Shard: %d)", senderNode.ID, hex.EncodeToString(tx.ID[:4]), recipientAddr[:8], tx.Nonce, tx.ShardHint)
                senderNode.HandleTransaction(tx) // Node handles adding to pool
                nonceMap[senderAddr] = currentNonce + 1 // Increment after attempting send
			}
		}
	}()

	// --- Keep Running & Handle Graceful Shutdown ---
	utils.InfoLogger.Println("Simulation running... Press Ctrl+C to stop.")
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	utils.InfoLogger.Println("--- Initiating Graceful Shutdown ---")
    close(txSimulatorStopChan)
    utils.InfoLogger.Println("Stopping nodes...")
    // Stop nodes first
    for _, node := range nodes { node.Stop() }
    // Unregistration happens within Node.Stop() using network object access (this assumes Node still has Network object, which we removed!)
    // -- Correction: Unregistration MUST happen here in main, using the network object --
    utils.InfoLogger.Println("Unregistering nodes...")
    for _, node := range nodes {
        network.UnregisterNode(node.ID) // Call network method directly
    }

    utils.CloseLogFile()
	utils.InfoLogger.Println("--- Simulation Finished ---") // This might not appear if log file closed first
}