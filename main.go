package main

import (
	// "bytes" // REMOVE - Not used
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
	"blockchain/p2p"
    "blockchain/state" // <-- ADD Import for state.NUM_SHARDS
	"blockchain/utils"
)

func main() {
	// Set higher log level for more details during simulation
	os.Setenv("LOG_LEVEL", "DEBUG") // Or "INFO" for less verbosity
	utils.InfoLogger.Println("--- Starting Simplified Blockchain Simulation ---")

	// --- Configuration ---
	numNodes := 5
	numValidators := 3           // Must be <= numNodes
	blockTime := 3 * time.Second // Propose blocks every N seconds (adjust for testing)
    rand.Seed(time.Now().UnixNano()) // Seed random number generator

	if numValidators <= 0 { utils.ErrorLogger.Fatal("Number of validators must be positive.") }
	if numValidators > numNodes { utils.ErrorLogger.Fatal("Number of validators cannot exceed number of nodes.") }

	// --- Setup Validators ---
	validatorWallets := make([]*crypto.Wallet, numValidators)
	validatorAddrs := make([]string, numValidators)
	utils.InfoLogger.Printf("Creating %d Validator Wallets...", numValidators)
	for i := 0; i < numValidators; i++ {
		wallet := crypto.NewWallet(); validatorWallets[i] = wallet; validatorAddrs[i] = wallet.Address
	}
    utils.InfoLogger.Printf("Validator Set Addresses: %v", validatorAddrs)

	// --- Create Genesis Block ---
    genesisBlock := p2p.CreateGenesisBlock(validatorAddrs)

	// --- Create Network & Nodes ---
	network := p2p.NewNetwork()
	nodes := make([]*p2p.Node, numNodes)
	utils.InfoLogger.Printf("Creating %d Network Nodes (%d Validators)...", numNodes, numValidators)
	for i := 0; i < numNodes; i++ {
		isValidator := i < numValidators
		nodePrefix := "Node"; if isValidator { nodePrefix = "Validator" }
		node, err := p2p.NewNode(nodePrefix, network, isValidator, validatorAddrs, genesisBlock)
        if err != nil { utils.ErrorLogger.Fatalf("Failed to create node %d: %v", i, err) }
		nodes[i] = node
        if isValidator {
            err := node.AssignValidatorWallet(validatorWallets[i], validatorAddrs, genesisBlock)
            if err != nil { utils.ErrorLogger.Fatalf("Failed to assign validator wallet to node %d (%s): %v", i, node.ID, err) }
        }
		err = network.RegisterNode(node)
        if err != nil { utils.ErrorLogger.Printf("Failed to register node %s: %v", node.ID, err) }
	}

	// --- Start Nodes ---
    utils.InfoLogger.Println("Starting all nodes...")
	for _, node := range nodes { node.Start(blockTime) }

	// --- Simulate Transaction Generation ---
    utils.InfoLogger.Println("Starting transaction simulator...")
	txSimulatorStopChan := make(chan struct{}) // Channel to stop simulator
	go func() {
        defer utils.InfoLogger.Println("Transaction simulator loop exited.") // Log when done
        if numNodes == 0 { return } // No nodes to send transactions

        senderNodeIndex := rand.Intn(numNodes)
		senderWallet := nodes[senderNodeIndex].Wallet
        senderNode := nodes[senderNodeIndex]
        utils.InfoLogger.Printf("Transaction simulator using sender: %s (%s)", senderNode.ID, senderWallet.Address)

		nonceMap := make(map[string]uint64)
        senderAddr := senderWallet.Address
        nonceMap[senderAddr] = 0

        // --- Get Shard Count ---
        // Prefer getting from a running node, fallback to constant
        var numShards uint32 = state.NUM_SHARDS // Default to constant from state package
        if len(nodes) > 0 && nodes[0].Blockchain != nil {
             fetchedNumShards := nodes[0].Blockchain.GetNumShards() // Use getter method
             if fetchedNumShards > 0 {
                 numShards = fetchedNumShards // Use fetched value if valid
             } else {
                 // Log if getter returned 0 but default is non-zero
                 if numShards > 0 {
                    utils.WarnLogger.Printf("Warning: GetNumShards returned 0, falling back to state.NUM_SHARDS (%d)", numShards)
                 }
             }
        } else if len(nodes) == 0 {
             utils.WarnLogger.Printf("Warning: No nodes available to determine shard count, using default from state: %d", numShards)
        } else {
             utils.WarnLogger.Printf("Warning: Node 0 or its blockchain is nil, using default shard count from state: %d", numShards)
        }
        // Final check: ensure we don't proceed with 0 shards
        if numShards == 0 {
             utils.ErrorLogger.Fatal("Cannot proceed: Effective number of shards is zero.")
        }
        utils.InfoLogger.Printf("Transaction simulator using Number of Shards: %d", numShards)
        // --- End Get Shard Count ---


		for {
			select {
            case <-txSimulatorStopChan:
                utils.InfoLogger.Println("Stopping transaction simulator.")
                return // Exit goroutine
            case <-time.After(time.Duration(rand.Intn(3000)+500) * time.Millisecond):
                recipientNodeIndex := rand.Intn(numNodes)
                recipientAddr := nodes[recipientNodeIndex].Wallet.Address

                value := uint64(rand.Intn(100) + 1)
                data := []byte(fmt.Sprintf("Payload from %s @ %d", senderNode.ID, time.Now().Unix()))

                currentNonce := nonceMap[senderAddr]

                tx, err := core.NewTransaction(senderWallet, recipientAddr, value, currentNonce, data, numShards) // Pass numShards here
                if err != nil {
                    utils.ErrorLogger.Printf("[%s] Simulator: Failed to create transaction (Nonce: %d): %v", senderNode.ID, currentNonce, err)
                    continue
                }

                utils.InfoLogger.Printf("==> [%s] Created Tx: %s... (To: %s..., Nonce: %d, Shard: %d)",
                     senderNode.ID, hex.EncodeToString(tx.ID[:4]), recipientAddr[:8], tx.Nonce, tx.ShardHint)

                // Submit transaction to the sender's node
                senderNode.HandleTransaction(tx)

                // Increment nonce after attempting submission
                nonceMap[senderAddr] = currentNonce + 1

			} // end select
		} // end for
	}() // end goroutine

	// --- Keep Running & Handle Graceful Shutdown ---
	utils.InfoLogger.Println("Simulation running... Press Ctrl+C to stop.")
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan // Wait for signal
	utils.InfoLogger.Println("--- Initiating Graceful Shutdown ---")

    close(txSimulatorStopChan) // Stop transaction simulator first

	// Stop all nodes (they wait for internal goroutines)
    utils.InfoLogger.Println("Stopping nodes...")
    for _, node := range nodes { node.Stop() }

    // Close the log file explicitly before exiting
    utils.CloseLogFile() // <-- ADD THIS CALL

	utils.InfoLogger.Println("--- Simulation Finished ---") // This might not appear if log file is closed first
}