package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	// Consensus not needed directly
	"blockchain/core"
	"blockchain/crypto"
	"blockchain/p2p" // Needed for node/network types and genesis creation
	"blockchain/state" // Needed for shard constant fallback
	"blockchain/utils" // Needed for logging and maybe others
)

func main() {
	// Set log level via environment variable or default
	// Example: export LOG_LEVEL=DEBUG for more verbose output
	os.Setenv("LOG_LEVEL", "INFO") // Set default to INFO (can be overridden by ENV)
	utils.InfoLogger.Println("--- Starting Simplified Blockchain Simulation ---")

	// --- Configuration ---
	numNodes := 5                // Total number of nodes in the network
	numValidators := 3           // Number of nodes acting as validators (must be <= numNodes)
	blockTime := 3 * time.Second // Target time between blocks
	rand.Seed(time.Now().UnixNano()) // Seed random number generator for variability

	// Basic configuration validation
	if numValidators <= 0 {
		utils.ErrorLogger.Fatal("Number of validators must be positive.")
	}
	if numValidators > numNodes {
		utils.ErrorLogger.Fatal("Number of validators cannot exceed number of nodes.")
	}

	// --- Setup Validators ---
	// Create dedicated wallets for nodes that will be validators
	validatorWallets := make([]*crypto.Wallet, numValidators)
	validatorAddrs := make([]string, numValidators)
	utils.InfoLogger.Printf("Creating %d Validator Wallets...", numValidators)
	for i := 0; i < numValidators; i++ {
		wallet := crypto.NewWallet() // Creates and registers the wallet
		validatorWallets[i] = wallet
		validatorAddrs[i] = wallet.Address
	}
	utils.InfoLogger.Printf("Validator Set Addresses: %v", validatorAddrs)

	// --- Create Genesis Block ---
	// All nodes must start with the identical genesis block.
	genesisBlock := p2p.CreateGenesisBlock(validatorAddrs)

	// --- Create Network & Nodes ---
	network := p2p.NewNetwork() // Create the simulated network hub
	nodes := make([]*p2p.Node, numNodes)
	utils.InfoLogger.Printf("Creating %d Network Nodes (%d Validators)...", numNodes, numValidators)
	for i := 0; i < numNodes; i++ {
		isValidator := i < numValidators // First 'numValidators' nodes are validators
		nodePrefix := "Node"
		if isValidator {
			nodePrefix = "Validator"
		}

		// Create the node instance. Pass the concrete network object where the
		// NetworkBroadcaster interface is expected.
		node, err := p2p.NewNode(nodePrefix, network, isValidator, validatorAddrs, genesisBlock)
		if err != nil {
			utils.ErrorLogger.Fatalf("Failed to create node %d: %v", i, err)
		}
		nodes[i] = node

		// If this node is designated as a validator, assign its pre-created wallet
		// and re-initialize components that depend on the node's identity (consensus, blockchain ID).
		if isValidator {
			err := node.AssignValidatorWallet(validatorWallets[i], validatorAddrs, genesisBlock)
			if err != nil {
				utils.ErrorLogger.Fatalf("Failed to assign validator wallet to node %d (%s): %v", i, node.ID, err)
			}
			// Node ID is now the validator's wallet address
		}

		// Register the fully initialized node with the network simulation hub.
		err = network.RegisterNode(node)
		if err != nil {
			// This might happen if node IDs somehow collide (unlikely with current setup)
			utils.ErrorLogger.Printf("Failed to register node %s: %v", node.ID, err)
		}
	}

	// --- Start Nodes ---
	// Each node runs its main loop (proposing or listening) in a separate goroutine.
	utils.InfoLogger.Println("Starting all nodes...")
	for _, node := range nodes {
		node.Start(blockTime)
	}

	// --- Simulate Transaction Generation ---
	utils.InfoLogger.Println("Starting transaction simulator...")
	txSimulatorStopChan := make(chan struct{}) // Channel to signal simulator goroutine to stop
	go func() {
		defer utils.InfoLogger.Println("Transaction simulator loop exited.") // Log when goroutine finishes
		if numNodes == 0 {
			utils.WarnLogger.Println("No nodes created, transaction simulator exiting.")
			return // Exit if no nodes exist
		}

		// --- Setup Simulator ---
		// Pick a random node to be the initial sender of transactions
		senderNodeIndex := rand.Intn(numNodes)
		senderWallet := nodes[senderNodeIndex].Wallet
		senderNode := nodes[senderNodeIndex]
		utils.InfoLogger.Printf("Transaction simulator using sender: %s (%s)", senderNode.ID, senderWallet.Address)

		// Track nonce per sender address locally in the simulator
		nonceMap := make(map[string]uint64)
		senderAddr := senderWallet.Address
		nonceMap[senderAddr] = 0 // Initialize nonce

		// Determine the number of shards for creating transactions
		var numShards uint32 = state.NUM_SHARDS // Default to constant from state package
		if len(nodes) > 0 && nodes[0].Blockchain != nil {
			fetchedNumShards := nodes[0].Blockchain.GetNumShards() // Use getter method
			if fetchedNumShards > 0 {
				numShards = fetchedNumShards // Use fetched value if valid
			} else {
				if numShards > 0 { // Log warning only if default was non-zero
					utils.WarnLogger.Printf("Warning: GetNumShards from node returned 0, falling back to state.NUM_SHARDS (%d)", numShards)
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
		// --- End Setup ---

		// --- Transaction Generation Loop ---
		for {
			select {
			case <-txSimulatorStopChan: // Check if shutdown signal received
				utils.InfoLogger.Println("Stopping transaction simulator.")
				return // Exit goroutine
			// Wait for a random time before generating next transaction
			case <-time.After(time.Duration(rand.Intn(1500)+500) * time.Millisecond): // Interval 0.5s - 2.0s
				// Choose a random recipient node
				recipientNodeIndex := rand.Intn(numNodes)
				recipientAddr := nodes[recipientNodeIndex].Wallet.Address // Target the recipient's wallet address

				// Create some dummy transaction data
				value := uint64(rand.Intn(100) + 1) // Random value 1-100
				data := []byte(fmt.Sprintf("Payload from %s @ %d", senderNode.ID, time.Now().Unix()))

				// Get the next nonce for the current sender
				currentNonce := nonceMap[senderAddr]

				// Create and sign the transaction
				tx, err := core.NewTransaction(senderWallet, recipientAddr, value, currentNonce, data, numShards)
				if err != nil {
					// Log error and skip this transaction attempt, do not increment nonce
					utils.ErrorLogger.Printf("[%s] Simulator: Failed to create transaction (Nonce: %d): %v", senderNode.ID, currentNonce, err)
					continue
				}

				// Log the created transaction (abbreviated)
				utils.InfoLogger.Printf("==> [%s] Created Tx: %s... (To: %s..., Nonce: %d, Shard: %d)",
					senderNode.ID, hex.EncodeToString(tx.ID[:4]), recipientAddr[:8], tx.Nonce, tx.ShardHint)

				// --- Broadcast Transaction to ALL nodes via the network ---
				// Option A: Broadcast directly using the network object.
				// This ensures all nodes receive it quickly in the simulation.
				network.BroadcastTransaction(senderNode, tx)

				// --- OR ---
				// Option B: Submit only to sender node and rely on node's HandleTransaction to broadcast.
				// senderNode.HandleTransaction(tx) // Node adds to pool and calls n.Broadcaster...

				// Increment nonce only after attempting to broadcast/send the transaction
				nonceMap[senderAddr] = currentNonce + 1

			} // end select
		} // end for
	}() // end goroutine

	// --- Keep Running & Handle Graceful Shutdown ---
	utils.InfoLogger.Println("Simulation running... Press Ctrl+C to stop.")
	signalChan := make(chan os.Signal, 1) // Channel to listen for OS signals
	// Notify channel on SIGINT (Ctrl+C) or SIGTERM (termination)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Block main goroutine until a signal is received
	<-signalChan

	// --- Shutdown Sequence ---
	utils.InfoLogger.Println("--- Initiating Graceful Shutdown ---")

	// 1. Signal the transaction simulator goroutine to stop
	close(txSimulatorStopChan)

	// 2. Stop all nodes (signals their internal goroutines to stop and waits)
	utils.InfoLogger.Println("Stopping nodes...")
	for _, node := range nodes {
		node.Stop() // This calls wg.Wait() internally, ensuring node loop finishes
	}

	// 3. Unregister nodes from the network simulation hub
	// (Done here because Node.Stop doesn't have access to the Network object anymore)
	utils.InfoLogger.Println("Unregistering nodes...")
	for _, node := range nodes {
		network.UnregisterNode(node.ID) // Call network method directly
	}

	// 4. Close the log file handle
	utils.CloseLogFile()

	// Note: This final log message might not appear in the console if stdout buffer
	// isn't flushed before exit, and won't appear in the file as it's closed.
	fmt.Println("--- Simulation Finished ---")
	// utils.InfoLogger.Println("--- Simulation Finished ---") // Use fmt for final message
}