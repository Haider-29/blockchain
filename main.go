package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"blockchain/core"
	"blockchain/crypto"
	"blockchain/p2p"
	"blockchain/state"
	"blockchain/utils"
)

func main() {
	os.Setenv("LOG_LEVEL", "DEBUG") // Set default to DEBUG for detailed logs
	utils.InfoLogger.Println("--- Starting Simplified Blockchain Simulation ---")

	// --- Configuration ---
	numNodes := 5
	numValidators := 4           // CHANGED TO 4 (Minimum for f=1 BFT threshold)
	blockTime := 3 * time.Second
    rand.Seed(time.Now().UnixNano())

	// Basic configuration validation
	if numValidators < 4 { // Enforce minimum for BFT simulation
		utils.ErrorLogger.Fatal("Number of validators must be at least 4 for f=1 BFT.")
	}
	if numValidators > numNodes {
		utils.ErrorLogger.Fatal("Number of validators cannot exceed number of nodes.")
	}

	// --- Setup Validators ---
	validatorWallets := make([]*crypto.Wallet, numValidators)
	validatorAddrs := make([]string, numValidators)
	utils.InfoLogger.Printf("Creating %d Validator Wallets...", numValidators)
	for i := 0; i < numValidators; i++ {
		wallet := crypto.NewWallet()
		validatorWallets[i] = wallet
		validatorAddrs[i] = wallet.Address
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
		nodePrefix := "Node"
		if isValidator { nodePrefix = "Validator" }
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
	txSimulatorStopChan := make(chan struct{})
	go func() {
		defer utils.InfoLogger.Println("Transaction simulator loop exited.")
		if numNodes == 0 { return }
		senderNodeIndex := rand.Intn(numNodes)
		senderWallet := nodes[senderNodeIndex].Wallet
		senderNode := nodes[senderNodeIndex]
		utils.InfoLogger.Printf("Transaction simulator using sender: %s (%s)", senderNode.ID, senderWallet.Address)
		nonceMap := make(map[string]uint64)
		senderAddr := senderWallet.Address
		nonceMap[senderAddr] = 0
		var numShards uint32 = state.NUM_SHARDS
		if len(nodes) > 0 && nodes[0].Blockchain != nil {
			fetchedNumShards := nodes[0].Blockchain.GetNumShards()
			if fetchedNumShards > 0 { numShards = fetchedNumShards
			} else { if numShards > 0 { utils.WarnLogger.Printf("Warning: GetNumShards returned 0, falling back to state.NUM_SHARDS (%d)", numShards) } }
		} else if len(nodes) == 0 { utils.WarnLogger.Printf("Warning: No nodes available, using default shard count: %d", numShards)
		} else { utils.WarnLogger.Printf("Warning: Node 0 or blockchain nil, using default shard count: %d", numShards) }
		if numShards == 0 { utils.ErrorLogger.Fatal("Cannot proceed: Effective number of shards is zero.") }
		utils.InfoLogger.Printf("Transaction simulator using Number of Shards: %d", numShards)
		for {
			select {
			case <-txSimulatorStopChan: utils.InfoLogger.Println("Stopping transaction simulator."); return
			case <-time.After(time.Duration(rand.Intn(1500)+500) * time.Millisecond):
				recipientNodeIndex := rand.Intn(numNodes); recipientAddr := nodes[recipientNodeIndex].Wallet.Address
				value := uint64(rand.Intn(100) + 1); data := []byte(fmt.Sprintf("Payload from %s @ %d", senderNode.ID, time.Now().Unix()))
				currentNonce := nonceMap[senderAddr]
				tx, err := core.NewTransaction(senderWallet, recipientAddr, value, currentNonce, data, numShards)
				if err != nil { utils.ErrorLogger.Printf("[%s] Simulator: Failed to create transaction (Nonce: %d): %v", senderNode.ID, currentNonce, err); continue }
				utils.InfoLogger.Printf("==> [%s] Created Tx: %s... (To: %s..., Nonce: %d, Shard: %d)", senderNode.ID, hex.EncodeToString(tx.ID[:4]), recipientAddr[:8], tx.Nonce, tx.ShardHint)
				network.BroadcastTransaction(senderNode, tx) // Broadcast to all nodes
				nonceMap[senderAddr] = currentNonce + 1 // Increment after attempting broadcast
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
	for _, node := range nodes { node.Stop() }
	utils.InfoLogger.Println("Unregistering nodes...")
	for _, node := range nodes { network.UnregisterNode(node.ID) }
	utils.CloseLogFile()
	fmt.Println("--- Simulation Finished ---")
}