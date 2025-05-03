package p2p

import (
	"fmt"          // <--- ADDED
	"math/rand"    // <--- ADDED
	"sync"
	"time"

	"blockchain/core"
	"blockchain/utils"
)

// Network simulates the P2P network connecting nodes.
type Network struct {
	Nodes map[string]*Node // Map Node ID -> Node instance (for simulation)
	lock  sync.RWMutex     // Protects the Nodes map
}

// NewNetwork creates a simulated network.
func NewNetwork() *Network {
	return &Network{
		Nodes: make(map[string]*Node),
	}
}

// RegisterNode adds a node to the network simulation.
func (net *Network) RegisterNode(node *Node) error {
    if node == nil || node.ID == "" {
        return fmt.Errorf("cannot register nil node or node with empty ID") // <--- Use fmt
    }
	net.lock.Lock()
	defer net.lock.Unlock()
	if _, exists := net.Nodes[node.ID]; exists {
		utils.WarnLogger.Printf("Node %s already registered in network.", node.ID)
		return fmt.Errorf("node %s already registered", node.ID) // <--- Use fmt
	}
	net.Nodes[node.ID] = node
	utils.InfoLogger.Printf("Network: Registered node %s (Total: %d)", node.ID, len(net.Nodes))
    return nil
}

// UnregisterNode removes a node (e.g., on shutdown).
func (net *Network) UnregisterNode(nodeID string) {
    net.lock.Lock()
    defer net.lock.Unlock()
    if _, exists := net.Nodes[nodeID]; exists {
        delete(net.Nodes, nodeID)
        utils.InfoLogger.Printf("Network: Unregistered node %s (Total: %d)", nodeID, len(net.Nodes))
    }
}


// BroadcastTransaction sends a transaction to all *other* nodes in the network simulation.
func (net *Network) BroadcastTransaction(sender *Node, tx *core.Transaction) {
	net.lock.RLock() // Read lock is sufficient for iterating map
	nodesSnapshot := make([]*Node, 0, len(net.Nodes))
    for _, node := range net.Nodes {
        nodesSnapshot = append(nodesSnapshot, node)
    }
	net.lock.RUnlock() // Release lock quickly

    if tx == nil || tx.ID == nil {
        utils.WarnLogger.Println("Network: Attempted to broadcast nil transaction or transaction with nil ID.")
        return
    }
	utils.DebugLogger.Printf("Network: Broadcasting Tx %x from %s...", tx.ID[:4], sender.ID)

	for _, node := range nodesSnapshot {
		if node.ID == sender.ID {
			continue // Don't send back to sender
		}
		// Simulate network delay/async processing by launching goroutine
		go func(receiverNode *Node, transactionToSend *core.Transaction) {
			// Add random delay? E.g., 5-50ms
			delay := time.Duration(rand.Intn(45)+5) * time.Millisecond // <--- Use rand
			time.Sleep(delay) // Simulate network latency
			receiverNode.HandleTransaction(transactionToSend) // Call the node's handler
		}(node, tx) // Pass copies to goroutine
	}
}

// BroadcastBlock sends a block to all *other* nodes in the network simulation.
func (net *Network) BroadcastBlock(sender *Node, block *core.Block) {
	net.lock.RLock()
    nodesSnapshot := make([]*Node, 0, len(net.Nodes))
    for _, node := range net.Nodes {
        nodesSnapshot = append(nodesSnapshot, node)
    }
	net.lock.RUnlock()

    if block == nil || block.Hash == nil {
         utils.WarnLogger.Println("Network: Attempted to broadcast nil block or block with nil hash.")
        return
    }
	utils.InfoLogger.Printf("Network: Broadcasting Block %d (%x...) from %s", block.Header.Height, block.Hash[:6], sender.ID)

	for _, node := range nodesSnapshot {
		if node.ID == sender.ID {
			// Include self for testing idempotency? Let's skip self for blocks usually.
            continue
		}
		// Simulate network delay/async processing
		go func(receiverNode *Node, blockToSend *core.Block) {
			// Add random delay? E.g., 10-100ms (blocks are larger)
            delay := time.Duration(rand.Intn(90)+10) * time.Millisecond // <--- Use rand
			time.Sleep(delay) // Simulate network latency
			receiverNode.HandleBlock(blockToSend) // Call the node's handler
		}(node, block) // Pass copies to goroutine
	}
}