package p2p

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"blockchain/core" // Network needs core types for broadcasted items
	"blockchain/utils"
	// We DO import node.go here because Network holds concrete Nodes
	// and needs the Node type definition for its map and method arguments.
)


// --- Network Implementation ---

// Network simulates the P2P network connecting nodes.
// It holds concrete node pointers for message delivery simulation.
type Network struct {
	nodes map[string]*Node // Map Node ID -> concrete Node instance
	lock  sync.RWMutex     // Protects the nodes map
}

// Compile-time check to ensure *Network implements NetworkBroadcaster
// This requires the methods below (BroadcastTransaction, BroadcastBlock)
// to match the interface signature exactly.
var _ NetworkBroadcaster = (*Network)(nil)

// NewNetwork creates a simulated network.
func NewNetwork() *Network {
	return &Network{
		nodes: make(map[string]*Node), // Initialize the map
	}
}

// RegisterNode adds a node to the network simulation.
// Takes concrete *Node for simulation purposes.
func (net *Network) RegisterNode(node *Node) error {
	if node == nil || node.ID == "" {
		return fmt.Errorf("cannot register nil node or node with empty ID")
	}
	net.lock.Lock()
	defer net.lock.Unlock()
	if _, exists := net.nodes[node.ID]; exists { // Use lowercase 'nodes' field
		utils.WarnLogger.Printf("Node %s already registered in network.", node.ID)
		return fmt.Errorf("node %s already registered", node.ID)
	}
	net.nodes[node.ID] = node // Use lowercase 'nodes' field
	utils.InfoLogger.Printf("Network: Registered node %s (Total: %d)", node.ID, len(net.nodes)) // Use lowercase 'nodes' field
	return nil
}

// UnregisterNode removes a node (e.g., on shutdown).
func (net *Network) UnregisterNode(nodeID string) {
	net.lock.Lock()
	defer net.lock.Unlock()
	if _, exists := net.nodes[nodeID]; exists { // Use lowercase 'nodes' field
		delete(net.nodes, nodeID) // Use lowercase 'nodes' field
		utils.InfoLogger.Printf("Network: Unregistered node %s (Total: %d)", nodeID, len(net.nodes)) // Use lowercase 'nodes' field
	}
}

// BroadcastTransaction sends a transaction to all *other* nodes in the network simulation.
// Implements NetworkBroadcaster interface method.
func (net *Network) BroadcastTransaction(senderNode *Node, tx *core.Transaction) { // Matches interface
	net.lock.RLock()
	nodesSnapshot := make([]*Node, 0, len(net.nodes)) // Use lowercase 'nodes' field
    for _, node := range net.nodes { // Use lowercase 'nodes' field
        nodesSnapshot = append(nodesSnapshot, node)
    }
	net.lock.RUnlock()

	if senderNode == nil { utils.WarnLogger.Println("Network: BroadcastTransaction called with nil sender."); return }
	if tx == nil || tx.ID == nil { utils.WarnLogger.Println("Network: Attempted to broadcast nil transaction or transaction with nil ID."); return }
	utils.DebugLogger.Printf("Network: Broadcasting Tx %x from %s...", tx.ID[:4], senderNode.ID)

	for _, node := range nodesSnapshot {
		if node.ID == senderNode.ID { continue } // Don't send back to sender
		go func(receiverNode *Node, transactionToSend *core.Transaction) {
			delay := time.Duration(rand.Intn(45)+5) * time.Millisecond
			time.Sleep(delay)
			// We need the concrete node to call its handler method
			receiverNode.HandleTransaction(transactionToSend)
		}(node, tx)
	}
}

// BroadcastBlock sends a block to all *other* nodes in the network simulation.
// Implements NetworkBroadcaster interface method.
func (net *Network) BroadcastBlock(senderNode *Node, block *core.Block) { // Matches interface
	net.lock.RLock()
    nodesSnapshot := make([]*Node, 0, len(net.nodes)) // Use lowercase 'nodes' field
    for _, node := range net.nodes { // Use lowercase 'nodes' field
        nodesSnapshot = append(nodesSnapshot, node)
    }
	net.lock.RUnlock()

	if senderNode == nil { utils.WarnLogger.Println("Network: BroadcastBlock called with nil sender."); return }
	if block == nil || block.Hash == nil { utils.WarnLogger.Println("Network: Attempted to broadcast nil block or block with nil hash."); return }
	utils.InfoLogger.Printf("Network: Broadcasting Block %d (%x...) from %s", block.Header.Height, block.Hash[:6], senderNode.ID)

	for _, node := range nodesSnapshot {
		if node.ID == senderNode.ID { continue } // Don't send block back to self
		go func(receiverNode *Node, blockToSend *core.Block) {
			delay := time.Duration(rand.Intn(90)+10) * time.Millisecond
			time.Sleep(delay)
			// We need the concrete node to call its handler method
			receiverNode.HandleBlock(blockToSend)
		}(node, block)
	}
}


// --- REMOVE DUPLICATED CODE ---
// // Network struct holds concrete nodes for simulation
// type Network struct { /* ... */ } // DUPLICATE REMOVED
// // NewNetwork creates a simulated network.
// func NewNetwork() *Network { /* ... */ } // DUPLICATE REMOVED
// // RegisterNode adds a node ...
// func (net *Network) RegisterNode(...) error { /* ... */ } // DUPLICATE REMOVED
// // UnregisterNode removes a node ...
// func (net *Network) UnregisterNode(...) { /* ... */ } // DUPLICATE REMOVED
// // BroadcastTransaction sends a transaction ...
// func (net *Network) BroadcastTransaction(...) { /* ... */ } // DUPLICATE REMOVED
// // BroadcastBlock sends a block ...
// func (net *Network) BroadcastBlock(...) { /* ... */ } // DUPLICATE REMOVED