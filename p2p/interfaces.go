package p2p

import "blockchain/core"

// NetworkBroadcaster defines the methods a Node needs to broadcast messages.
// This interface is implemented by the p2p.Network struct.
type NetworkBroadcaster interface {
	BroadcastTransaction(sender *Node, tx *core.Transaction)
	BroadcastBlock(sender *Node, block *core.Block)
    // Potentially add methods like:
    // SendDirectMessage(targetID string, msg interface{}) error
}

// NodeHandler defines methods required to handle incoming messages.
// This interface would be implemented by p2p.Node. The Network uses this
// to deliver messages without needing the full concrete Node type (if we went that route).
// type NodeHandler interface {
//    HandleTransaction(tx *core.Transaction)
//    HandleBlock(block *core.Block)
//    ID() string // Network needs ID to route messages
// }