package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"blockchain/utils" // Updated import path
)

// PrivateKey wraps ecdsa.PrivateKey for convenience.
type PrivateKey struct {
	*ecdsa.PrivateKey
}

// PublicKey wraps ecdsa.PublicKey for convenience.
type PublicKey struct {
	*ecdsa.PublicKey
}

var curve = elliptic.P256() // Use P256 curve

// GenerateKeyPair creates a new ECDSA key pair.
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &PrivateKey{priv}, &PublicKey{&priv.PublicKey}, nil
}

// PublicKeyToAddress converts a public key to a simple hex string address.
func (pub *PublicKey) Address() string {
	if pub == nil || pub.PublicKey == nil {
		return ""
	}
	// Use uncompressed format: 0x04 + X + Y
	pubBytes := elliptic.Marshal(curve, pub.X, pub.Y)
	// Hash the public key to get the address (common practice)
	// Use first 20 bytes of hash similar to Ethereum
	hash := utils.CalculateHash(pubBytes)
	return "0x" + hex.EncodeToString(hash[len(hash)-20:])
}

// Bytes returns the byte representation of the public key (uncompressed).
func (pub *PublicKey) Bytes() []byte {
    if pub == nil || pub.PublicKey == nil {
        return nil
    }
	return elliptic.Marshal(curve, pub.X, pub.Y)
}

// PublicKeyFromBytes reconstructs a public key from its byte representation.
func PublicKeyFromBytes(pubBytes []byte) (*PublicKey, error) {
	if len(pubBytes) == 0 {
		return nil, fmt.Errorf("empty public key bytes")
	}
	x, y := elliptic.Unmarshal(curve, pubBytes)
	if x == nil {
		return nil, fmt.Errorf("invalid public key bytes")
	}
	return &PublicKey{&ecdsa.PublicKey{Curve: curve, X: x, Y: y}}, nil
}


// Sign data using a private key. Returns ASN.1 encoded signature.
func (priv *PrivateKey) Sign(data []byte) ([]byte, error) {
	hash := utils.CalculateHash(data) // Hash the data first
	return ecdsa.SignASN1(rand.Reader, priv.PrivateKey, hash)
}

// Verify signature using a public key. Expects ASN.1 encoded signature.
func (pub *PublicKey) Verify(data []byte, signature []byte) bool {
    if pub == nil || pub.PublicKey == nil || len(signature) == 0 {
        return false
    }
	hash := utils.CalculateHash(data) // Hash the data first
	return ecdsa.VerifyASN1(pub.PublicKey, hash, signature)
}

// --- Simple Wallet for Demo ---
type Wallet struct {
	PrivateKey *PrivateKey
	PublicKey  *PublicKey
	Address    string
}

var (
	walletStore = make(map[string]*Wallet)
	walletMutex sync.RWMutex
)

// NewWallet creates and stores a new wallet.
func NewWallet() *Wallet {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		utils.ErrorLogger.Panicf("Failed to generate key pair: %v", err)
	}
	addr := pub.Address()
	w := &Wallet{
		PrivateKey: priv,
		PublicKey:  pub,
		Address:    addr,
	}
	walletMutex.Lock()
	walletStore[addr] = w
	walletMutex.Unlock()
	utils.InfoLogger.Printf("Created new wallet: %s", addr)
	return w
}

// GetWallet retrieves a wallet by address.
func GetWallet(address string) *Wallet {
	walletMutex.RLock()
	defer walletMutex.RUnlock()
	// Return a copy to prevent modification of the stored wallet?
	// For simplicity, return direct pointer. Be careful with concurrent access to Wallet fields if needed.
	return walletStore[address]
}

// GetAllWallets returns addresses of all created wallets (for debug/listing).
func GetAllWallets() []string {
    walletMutex.RLock()
    defer walletMutex.RUnlock()
    addrs := make([]string, 0, len(walletStore))
    for addr := range walletStore {
        addrs = append(addrs, addr)
    }
    return addrs
}