package utils

import (
	"crypto/sha256"
	"encoding/binary" // Added for shard hint calculation
	"encoding/hex"
    "fmt" // Added for error handling
)

// CalculateHash calculates the SHA256 hash of byte data.
func CalculateHash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// CalculateHashString calculates the SHA256 hash and returns it as a hex string.
func CalculateHashString(data []byte) string {
	return hex.EncodeToString(CalculateHash(data))
}

// CalculateShardHint determines the target shard (simple example).
// Moved here from core/transaction.go to break import cycle.
// Takes a key (e.g., address, data identifier) and the total number of shards.
// Returns the calculated shard ID (0 to numShards-1) and an error if issues occur.
func CalculateShardHint(key string, numShards uint32) (uint32, error) {
    if numShards == 0 {
         // Returning an error is generally better than panicking here,
         // as initialization order might affect logger availability.
         return 0, fmt.Errorf("number of shards cannot be zero")
    }
	// Simple hash-based sharding: Hash the key
	h := CalculateHash([]byte(key)) // Use CalculateHash from this package

	// Use the first 4 bytes of the hash to determine shard ID consistently
	if len(h) < 4 {
        // This is highly unlikely with SHA256 but handle defensively.
        err := fmt.Errorf("hash too short (%d bytes) for shard hint calculation for key '%s'", len(h), key)
        // Log the error if logger is available, but still return the error.
        // ErrorLogger might not be ready if called very early.
        // ErrorLogger.Printf("%v. Defaulting to shard 0.", err)
        return 0, err // Return the error, let caller decide how to handle
    }

	// Convert first 4 bytes to uint32 using binary package for deterministic encoding (LittleEndian)
	shardIDIntermediate := binary.LittleEndian.Uint32(h[:4])

    // Modulo operation to map the hash value to a valid shard ID
	shardID := shardIDIntermediate % numShards

	return shardID, nil // Return calculated shard ID and nil error
}