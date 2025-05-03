package crypto

import (
	"bytes"
	"fmt"

	"blockchain/utils" // For logger and hashing
)

// --- Simulated VRF ---
// WARNING: This is NOT a secure VRF implementation. It uses simple hashing
// for demonstration purposes only. A real VRF requires complex cryptography
// (e.g., based on elliptic curves and pairings or RSA).

// EvaluateVRF simulates VRF evaluation.
// Output is pseudorandom based on key and input. Proof is simple hash.
func EvaluateVRF(privKey *PrivateKey, input []byte) (output []byte, proof []byte, err error) {
	if privKey == nil || privKey.PrivateKey == nil {
		return nil, nil, fmt.Errorf("VRF evaluation requires a valid private key")
	}
	if input == nil {
		return nil, nil, fmt.Errorf("VRF evaluation requires non-nil input")
	}

	// Combine private key material and input for "randomness"
	// IMPORTANT: Directly hashing priv.D is insecure, just for simulation.
	seedMaterial := append(privKey.D.Bytes(), input...)
	output = utils.CalculateHash(seedMaterial) // H(privKey | input)

	// Create a simple "proof" - H(output | input)
	proofMaterial := append(output, input...)
	proof = utils.CalculateHash(proofMaterial)

	utils.DebugLogger.Printf("[VRF Sim] Evaluate(input: %x...) -> output: %x..., proof: %x...", input[:minInt(4, len(input))], output[:4], proof[:4])
	return output, proof, nil
}

// VerifyVRF simulates VRF proof verification.
// It checks if the proof matches the expected hash based on output and input.
// It includes a superficial check involving the public key for interface matching.
func VerifyVRF(pubKey *PublicKey, input, output, proof []byte) bool {
	if pubKey == nil || pubKey.PublicKey == nil || input == nil || output == nil || proof == nil {
		utils.WarnLogger.Printf("[VRF Sim] Verify called with nil arguments.")
		return false
	}

	// 1. Recalculate the expected proof hash: H(output | input)
	expectedProofMaterial := append(output, input...)
	expectedProofHash := utils.CalculateHash(expectedProofMaterial)

	// 2. Check if the calculated hash matches the provided proof
	proofIsValid := bytes.Equal(expectedProofHash, proof)

	// 3. Superficial check involving public key (NOT cryptographically meaningful)
	// Example: check H(pubKeyBytes | expectedProofHash) == H(pubKeyBytes | proof)
	pubKeyBytes := pubKey.Bytes()
	// Handle nil pubKeyBytes (shouldn't happen if pubKey validation passed)
	if pubKeyBytes == nil {
	    utils.WarnLogger.Println("[VRF Sim] Verify failed: Could not get public key bytes.")
	    return false
	}
	checkHash1 := utils.CalculateHash(append(pubKeyBytes, expectedProofHash...))
	checkHash2 := utils.CalculateHash(append(pubKeyBytes, proof...))
	pubKeyCheck := bytes.Equal(checkHash1, checkHash2)

	isValid := proofIsValid && pubKeyCheck

	if !isValid {
	    utils.DebugLogger.Printf("[VRF Sim] Verify(input: %x..., output: %x..., proof: %x...) FAILED. proofCheck: %v, pubKeyCheck: %v", input[:minInt(4, len(input))], output[:4], proof[:4], proofIsValid, pubKeyCheck)
	} else {
        utils.DebugLogger.Printf("[VRF Sim] Verify(input: %x..., output: %x...) SUCCEEDED.", input[:minInt(4, len(input))], output[:4])
    }

	return isValid
}

// Helper for safe slicing in logs
func minInt(a, b int) int {
	if a < b { return a }
	return b
}