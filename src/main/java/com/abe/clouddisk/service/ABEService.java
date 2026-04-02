package com.abe.clouddisk.service;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;

/**
 * Service interface for Attribute-Based Encryption (ABE) operations.
 * Provides methods for system setup, key generation, encryption, decryption,
 * and hybrid encryption schemes.
 */
public interface ABEService {
    
    // --- Data Structures (Inner classes for simplicity, or can be moved to dto) ---
    
    /**
     * Container for ABE system keys, including public and master keys.
     */
    class ABEKeys {
        /** Generator element h in G1. */
        public Element h;
        /** Public key component e(g,g)^alpha. */
        public Element egg_alpha;
        /** Public key component g^beta. */
        public Element beta;
        /** Master key component alpha. */
        public Element alpha;
    }

    /**
     * Container for a user's ABE secret key.
     */
    class SecretKeyContainer {
        /** Secret key component D = g^((alpha + r) / beta). */
        public Element D;
        /** Secret key component D_r = g^r. */
        public Element D_r;
        /** List of attribute-specific secret key components. */
        public List<SKComponent> components = new ArrayList<>();
        
        /** @return Byte representation of D. */
        public byte[] getDBytes() { return D != null ? D.toBytes() : null; }
        /** @return Byte representation of D_r. */
        public byte[] getDrBytes() { return D_r != null ? D_r.toBytes() : null; }
    }

    /**
     * Represents a single attribute component within a secret key.
     */
    class SKComponent {
        /** The attribute name. */
        public String attribute;
    }

    /**
     * Container for an ABE encrypted session key (ciphertext).
     */
    class ABECiphertext {
        /** The session key encrypted via ABE. */
        public byte[] encryptedSessionKey;
        /** Ciphertext component C. */
        public Element C;
        /** Ciphertext component C_prime. */
        public Element C_prime;
        /** List of attribute-specific ciphertext components. */
        public List<CTComponent> components = new ArrayList<>();
        
        /** @return Byte representation of C. */
        public byte[] getCBytes() { return C != null ? C.toBytes() : null; }
        /** @return Byte representation of C_prime. */
        public byte[] getCPrimeBytes() { return C_prime != null ? C_prime.toBytes() : null; }
        
        /** Temporary storage for C bytes during serialization/deserialization. */
        public byte[] tempCBytes;
        /** Temporary storage for C_prime bytes during serialization/deserialization. */
        public byte[] tempCPrimeBytes;
    }

    /**
     * Represents a single attribute component within a ciphertext.
     */
    class CTComponent {
        /** The attribute name associated with this component. */
        public String attribute;
    }

    /**
     * Container for a hybrid ciphertext, combining ABE and AES.
     */
    class HybridCiphertext {
        /** The file data encrypted via AES. */
        public byte[] aesEncryptedFile;
        /** The AES session key encrypted via ABE. */
        public ABECiphertext abeEncryptedKey;
        /** The initialization vector (IV) used for AES encryption. */
        public byte[] iv; 
    }

    // --- Service Methods ---

    /**
     * Initializes the ABE system and generates global parameters.
     *
     * @return The generated ABE system keys.
     */
    ABEKeys setup();

    /**
     * Retrieves the current global ABE public keys.
     *
     * @return The global ABE public keys.
     */
    ABEKeys getGlobalKeys();

    /**
     * Reconstructs a JPBC Element from its byte representation.
     *
     * @param data  The byte array representing the element.
     * @param group The group the element belongs to (e.g., "G1", "Zr").
     * @return The reconstructed Element.
     */
    Element getElementFromBytes(byte[] data, String group);

    /**
     * Generates a secret key for a user with the specified attributes.
     *
     * @param attributes The array of attributes to be associated with the secret key.
     * @return The generated SecretKeyContainer.
     */
    SecretKeyContainer keygen(String[] attributes);

    /**
     * Encrypts a symmetric session key using ABE under a specified access policy.
     *
     * @param sessionKeyBytes The symmetric key to be encrypted.
     * @param policy          The access policy (array of required attributes).
     * @return The ABE ciphertext containing the encrypted session key.
     * @throws Exception If encryption fails.
     */
    ABECiphertext encryptSessionKey(byte[] sessionKeyBytes, String[] policy) throws Exception;

    /**
     * Decrypts an ABE ciphertext to recover the symmetric session key.
     *
     * @param sk         The user's ABE secret key.
     * @param ciphertext The ABE ciphertext to decrypt.
     * @return The recovered symmetric session key bytes, or null if decryption fails.
     * @throws Exception If decryption fails due to internal errors.
     */
    byte[] decryptSessionKey(SecretKeyContainer sk, ABECiphertext ciphertext) throws Exception;

    /**
     * Encrypts data using AES with the provided key and IV.
     *
     * @param data The data to encrypt.
     * @param key  The AES symmetric key.
     * @param iv   The initialization vector.
     * @return The AES encrypted data.
     * @throws Exception If AES encryption fails.
     */
    byte[] encryptAES(byte[] data, byte[] key, byte[] iv) throws Exception;

    /**
     * Decrypts AES encrypted data using the provided key and IV.
     *
     * @param encryptedData The data to decrypt.
     * @param key           The AES symmetric key.
     * @param iv            The initialization vector.
     * @return The decrypted data.
     * @throws Exception If AES decryption fails.
     */
    byte[] decryptAES(byte[] encryptedData, byte[] key, byte[] iv) throws Exception;

    /**
     * Performs hybrid encryption: encrypts a file with AES and the AES key with ABE.
     *
     * @param fileBytes    The file content to encrypt.
     * @param symmetricKey The AES key to use (will be encrypted with ABE).
     * @param policy       The ABE access policy.
     * @return A HybridCiphertext containing the encrypted file and encrypted key.
     * @throws Exception If encryption fails.
     */
    HybridCiphertext encryptFileHybrid(byte[] fileBytes, byte[] symmetricKey, String[] policy) throws Exception;

    /**
     * Decrypts a hybrid ciphertext by first recovering the AES key via ABE.
     *
     * @param hc             The hybrid ciphertext to decrypt.
     * @param userAttributes The attributes of the user attempting decryption.
     * @return The decrypted file content.
     * @throws Exception If decryption fails or attributes do not satisfy the policy.
     */
    byte[] decryptFileHybrid(HybridCiphertext hc, String[] userAttributes) throws Exception;
    
    /**
     * Checks if a set of user attributes satisfies a given access policy.
     *
     * @param policy         The access policy string.
     * @param userAttributes The user's attributes string.
     * @return true if the policy is satisfied, false otherwise.
     */
    boolean isPolicySatisfied(String policy, String userAttributes);
}
