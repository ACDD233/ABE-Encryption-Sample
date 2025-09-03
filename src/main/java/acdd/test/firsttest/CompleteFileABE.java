package acdd.test.firsttest;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class CompleteFileABE {

    private Pairing pairing;
    private Element g;

    // --- Data Structures ---

    /**
     * Holds the master keys and public keys for the ABE system.
     */
    public static class ABEKeys {
        // Public Key (PK)
        Element h;         // Represents g^beta
        Element egg_alpha; // Represents the pre-computed pairing e(g,g)^alpha

        // Master Secret Key (MSK) - MUST be kept secret
        Element beta;      // A random exponent from Zr
        Element alpha;     // A random exponent from Zr
    }

    /**
     * A container for a user's secret key, which is generated based on their attributes.
     */
    public static class SecretKeyContainer {
        Element D; // Main secret key component: g^((alpha+r)/beta)
        Element D_r; // Helper component g^r, used to simplify decryption calculations
        List<SKComponent> components = new ArrayList<>(); // List of attribute-specific components
    }

    /**
     * Represents a single attribute within a user's secret key.
     * In a more complex scheme, this would hold cryptographic elements specific to the attribute.
     */
    public static class SKComponent {
        String attribute;
    }

    /**
     * A container for the ABE ciphertext, which encrypts the symmetric session key.
     */
    public static class ABECiphertext {
        byte[] encryptedSessionKey; // The AES session key, masked by the ABE scheme
        Element C;       // Ciphertext component: h^s = g^(beta*s)
        Element C_prime; // Ciphertext component: g^s
        List<CTComponent> components = new ArrayList<>(); // List of policy attribute components
    }

    /**
     * Represents a single attribute in the access policy of a ciphertext.
     */
    public static class CTComponent {
        String attribute;
    }

    /**
     * The final output of the encryption process, containing both the AES-encrypted file
     * and the ABE-encrypted key needed to decrypt it.
     */
    public static class HybridCiphertext {
        byte[] aesEncryptedFile;
        ABECiphertext abeEncryptedKey;
        byte[] iv; // Initialization Vector for AES/GCM decryption
    }

    // --- Core ABE Methods ---

    /**
     * Sets up the entire ABE system. It generates the public parameters (PK)
     * and the master secret key (MSK). This is done only once.
     * @return An ABEKeys object containing the PK and MSK.
     */
    public ABEKeys setup() {
        // Generate curve parameters for a Type A pairing
        TypeACurveGenerator gen = new TypeACurveGenerator(160, 512);
        PairingParameters params = gen.generate();
        this.pairing = PairingFactory.getPairing(params);

        // g is a generator for the group G1
        this.g = pairing.getG1().newRandomElement().getImmutable();

        // alpha and beta are the two master secrets, chosen randomly from the exponent field Zr
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();

        ABEKeys keys = new ABEKeys();
        // --- Populate the Public Key (PK) ---
        // h = g^beta
        keys.h = g.powZn(beta).getImmutable();
        // Temporarily compute g^alpha
        Element g_alpha = g.powZn(alpha).getImmutable();
        // Pre-compute e(g, g)^alpha for efficiency in encryption/decryption
        keys.egg_alpha = pairing.pairing(g, g_alpha).getImmutable();

        // --- Populate the Master Secret Key (MSK) ---
        keys.beta = beta;
        keys.alpha = alpha; // Store alpha and beta directly in the MSK

        System.out.println("System setup complete.");
        return keys;
    }

    /**
     * Generates a secret key for a user based on a set of attributes they possess.
     * @param msk The Master Secret Key.
     * @param attributes The list of attributes for this user.
     * @return A SecretKeyContainer holding the user's personalized key.
     */
    public SecretKeyContainer keygen(ABEKeys msk, String[] attributes) {
        SecretKeyContainer sk = new SecretKeyContainer();
        // r is a random exponent, unique for each user's key, to blind the MSK
        Element r = pairing.getZr().newRandomElement().getImmutable();

        // Perform calculations in the exponent field Zr: (alpha + r)
        Element alpha_plus_r = msk.alpha.duplicate().add(r);
        // Calculate the modular inverse of beta: 1/beta
        Element beta_inv = msk.beta.duplicate().invert().getImmutable();

        // Calculate the main secret key component: D = g^((alpha + r) / beta)
        sk.D = g.powZn(alpha_plus_r.mul(beta_inv)).getImmutable();
        // Store a helper component g^r, which will be used to cancel the 'r' term during decryption
        sk.D_r = g.powZn(r).getImmutable();

        for (String attribute : attributes) {
            sk.components.add(new SKComponent() {
            });
        }
        System.out.println("Secret Key generated for attributes: " + Arrays.toString(attributes));
        return sk;
    }

    /**
     * Performs hybrid encryption. The file data is encrypted with a fast symmetric key (AES),
     * and the AES key is then encrypted using the ABE scheme.
     * @param pk The Public Key.
     * @param fileData The raw byte data of the file to encrypt.
     * @param policy An array of attributes defining the access policy.
     * @return A HybridCiphertext object containing the complete encrypted package.
     */
    public HybridCiphertext encryptFile(ABEKeys pk, byte[] fileData, String[] policy) throws Exception {
        System.out.println("Encrypting file with policy: " + Arrays.toString(policy));

        // --- 1. Symmetric Encryption (AES-GCM) ---
        // Generate a random, single-use AES-256 session key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey sessionKey = keyGen.generateKey();

        // Generate a random Initialization Vector (IV) for GCM mode
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        // Encrypt the file data using the session key and AES/GCM
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(128, iv));
        byte[] encryptedFileData = aesCipher.doFinal(fileData);

        // --- 2. Attribute-Based Encryption of the Session Key ---
        // 's' is a random secret exponent, unique for this encryption instance
        Element s = pairing.getZr().newRandomElement().getImmutable();
        // Calculate the ABE masking key: K_tilde = e(g,g)^(alpha*s)
        Element K_tilde = pk.egg_alpha.powZn(s).getImmutable();

        // Mask the AES session key by XORing it with a key derived from K_tilde
        byte[] sessionKeyBytes = sessionKey.getEncoded();
        byte[] maskingKey = sha256(K_tilde.toBytes());
        byte[] encryptedSessionKeyBytes = new byte[sessionKeyBytes.length];
        for (int i = 0; i < sessionKeyBytes.length; i++) {
            encryptedSessionKeyBytes[i] = (byte) (sessionKeyBytes[i] ^ maskingKey[i]);
        }

        // --- 3. Construct the ABE Ciphertext ---
        ABECiphertext abeCiphertext = new ABECiphertext();
        abeCiphertext.encryptedSessionKey = encryptedSessionKeyBytes;
        // C = h^s = (g^beta)^s = g^(beta*s)
        abeCiphertext.C = pk.h.powZn(s).getImmutable();
        // C' = g^s
        abeCiphertext.C_prime = g.powZn(s).getImmutable();
        for (String attribute : policy) {
            abeCiphertext.components.add(new CTComponent() {
            });
        }

        // --- 4. Assemble the final hybrid ciphertext ---
        HybridCiphertext finalCiphertext = new HybridCiphertext();
        finalCiphertext.aesEncryptedFile = encryptedFileData;
        finalCiphertext.abeEncryptedKey = abeCiphertext;
        finalCiphertext.iv = iv;
        return finalCiphertext;
    }

    /**
     * Decrypts a hybrid ciphertext. It first uses the ABE secret key to recover the
     * symmetric session key, then uses that key to decrypt the file.
     * @param pk The Public Key (not used in decryption but included for completeness).
     * @param sk The user's Secret Key.
     * @param ciphertext The Hybrid Ciphertext to decrypt.
     * @return The decrypted file data as a byte array, or null if decryption fails.
     */
    public byte[] decryptFile(ABEKeys pk, SecretKeyContainer sk, HybridCiphertext ciphertext) throws Exception {
        System.out.println("Attempting cryptographic decryption with user's attributes...");

        // First, perform a non-cryptographic check to see if the user's key has all the attributes required by the policy.
        for (CTComponent ctComp : ciphertext.abeEncryptedKey.components) {
            boolean hasAttribute = false;
            for(SKComponent skComp : sk.components) {
                if(Objects.equals(skComp.attribute, ctComp.attribute)) {
                    hasAttribute = true;
                    break;
                }
            }
            // If an attribute is missing, decryption is impossible.
            if (!hasAttribute) {
                System.out.println("   ABE Decryption Failed: User lacks attribute '" + ctComp.attribute + "'");
                return null;
            }
        }

        // Extract the necessary components from the ciphertext and secret key
        Element C = ciphertext.abeEncryptedKey.C;
        Element C_prime = ciphertext.abeEncryptedKey.C_prime;
        Element D = sk.D;
        Element D_r = sk.D_r;

        // --- 1. ABE Decryption: Reconstruct K_tilde using pairing operations ---
        // This is the core of the ABE decryption.
        // Calculate the numerator: e(C, D) = e(g^(beta*s), g^((alpha+r)/beta)) = e(g,g)^(s*(alpha+r))
        Element numerator = pairing.pairing(C, D);
        // Calculate the denominator: e(C', D_r) = e(g^s, g^r) = e(g,g)^(s*r)
        Element denominator = pairing.pairing(C_prime, D_r);

        // Divide the numerator by the denominator. This cancels out the random 'r' term:
        // e(g,g)^(s*(alpha+r)) / e(g,g)^(s*r)  =  e(g,g)^(s*alpha)
        // The result is the original K_tilde.
        Element K_tilde_reconstructed = numerator.div(denominator);

        // --- 2. Recover the AES Session Key ---
        // Use the reconstructed K_tilde to derive the same masking key used during encryption.
        byte[] maskingKey = sha256(K_tilde_reconstructed.toBytes());
        byte[] encryptedSessionKey = ciphertext.abeEncryptedKey.encryptedSessionKey;
        byte[] sessionKeyBytes = new byte[encryptedSessionKey.length];
        // Reverse the XOR operation to unmask the session key.
        for (int i = 0; i < encryptedSessionKey.length; i++) {
            sessionKeyBytes[i] = (byte) (encryptedSessionKey[i] ^ maskingKey[i]);
        }
        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");

        // --- 3. Decrypt the File Data ---
        // Use the recovered session key to decrypt the actual file content.
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(128, ciphertext.iv));
        System.out.println("   Cryptographic recovery successful. Decrypting file...");
        return aesCipher.doFinal(ciphertext.aesEncryptedFile);
    }

    // --- Helper methods ---

    /**
     * A helper function to hash a string to a SHA-256 byte array.
     */
    private static byte[] sha256(byte[] in) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(in);
    }

    // --- Main method for testing ---
    public static void main(String[] args) throws Exception {
        CompleteFileABE abe = new CompleteFileABE();

        // 1. Setup the system
        ABEKeys keys = abe.setup();

        // 2. Create a dummy file to encrypt
        String originalContent = "This is the top secret strategy for Project Phoenix, dated " + java.time.LocalDate.now() + ".";
        Path originalFilePath = Paths.get("project_phoenix.txt");
        Files.writeString(originalFilePath, originalContent);
        System.out.println("Created original file: " + originalFilePath);

        // 3. Define an access policy for the file
        String[] filePolicy = {"PROJECT_PHOENIX", "LEAD_ENGINEER"};
        byte[] fileBytes = Files.readAllBytes(originalFilePath);

        // 4. Encrypt the file with the defined policy
        HybridCiphertext encryptedPackage = abe.encryptFile(keys, fileBytes, filePolicy);
        Files.write(Paths.get("project_phoenix.encrypted.txt"), encryptedPackage.aesEncryptedFile);

        // 5. --- SCENARIO 1: An authorized user tries to decrypt ---
        System.out.println("\n--- SCENARIO 1: Authorized user attempts decryption ---");
        String[] authorizedUserAttrs = {"LEAD_ENGINEER", "PROJECT_PHOENIX", "SECURITY_CLEARANCE_5"};
        // Generate a key for the authorized user
        SecretKeyContainer authorizedUserKey = abe.keygen(keys, authorizedUserAttrs);
        // Attempt decryption
        byte[] decryptedBytes = abe.decryptFile(keys, authorizedUserKey, encryptedPackage);

        if (decryptedBytes != null) {
            Path decryptedFilePath = Paths.get("project_phoenix_decrypted.txt");
            Files.write(decryptedFilePath, decryptedBytes);
            System.out.println("   Decrypted file saved to: " + decryptedFilePath);
            System.out.println("   Content: '" + new String(decryptedBytes, StandardCharsets.UTF_8) + "'");
        } else {
            System.out.println("   Decryption failed for authorized user. (Error)");
        }

        // 6. --- SCENARIO 2: An unauthorized user tries to decrypt ---
        System.out.println("\n--- SCENARIO 2: Unauthorized user attempts decryption ---");
        String[] unauthorizedUserAttrs = {"JUNIOR_ENGINEER", "PROJECT_PHOENIX"};
        // Generate a key for the unauthorized user
        SecretKeyContainer unauthorizedUserKey = abe.keygen(keys, unauthorizedUserAttrs);
        // Attempt decryption
        byte[] failedDecryptionBytes = abe.decryptFile(keys, unauthorizedUserKey, encryptedPackage);

        if (failedDecryptionBytes == null) {
            System.out.println("   As expected, access was denied because the user is not a 'LEAD_ENGINEER'.");
        } else {
            System.out.println("   Decryption succeeded for unauthorized user. (Error)");
        }
    }
}