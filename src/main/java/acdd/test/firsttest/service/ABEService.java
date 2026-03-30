package acdd.test.firsttest.service;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;

public interface ABEService {
    
    // --- Data Structures (Inner classes for simplicity, or can be moved to dto) ---
    
    class ABEKeys {
        public Element h;
        public Element egg_alpha;
        public Element beta;
        public Element alpha;
    }

    class SecretKeyContainer {
        public Element D;
        public Element D_r;
        public List<SKComponent> components = new ArrayList<>();
        public byte[] getDBytes() { return D != null ? D.toBytes() : null; }
        public byte[] getDrBytes() { return D_r != null ? D_r.toBytes() : null; }
    }

    class SKComponent {
        public String attribute;
    }

    class ABECiphertext {
        public byte[] encryptedSessionKey;
        public Element C;
        public Element C_prime;
        public List<CTComponent> components = new ArrayList<>();
        public byte[] getCBytes() { return C != null ? C.toBytes() : null; }
        public byte[] getCPrimeBytes() { return C_prime != null ? C_prime.toBytes() : null; }
        public byte[] tempCBytes;
        public byte[] tempCPrimeBytes;
    }

    class CTComponent {
        public String attribute;
    }

    class HybridCiphertext {
        public byte[] aesEncryptedFile;
        public ABECiphertext abeEncryptedKey;
        public byte[] iv; 
    }

    // --- Service Methods ---

    ABEKeys setup();

    ABEKeys getGlobalKeys();
    Element getElementFromBytes(byte[] data, String group);
    SecretKeyContainer keygen(String[] attributes);
    ABECiphertext encryptSessionKey(byte[] sessionKeyBytes, String[] policy) throws Exception;
    byte[] decryptSessionKey(SecretKeyContainer sk, ABECiphertext ciphertext) throws Exception;
    byte[] encryptAES(byte[] data, byte[] key, byte[] iv) throws Exception;
    byte[] decryptAES(byte[] encryptedData, byte[] key, byte[] iv) throws Exception;
    HybridCiphertext encryptFileHybrid(byte[] fileBytes, byte[] symmetricKey, String[] policy) throws Exception;
    byte[] decryptFileHybrid(HybridCiphertext hc, String[] userAttributes) throws Exception;
}
