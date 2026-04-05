package com.abe.clouddisk.service.impl;

import com.abe.clouddisk.entity.SystemKey;
import com.abe.clouddisk.mapper.SystemKeyMapper;
import com.abe.clouddisk.service.ABEService;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Implementation of the {@link ABEService} providing concrete logic for Attribute-Based Encryption.
 * This implementation uses the JPBC library for bilinear pairings and AES/GCM for symmetric encryption.
 */
@Slf4j
@Service
public class ABEServiceImpl implements ABEService {

    /** The pairing object used for elliptic curve operations. */
    private Pairing pairing;
    /** Parameters defining the elliptic curve and pairing. */
    private PairingParameters pairingParameters;
    /** Global generator element g in G1. */
    private Element g;
    /** Global ABE system keys (public and master). */
    private ABEKeys globalKeys;

    /** Mapper for persisting and retrieving system keys. */
    @Autowired
    private SystemKeyMapper systemKeyMapper;

    /**
     * Initializes the ABE service.
     * Checks if system keys exist in the database; if not, performs setup and saves them.
     */
    @PostConstruct
    public void init() {
        try {
            SystemKey data = systemKeyMapper.selectById(1);

            if (data == null) {
                this.globalKeys = setup();
                saveKeysToDb(this.globalKeys);
            } else {
                loadKeysFromData(data);
            }
        } catch (Exception e) {
            log.error("ABE Service initialization failed", e);
        }
    }

    /**
     * Saves the generated ABE system keys and parameters to the database.
     *
     * @param keys The ABE system keys to save.
     */
    private void saveKeysToDb(ABEKeys keys) {
        SystemKey systemKey = new SystemKey();
        systemKey.setId(1);
        systemKey.setParams(this.pairingParameters.toString());
        systemKey.setG(this.g.toBytes());
        systemKey.setPkH(keys.h.toBytes());
        systemKey.setPkEggAlpha(keys.egg_alpha.toBytes());
        systemKey.setMskBeta(keys.beta.toBytes());
        systemKey.setMskAlpha(keys.alpha.toBytes());
        
        systemKeyMapper.insert(systemKey);
    }

    /**
     * Loads ABE system keys and parameters from the database.
     *
     * @param data The SystemKey entity containing serialized key data.
     */
    private void loadKeysFromData(SystemKey data) {
        this.pairingParameters = new PropertiesParameters().load(new java.io.ByteArrayInputStream(data.getParams().getBytes(StandardCharsets.UTF_8)));
        this.pairing = PairingFactory.getPairing(this.pairingParameters);
        this.g = pairing.getG1().newElementFromBytes(data.getG()).getImmutable();

        this.globalKeys = new ABEKeys();
        this.globalKeys.h = pairing.getG1().newElementFromBytes(data.getPkH()).getImmutable();
        this.globalKeys.egg_alpha = pairing.getGT().newElementFromBytes(data.getPkEggAlpha()).getImmutable();
        this.globalKeys.beta = pairing.getZr().newElementFromBytes(data.getMskBeta()).getImmutable();
        this.globalKeys.alpha = pairing.getZr().newElementFromBytes(data.getMskAlpha()).getImmutable();
    }

    /**
     * {@inheritDoc}
     * Sets up the ABE system using a Type A curve generator.
     */
    @Override
    public ABEKeys setup() {
        TypeACurveGenerator gen = new TypeACurveGenerator(160, 512);
        this.pairingParameters = gen.generate();
        this.pairing = PairingFactory.getPairing(this.pairingParameters);
        this.g = pairing.getG1().newRandomElement().getImmutable();

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();

        ABEKeys keys = new ABEKeys();
        keys.h = g.powZn(beta).getImmutable();
        Element g_alpha = g.powZn(alpha).getImmutable();
        keys.egg_alpha = pairing.pairing(g, g_alpha).getImmutable();
        keys.beta = beta;
        keys.alpha = alpha; 
        return keys;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ABEKeys getGlobalKeys() {
        return this.globalKeys;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Element getElementFromBytes(byte[] data, String group) {
        if (data == null) return null;
        return switch (group) {
            case "G1" -> pairing.getG1().newElementFromBytes(data).getImmutable();
            case "G2" -> pairing.getG2().newElementFromBytes(data).getImmutable();
            case "GT" -> pairing.getGT().newElementFromBytes(data).getImmutable();
            case "Zr" -> pairing.getZr().newElementFromBytes(data).getImmutable();
            default -> throw new IllegalArgumentException("Unknown group: " + group);
        };
    }

    /**
     * {@inheritDoc}
     * Generates a secret key for a user. In this CP-ABE scheme, the secret key is tied to attributes.
     */
    @Override
    public SecretKeyContainer keygen(String[] attributes) {
        SecretKeyContainer sk = new SecretKeyContainer();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element alpha_plus_r = globalKeys.alpha.duplicate().add(r);
        Element beta_inv = globalKeys.beta.duplicate().invert().getImmutable();

        sk.D = g.powZn(alpha_plus_r.mul(beta_inv)).getImmutable();
        sk.D_r = g.powZn(r).getImmutable();

        for (String attribute : attributes) {
            SKComponent component = new SKComponent();
            component.attribute = attribute;
            sk.components.add(component);
        }
        return sk;
    }

    /**
     * {@inheritDoc}
     * Encrypts a session key. The policy is represented as a list of required attributes.
     */
    @Override
    public ABECiphertext encryptSessionKey(byte[] sessionKeyBytes, String[] policy) throws Exception {
        if (sessionKeyBytes == null || sessionKeyBytes.length != 32) {
            throw new IllegalArgumentException("AES key must be exactly 32 bytes (256 bits) for AES-256.");
        }
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element K_tilde = globalKeys.egg_alpha.powZn(s).getImmutable();

        byte[] maskingKey = sha256(K_tilde.toBytes());
        byte[] encryptedSessionKeyBytes = new byte[sessionKeyBytes.length];
        for (int i = 0; i < sessionKeyBytes.length; i++) {
            encryptedSessionKeyBytes[i] = (byte) (sessionKeyBytes[i] ^ maskingKey[i]);
        }

        ABECiphertext abeCiphertext = new ABECiphertext();
        abeCiphertext.encryptedSessionKey = encryptedSessionKeyBytes;
        abeCiphertext.C = globalKeys.h.powZn(s).getImmutable();
        abeCiphertext.C_prime = g.powZn(s).getImmutable();
        for (String attribute : policy) {
            CTComponent component = new CTComponent();
            component.attribute = attribute;
            abeCiphertext.components.add(component);
        }
        return abeCiphertext;
    }

    /**
     * {@inheritDoc}
     * Recovers the session key if the secret key's attributes satisfy the ciphertext's policy.
     */
    @Override
    public byte[] decryptSessionKey(SecretKeyContainer sk, ABECiphertext ciphertext) throws Exception {
        if (ciphertext.C == null && ciphertext.tempCBytes != null) {
            ciphertext.C = pairing.getG1().newElementFromBytes(ciphertext.tempCBytes).getImmutable();
        }
        if (ciphertext.C_prime == null && ciphertext.tempCPrimeBytes != null) {
            ciphertext.C_prime = pairing.getG1().newElementFromBytes(ciphertext.tempCPrimeBytes).getImmutable();
        }

        for (CTComponent ctComp : ciphertext.components) {
            boolean hasAttribute = false;
            for(SKComponent skComp : sk.components) {
                if(Objects.equals(skComp.attribute, ctComp.attribute)) {
                    hasAttribute = true;
                    break;
                }
            }
            if (!hasAttribute) return null;
        }

        Element numerator = pairing.pairing(ciphertext.C, sk.D);
        Element denominator = pairing.pairing(ciphertext.C_prime, sk.D_r);
        Element K_tilde_reconstructed = numerator.div(denominator);

        byte[] maskingKey = sha256(K_tilde_reconstructed.toBytes());
        byte[] sessionKeyBytes = new byte[ciphertext.encryptedSessionKey.length];
        for (int i = 0; i < ciphertext.encryptedSessionKey.length; i++) {
            sessionKeyBytes[i] = (byte) (ciphertext.encryptedSessionKey[i] ^ maskingKey[i]);
        }
        return sessionKeyBytes;
    }

    /**
     * Computes the SHA-256 hash of the input bytes.
     *
     * @param in The input bytes.
     * @return The SHA-256 hash bytes.
     * @throws NoSuchAlgorithmException If the SHA-256 algorithm is not available.
     */
    private byte[] sha256(byte[] in) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(in);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encryptAES(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(data);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decryptAES(byte[] encryptedData, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(encryptedData);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public HybridCiphertext encryptFileHybrid(byte[] fileBytes, byte[] symmetricKey, String[] policy) throws Exception {
        if (symmetricKey == null || symmetricKey.length != 32) {
            throw new IllegalArgumentException("AES key must be exactly 32 bytes (256 bits) for AES-256.");
        }
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        byte[] encryptedFile = encryptAES(fileBytes, symmetricKey, iv);
        ABECiphertext abeEncryptedKey = encryptSessionKey(symmetricKey, policy);
        HybridCiphertext hc = new HybridCiphertext();
        hc.aesEncryptedFile = encryptedFile;
        hc.abeEncryptedKey = abeEncryptedKey;
        hc.iv = iv;
        return hc;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decryptFileHybrid(HybridCiphertext hc, String[] userAttributes) throws Exception {
        SecretKeyContainer sk = keygen(userAttributes);
        byte[] recoveredKey = decryptSessionKey(sk, hc.abeEncryptedKey);
        if (recoveredKey == null) throw new RuntimeException("ABE Decryption failed.");
        return decryptAES(hc.aesEncryptedFile, recoveredKey, hc.iv);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isPolicySatisfied(String policy, String userAttributesStr) {
        if (policy == null || policy.isEmpty()) return true;
        if (userAttributesStr == null || userAttributesStr.isEmpty()) return false;

        String[] requiredAttributes = policy.split(",");
        String[] userAttributes = userAttributesStr.split(",");
        
        for (String req : requiredAttributes) {
            String trimmedReq = req.trim();
            if (trimmedReq.isEmpty()) continue;
            boolean found = false;
            for (String userAttr : userAttributes) {
                if (userAttr.trim().equals(trimmedReq)) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }
}
