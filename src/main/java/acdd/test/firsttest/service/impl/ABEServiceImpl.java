package acdd.test.firsttest.service.impl;

import acdd.test.firsttest.service.ABEService;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Objects;

@Service
public class ABEServiceImpl implements ABEService {

    private Pairing pairing;
    private PairingParameters pairingParameters;
    private Element g;
    private ABEKeys globalKeys;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @PostConstruct
    public void init() {
        try {
            List<SystemKeyData> results = jdbcTemplate.query(
                    "SELECT params, g, pk_h, pk_egg_alpha, msk_beta, msk_alpha FROM system_keys WHERE id = 1",
                    (rs, rowNum) -> {
                        SystemKeyData data = new SystemKeyData();
                        data.params = rs.getString("params");
                        data.g = rs.getBytes("g");
                        data.pk_h = rs.getBytes("pk_h");
                        data.pk_egg_alpha = rs.getBytes("pk_egg_alpha");
                        data.msk_beta = rs.getBytes("msk_beta");
                        data.msk_alpha = rs.getBytes("msk_alpha");
                        return data;
                    });

            if (results.isEmpty()) {
                this.globalKeys = setup();
                saveKeysToDb(this.globalKeys);
            } else {
                loadKeysFromData(results.get(0));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void saveKeysToDb(ABEKeys keys) {
        jdbcTemplate.update(
                "INSERT INTO system_keys (id, params, g, pk_h, pk_egg_alpha, msk_beta, msk_alpha) VALUES (1, ?, ?, ?, ?, ?, ?)",
                this.pairingParameters.toString(),
                this.g.toBytes(),
                keys.h.toBytes(),
                keys.egg_alpha.toBytes(),
                keys.beta.toBytes(),
                keys.alpha.toBytes()
        );
    }

    private void loadKeysFromData(SystemKeyData data) {
        this.pairingParameters = new PropertiesParameters().load(new java.io.ByteArrayInputStream(data.params.getBytes(StandardCharsets.UTF_8)));
        this.pairing = PairingFactory.getPairing(this.pairingParameters);
        this.g = pairing.getG1().newElementFromBytes(data.g).getImmutable();

        this.globalKeys = new ABEKeys();
        this.globalKeys.h = pairing.getG1().newElementFromBytes(data.pk_h).getImmutable();
        this.globalKeys.egg_alpha = pairing.getGT().newElementFromBytes(data.pk_egg_alpha).getImmutable();
        this.globalKeys.beta = pairing.getZr().newElementFromBytes(data.msk_beta).getImmutable();
        this.globalKeys.alpha = pairing.getZr().newElementFromBytes(data.msk_alpha).getImmutable();
    }

    private static class SystemKeyData {
        String params;
        byte[] g;
        byte[] pk_h;
        byte[] pk_egg_alpha;
        byte[] msk_beta;
        byte[] msk_alpha;
    }

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

    @Override
    public ABEKeys getGlobalKeys() {
        return this.globalKeys;
    }

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

    @Override
    public ABECiphertext encryptSessionKey(byte[] sessionKeyBytes, String[] policy) throws Exception {
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

    private byte[] sha256(byte[] in) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(in);
    }

    @Override
    public byte[] encryptAES(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(data);
    }

    @Override
    public byte[] decryptAES(byte[] encryptedData, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(encryptedData);
    }

    @Override
    public HybridCiphertext encryptFileHybrid(byte[] fileBytes, byte[] symmetricKey, String[] policy) throws Exception {
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

    @Override
    public byte[] decryptFileHybrid(HybridCiphertext hc, String[] userAttributes) throws Exception {
        SecretKeyContainer sk = keygen(userAttributes);
        byte[] recoveredKey = decryptSessionKey(sk, hc.abeEncryptedKey);
        if (recoveredKey == null) throw new RuntimeException("ABE Decryption failed.");
        return decryptAES(hc.aesEncryptedFile, recoveredKey, hc.iv);
    }

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
