package org.owasp.esapi.crypto;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;

public class CipherTextSerializerTest {
    private Cipher encryptor = null;
    private IvParameterSpec ivSpec = null;  // Note: FindBugs reports false positive
                                            // about this being unread field. See
                                            // testAsSerializedByteArray().


    @BeforeEach
    public void setUp() throws Exception {
        encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] ivBytes = null;
        ivBytes = ESAPI.randomizer().getRandomBytes(encryptor.getBlockSize());
        ivSpec = new IvParameterSpec(ivBytes);
    }

    @AfterEach
    public void tearDown() throws Exception {
        System.out.flush();
    }

    @Test
    public final void testAsSerializedByteArray() {
        System.out.println("CipherTextSerializerTest.testAsSerializedByteArray() ...");
        CipherSpec cipherSpec = new CipherSpec(encryptor, 128);
        cipherSpec.setIV(ivSpec.getIV());
        SecretKey key;
        try {
            key = CryptoHelper.generateSecretKey(cipherSpec.getCipherAlgorithm(), 128);
            encryptor.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] raw = encryptor.doFinal("Hello".getBytes("UTF8"));
            CipherText ct = ESAPI.encryptor().encrypt(key, new PlainText("Hello") );
            assertTrue( ct != null );   // Here to eliminate false positive from FindBugs.
            CipherTextSerializer cts = new CipherTextSerializer( ct );
            byte[] serializedBytes = cts.asSerializedByteArray();
            CipherText result = CipherText.fromPortableSerializedBytes(serializedBytes);
            PlainText pt = ESAPI.encryptor().decrypt(key, result);
            assertTrue( "Hello".equals( pt.toString() ) );
        } catch (Exception e) {
            fail("Test failed: Caught exception: " + e.getClass().getName() + "; msg was: " + e);
            e.printStackTrace(System.err);
        }
    }

    @Test
    public final void testAsCipherText() {
        try {
            System.out.println("CipherTextSerializerTest.testAsCipherText() ...");
            CipherText ct = ESAPI.encryptor().encrypt( new PlainText("Hello") );
            CipherTextSerializer cts = new CipherTextSerializer( ct );
            CipherText result = cts.asCipherText();
            assertTrue( ct.equals(result) );
            PlainText pt = ESAPI.encryptor().decrypt(result);
            assertTrue( "Hello".equals( pt.toString() ) );
        } catch (EncryptionException e) {
            fail("Caught EncryptionException; exception msg: " + e);
        }
    }

}
