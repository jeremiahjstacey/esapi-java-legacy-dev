package org.owasp.esapi.crypto;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Random;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;
import org.owasp.esapi.errors.EncryptionException;

public class CryptoHelperTest {

    @Test
    public final void testGenerateSecretKeySunnyDay() {
        try {
            SecretKey key = CryptoHelper.generateSecretKey("AES", 128);
            assertTrue(key.getAlgorithm().equals("AES"));
            assertTrue(128 / 8 == key.getEncoded().length);
        } catch (EncryptionException e) {
            // OK if not covered in code coverage -- not expected.
            fail("Caught unexpected EncryptionException; msg was "
                    + e.getMessage());
        }
    }

    @Test
    public final void testGenerateSecretKeyEncryptionException()
            throws EncryptionException {
        assertThrows (EncryptionException.class, () -> {
            SecretKey key = CryptoHelper.generateSecretKey("NoSuchAlg", 128);
            assertTrue(key == null); // Not reached!
        });
    }

    @Test
    public final void testOverwriteByteArrayByte() {
        byte[] secret = "secret password".getBytes();
        int len = secret.length;
        CryptoHelper.overwrite(secret, (byte) 'x');
        assertTrue(secret.length == len); // Length unchanged
        assertTrue(checkByteArray(secret, (byte) 'x')); // Filled with 'x'
    }

    @Test
    public final void testCopyByteArraySunnyDay() {
        byte[] src = new byte[20];
        fillByteArray(src, (byte) 'A');
        byte[] dest = new byte[20];
        fillByteArray(dest, (byte) 'B');
        CryptoHelper.copyByteArray(src, dest);
        assertTrue(checkByteArray(src, (byte) 'A')); // Still filled with 'A'
        assertTrue(checkByteArray(dest, (byte) 'A')); // Now filled with 'B'
    }

    @Test
    public final void testCopyByteArraySrcNullPointerException() {
        assertThrows (NullPointerException.class, () -> {
            byte[] ba = new byte[16];
            CryptoHelper.copyByteArray(null, ba, ba.length);
        });
    }

    @Test
    public final void testCopyByteArrayDestNullPointerException() {
        assertThrows (NullPointerException.class, () -> {
            byte[] ba = new byte[16];
            CryptoHelper.copyByteArray(ba, null, ba.length);
        });
    }

    @Test
    public final void testCopyByteArrayIndexOutOfBoundsException() {
        assertThrows (IndexOutOfBoundsException.class, () -> {
            byte[] ba8 = new byte[8];
            byte[] ba16 = new byte[16];
            CryptoHelper.copyByteArray(ba8, ba16, ba16.length);
        });
    }

    @Test
    public final void testArrayCompare() {
        byte[] ba1 = new byte[32];
        byte[] ba2 = new byte[32];
        byte[] ba3 = new byte[48];

        // Note: Don't need cryptographically secure random numbers for this!
        Random prng = new Random();

        prng.nextBytes(ba1);
        prng.nextBytes(ba2);
        prng.nextBytes(ba3);

        /*
         * Unfortunately, can't rely no the nanosecond timer because as the
         * Javadoc for System.nanoTime() states, " No guarantees are made
         * about how frequently values change", so this is not very reliable.
         *
         * However, on can uncomment the code and observe that elapsed times
         * are generally less than 10 millionth of a second. I suppose if we
         * declared a large enough epsilon, we could make it work, but it is
         * easier to convince yourself from the CryptoHelper.arrayCompare() code
         * itself that it always goes through all the bits of the byte array
         * if it compares any bits at all.
         */

//        long start, stop, diff;

//        start = System.nanoTime();
        assertTrue(CryptoHelper.arrayCompare(null, null));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

//        start = System.nanoTime();
        assertTrue(CryptoHelper.arrayCompare(ba1, ba1));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

//        start = System.nanoTime();
        assertFalse(CryptoHelper.arrayCompare(ba1, ba2));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

//        start = System.nanoTime();
        assertFalse(CryptoHelper.arrayCompare(ba1, ba3));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

//        start = System.nanoTime();
        assertFalse(CryptoHelper.arrayCompare(ba1, null));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

//        start = System.nanoTime();
        assertFalse(CryptoHelper.arrayCompare(null, ba1));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");

        ba2 = ba1;
//        start = System.nanoTime();
        assertTrue(CryptoHelper.arrayCompare(ba1, ba2));
//        stop = System.nanoTime();
//        diff = stop - start;
//        System.out.println("diff: " + diff + " nanosec");
    }

    @Test
    public final void testIsValidKDFVersion() {
        assertTrue( CryptoHelper.isValidKDFVersion(20110203, false, false));
        assertTrue( CryptoHelper.isValidKDFVersion(20130830, false, false));
        assertTrue( CryptoHelper.isValidKDFVersion(33330303, false, false));
        assertTrue( CryptoHelper.isValidKDFVersion(99991231, false, false));

        assertFalse( CryptoHelper.isValidKDFVersion(0, false, false));
        assertFalse( CryptoHelper.isValidKDFVersion(99991232, false, false));
        assertFalse( CryptoHelper.isValidKDFVersion(20110202, false, false));

        assertTrue( CryptoHelper.isValidKDFVersion(20110203, true, false));
        assertTrue( CryptoHelper.isValidKDFVersion(KeyDerivationFunction.kdfVersion, true, false));
        assertFalse( CryptoHelper.isValidKDFVersion(KeyDerivationFunction.kdfVersion + 1, true, false));

        try {
            CryptoHelper.isValidKDFVersion(77777777, true, true);
            fail("Failed to CryptoHelper.isValidKDFVersion() failed to throw IllegalArgumentException.");
        }
        catch (Exception e) {
            assertTrue( e instanceof IllegalArgumentException);
        }
    }

    private void fillByteArray(byte[] ba, byte b) {
        for (int i = 0; i < ba.length; i++) {
            ba[i] = b;
        }
    }

    private boolean checkByteArray(byte[] ba, byte b) {
        for (int i = 0; i < ba.length; i++) {
            if (ba[i] != b) {
                return false;
            }
        }
        return true;
    }

}
