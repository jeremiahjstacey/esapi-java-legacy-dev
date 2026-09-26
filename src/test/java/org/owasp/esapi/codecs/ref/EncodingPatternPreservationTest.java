package org.owasp.esapi.codecs.ref;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

public class EncodingPatternPreservationTest {
    @Test
    public void testReplaceAndRestore() {
        Pattern numberRegex = Pattern.compile("(ABC)");
        EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
        String origStr = "12 ABC 34 DEF 56 G 7";
        String replacedStr = epp.captureAndReplaceMatches(origStr);

        assertEquals("12 EncodingPatternPreservation 34 DEF 56 G 7", replacedStr);

        String restored = epp.restoreOriginalContent(replacedStr);
        assertEquals(origStr, restored);
    }
    @Test
    public void testReplaceMultipleAndRestore() {
        Pattern numberRegex = Pattern.compile("(ABC)");
        EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
        String origStr = "12 ABC 34 ABC 56 G 7 ABC8";
        String replacedStr = epp.captureAndReplaceMatches(origStr);

        assertEquals("12 EncodingPatternPreservation 34 EncodingPatternPreservation 56 G 7 EncodingPatternPreservation8", replacedStr);

        String restored = epp.restoreOriginalContent(replacedStr);
        assertEquals(origStr, restored);
    }
    @Test
    public void testSetMarker() {
        Pattern numberRegex = Pattern.compile("(ABC)");
        EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
        epp.setReplacementMarker(EncodingPatternPreservationTest.class.getSimpleName());

        String origStr = "12 ABC 34 DEF 56 G 7";
        String replacedStr = epp.captureAndReplaceMatches(origStr);

        assertEquals("12 EncodingPatternPreservationTest 34 DEF 56 G 7", replacedStr);

        String restored = epp.restoreOriginalContent(replacedStr);
        assertEquals(origStr, restored);
    }

    @Test
    public void testSetMarkerExceptionNoReset() {
        assertThrows (IllegalStateException.class, () -> {
            Pattern numberRegex = Pattern.compile("(ABC)");
            EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
            String origStr = "12 ABC 34 DEF 56 G 7";
            epp.captureAndReplaceMatches(origStr);
            //This allows the + case to be illustrated
            epp.reset();

            //And the exception case.
            epp.captureAndReplaceMatches(origStr);
            epp.setReplacementMarker(EncodingPatternPreservationTest.class.getSimpleName());
        });
    }

    @Test
    public void testReplaceExceptionNoReset() {
        assertThrows (IllegalStateException.class, () -> {
            Pattern numberRegex = Pattern.compile("(ABC)");
            EncodingPatternPreservation epp = new EncodingPatternPreservation(numberRegex);
            String origStr = "12 ABC 34 DEF 56 G 7";
            epp.captureAndReplaceMatches(origStr);
            //This allows the + case to be illustrated
            epp.reset();

            //And the exception case.
            epp.captureAndReplaceMatches(origStr);
            epp.captureAndReplaceMatches(origStr);
        });
    }
}
