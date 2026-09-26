/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @created 2018
 */
package org.owasp.esapi.logging.cleaning;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

public class CompositeLogScrubberTest {
    @Test
    public void testNullListThrowsException() {
        IllegalArgumentException exEx = assertThrows(IllegalArgumentException.class, () -> {
            new CompositeLogScrubber(null);
        });
        assertTrue(exEx.getMessage().contains("cannot be null"));
    }
    @Test
    public void testPassthroughOnEmpty() {
        String str = "Testing Content";
        String cleaned = new CompositeLogScrubber(new ArrayList<LogScrubber>()).cleanMessage(str);
        assertEquals(str, cleaned);
    }
    @Test
    public void testListIteration() {
        LogScrubber scrub1 = Mockito.mock(LogScrubber.class);
        LogScrubber scrub2 = Mockito.mock(LogScrubber.class);
        CompositeLogScrubber scrubber = new CompositeLogScrubber(Arrays.asList(scrub1, scrub2));

        String msg1 = "start";
        String msg2 = "scrub1 return";
        String msg3 = "scrub2 return";

        Mockito.when(scrub1.cleanMessage(msg1)).thenReturn(msg2);
        Mockito.when(scrub2.cleanMessage(msg2)).thenReturn(msg3);

        String cleaned = scrubber.cleanMessage(msg1);

        Mockito.verify(scrub1, Mockito.times(1)).cleanMessage(msg1);
        Mockito.verify(scrub2, Mockito.times(1)).cleanMessage(msg2);

        assertEquals(msg3, cleaned);
    }

}
