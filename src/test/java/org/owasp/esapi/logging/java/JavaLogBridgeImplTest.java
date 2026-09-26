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
 * @created 2019
 */
package org.owasp.esapi.logging.java;

import static org.junit.Assert.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Logger.EventType;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.cleaning.LogScrubber;

public class JavaLogBridgeImplTest {

    private LogScrubber mockScrubber = Mockito.mock(LogScrubber.class);
    private LogAppender mockAppender = Mockito.mock(LogAppender.class);
    private JavaLogLevelHandler mockHandler = Mockito.mock(JavaLogLevelHandler.class);
    private java.util.logging.Logger javaLogSpy;
    private Throwable testEx;
    private JavaLogBridge bridge;
    private String testName;
    
    @BeforeEach
    public void setup(TestInfo testInfo) {
       testName = testInfo.getDisplayName();

        testEx = new Throwable(testName);
        
        Map<Integer, JavaLogLevelHandler> levelLookup = new HashMap<>();
        levelLookup.put(Logger.ALL, mockHandler);

        java.util.logging.Logger wrappedLogger = java.util.logging.Logger.getLogger(testName);
        javaLogSpy = Mockito.spy(wrappedLogger);
        bridge = new JavaLogBridgeImpl(mockAppender, mockScrubber, levelLookup);
    }
    @Test
    public void testLogMessageWithUnmappedEsapiLevelThrowsException() {
        IllegalArgumentException iae = assertThrows (IllegalArgumentException.class, () -> {
            Map<Integer, JavaLogLevelHandler> emptyMap = Collections.emptyMap();
            new JavaLogBridgeImpl(mockAppender, mockScrubber, emptyMap).log(javaLogSpy, 0, Logger.EVENT_UNSPECIFIED, "This Should fail");
        });

        assertTrue(iae.getMessage().contains("Unable to lookup Java level mapping"));

    }
    @Test
    public void testLogMessageAndExceptionWithUnmappedEsapiLevelThrowsException() {
        IllegalArgumentException iae = assertThrows (IllegalArgumentException.class, () -> {
            Map<Integer, JavaLogLevelHandler> emptyMap = Collections.emptyMap();
            new JavaLogBridgeImpl(mockAppender, mockScrubber, emptyMap).log(javaLogSpy, 0, Logger.EVENT_UNSPECIFIED, "This Should fail", testEx);
        });

        assertTrue(iae.getMessage().contains("Unable to lookup Java level mapping"));
    }
    @Test
    public void testLogMessage() {
        EventType eventType = Logger.EVENT_UNSPECIFIED;
        String loggerName = testName + "-LOGGER";
        String orignMsg = testName;
        String appendMsg = "[APPEND] " + orignMsg;
        String cleanMsg = appendMsg + " [CLEANED]";

        //Setup for Appender
        Mockito.when(javaLogSpy.getName()).thenReturn(loggerName);
        Mockito.when(mockAppender.appendTo(loggerName, eventType, orignMsg)).thenReturn(appendMsg);
        //Setup for Scrubber
        Mockito.when(mockScrubber.cleanMessage(appendMsg)).thenReturn(cleanMsg);
        //Setup for Delegate Handler
        Mockito.when(mockHandler.isEnabled(javaLogSpy)).thenReturn(true);

        bridge.log(javaLogSpy, Logger.ALL, eventType, testName);

        Mockito.verify(javaLogSpy, Mockito.atLeastOnce()).getName();
        Mockito.verify(mockAppender, Mockito.times(1)).appendTo(loggerName, eventType, testName);
        Mockito.verify(mockScrubber, Mockito.times(1)).cleanMessage(appendMsg);
        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(javaLogSpy);
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(java.util.logging.Logger.class), ArgumentMatchers.any(String.class), ArgumentMatchers.any(Throwable.class));
        Mockito.verify(mockHandler, Mockito.times(1)).log(ArgumentMatchers.same(javaLogSpy), ArgumentMatchers.eq(cleanMsg));

        Mockito.verifyNoMoreInteractions(javaLogSpy, mockAppender, mockScrubber,mockHandler);
    }
    @Test
    public void testLogErrorMessageWithException() {
        EventType eventType = Logger.EVENT_UNSPECIFIED;
        String loggerName = testName + "-LOGGER";
        String orignMsg = testName;
        String appendMsg = "[APPEND] " + orignMsg;
        String cleanMsg = appendMsg + " [CLEANED]";

        //Setup for Appender
        Mockito.when(javaLogSpy.getName()).thenReturn(loggerName);
        Mockito.when(mockAppender.appendTo(loggerName, eventType, orignMsg)).thenReturn(appendMsg);
        //Setup for Scrubber
        Mockito.when(mockScrubber.cleanMessage(appendMsg)).thenReturn(cleanMsg);
        //Setup for Delegate Handler
        Mockito.when(mockHandler.isEnabled(javaLogSpy)).thenReturn(true);

        bridge.log(javaLogSpy, Logger.ALL, eventType, testName, testEx);

        Mockito.verify(javaLogSpy, Mockito.atLeastOnce()).getName();
        Mockito.verify(mockAppender, Mockito.times(1)).appendTo(loggerName, eventType, testName);
        Mockito.verify(mockScrubber, Mockito.times(1)).cleanMessage(appendMsg);
        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(javaLogSpy);
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(java.util.logging.Logger.class), ArgumentMatchers.any(String.class));

        Mockito.verify(mockHandler, Mockito.times(1)).log(ArgumentMatchers.same(javaLogSpy), ArgumentMatchers.eq(cleanMsg), ArgumentMatchers.same(testEx));

        Mockito.verifyNoMoreInteractions(javaLogSpy, mockAppender, mockScrubber,mockHandler);
    }
    @Test
    public void testDisabledLogMessage() {
        Mockito.when(mockHandler.isEnabled(javaLogSpy)).thenReturn(false);

        bridge.log(javaLogSpy, Logger.ALL, Logger.EVENT_UNSPECIFIED, testName);

        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(javaLogSpy);
        Mockito.verify(mockScrubber, Mockito.times(0)).cleanMessage(ArgumentMatchers.anyString());
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(java.util.logging.Logger.class), ArgumentMatchers.any(String.class));
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(java.util.logging.Logger.class), ArgumentMatchers.any(String.class), ArgumentMatchers.any(Throwable.class));
    }
    @Test
    public void testDisabledErrorLogWithException() {
        Mockito.when(mockHandler.isEnabled(javaLogSpy)).thenReturn(false);

        bridge.log(javaLogSpy, Logger.ALL, Logger.EVENT_UNSPECIFIED, testName, testEx);

        Mockito.verify(mockHandler, Mockito.times(1)).isEnabled(javaLogSpy);
        Mockito.verify(mockScrubber, Mockito.times(0)).cleanMessage(ArgumentMatchers.anyString());
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(java.util.logging.Logger.class), ArgumentMatchers.any(String.class));
        Mockito.verify(mockHandler, Mockito.times(0)).log(ArgumentMatchers.any(java.util.logging.Logger.class), ArgumentMatchers.any(String.class), ArgumentMatchers.any(Throwable.class));

    }
    @Test
    public void testNullEventTypeWorks()
    {
        // would throw an exception if the null wasn't handled properly
        bridge.log(javaLogSpy, Logger.ALL, null, testName);
    }
}
