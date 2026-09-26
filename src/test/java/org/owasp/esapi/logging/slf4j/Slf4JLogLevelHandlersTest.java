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
package org.owasp.esapi.logging.slf4j;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.helpers.BasicMarkerFactory;

public class Slf4JLogLevelHandlersTest {

    private Logger mockLogger = Mockito.mock(Logger.class);
    private String testName;

    private Marker marker = new BasicMarkerFactory().getMarker(Slf4JLogLevelHandlersTest.class.getSimpleName());
    private Throwable testException = new Throwable("Expected for testing");
    
    @BeforeEach
    void setUp(TestInfo testInfo) {
        testName = testInfo.getDisplayName();
    }
    
    @Test
    public void testErrorDelegation() {
        Slf4JLogLevelHandlers.ERROR.isEnabled(mockLogger);
        Slf4JLogLevelHandlers.ERROR.log(mockLogger, marker, testName);
        Slf4JLogLevelHandlers.ERROR.log(mockLogger, marker, testName, testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isErrorEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).error(marker, testName);
        Mockito.verify(mockLogger, Mockito.times(1)).error(marker, testName, testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testWarnDelegation() {
        Slf4JLogLevelHandlers.WARN.isEnabled(mockLogger);
        Slf4JLogLevelHandlers.WARN.log(mockLogger, marker, testName);
        Slf4JLogLevelHandlers.WARN.log(mockLogger, marker, testName, testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isWarnEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).warn(marker, testName);
        Mockito.verify(mockLogger, Mockito.times(1)).warn(marker, testName, testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testInfoDelegation() {
        Slf4JLogLevelHandlers.INFO.isEnabled(mockLogger);
        Slf4JLogLevelHandlers.INFO.log(mockLogger, marker, testName);
        Slf4JLogLevelHandlers.INFO.log(mockLogger, marker, testName, testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isInfoEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).info(marker, testName);
        Mockito.verify(mockLogger, Mockito.times(1)).info(marker, testName, testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testDebugDelegation() {
        Slf4JLogLevelHandlers.DEBUG.isEnabled(mockLogger);
        Slf4JLogLevelHandlers.DEBUG.log(mockLogger, marker, testName);
        Slf4JLogLevelHandlers.DEBUG.log(mockLogger, marker, testName, testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isDebugEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).debug(marker, testName);
        Mockito.verify(mockLogger, Mockito.times(1)).debug(marker, testName, testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testTraceDelegation() {
        Slf4JLogLevelHandlers.TRACE.isEnabled(mockLogger);
        Slf4JLogLevelHandlers.TRACE.log(mockLogger, marker, testName);
        Slf4JLogLevelHandlers.TRACE.log(mockLogger, marker, testName, testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isTraceEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).trace(marker, testName);
        Mockito.verify(mockLogger, Mockito.times(1)).trace(marker, testName, testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
}
