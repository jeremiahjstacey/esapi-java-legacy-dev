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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;



import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.owasp.esapi.errors.ValidationException;


/**
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ValidationErrorListTest {
    String testName;
    ValidationErrorList vel = new ValidationErrorList();
    ValidationException vex;
    
    @BeforeEach
    void setUp(TestInfo testInfo) {
        testName = testInfo.getDisplayName();
        vex = new ValidationException(testName,testName);
    }
    
    @Test
    public void testAddErrorNullContextThrows() {
        RuntimeException rex = assertThrows(RuntimeException.class,() ->{
            vel.addError(null, vex);
        });
        assertNotNull(rex);
        assertTrue(rex.getMessage().contains("Context cannot be null"));
    }
    @Test
    public void testAddErrorNullExceptionThrows() {
        RuntimeException rex = assertThrows(RuntimeException.class,() ->{
            vel.addError(testName, null);
        });
        assertNotNull(rex);
        assertTrue(rex.getMessage().contains("ValidationException cannot be null"));
    }
    @Test
    public void testAddErrorDuplicateContextThrows() {
        RuntimeException rex = assertThrows(RuntimeException.class,() ->{
            vel.addError(testName, vex);
            vel.addError(testName, vex);
        });
        assertNotNull(rex);
        assertTrue(rex.getMessage().contains("already exists, must be unique"));

    }
    @Test
    public void testErrors() throws Exception {
        vel.addError("context",  vex );
        assertTrue(vel.errors().contains( vex),"Validation Errors List should contain the added ValidationException Reference");
    }
    @Test
    public void testGetError() throws Exception {
        vel.addError("context",  vex );
        assertTrue( vel.getError( "context" ) == vex );
        assertNull( vel.getError( "ridiculous" ) );
    }
    @Test
    public void testIsEmpty() throws Exception {
        assertTrue( vel.isEmpty() );
        vel.addError("context",  vex );
        assertFalse( vel.isEmpty() );
    }
    @Test
    public void testSize() throws Exception {
        assertEquals(0, vel.size() );
        vel.addError("context",  vex );
        assertEquals(1, vel.size());
    }

}


