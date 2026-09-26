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
package org.owasp.esapi.errors;

import static org.junit.Assert.assertEquals;

import org.junit.Test;


/**
 * The Class AccessReferenceMapTest.
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class EnterpriseSecurityExceptionTest {
    /**
     * Test of update method, of class org.owasp.esapi.AccessReferenceMap.
     *
     */
    @Test
    public void testExceptions() {
        System.out.println("exceptions");
        EnterpriseSecurityException e = null;
        e = new EnterpriseSecurityException();
        e = new EnterpriseSecurityException("m1","m2");
        e = new EnterpriseSecurityException("m1","m2",new Throwable());
        assertEquals( e.getUserMessage(), "m1" );
        assertEquals( e.getLogMessage(), "m2" );
        e = new AccessControlException();
        e = new AccessControlException("m1","m2");
        e = new AccessControlException("m1","m2",new Throwable());
        e = new AuthenticationException();
        e = new AuthenticationException("m1","m2");
        e = new AuthenticationException("m1","m2",new Throwable());
        e = new AvailabilityException();
        e = new AvailabilityException("m1","m2");
        e = new AvailabilityException("m1","m2",new Throwable());
        e = new CertificateException();
        e = new CertificateException("m1","m2");
        e = new CertificateException("m1","m2",new Throwable());
        e = new EncodingException();
        e = new EncodingException("m1","m2");
        e = new EncodingException("m1","m2",new Throwable());
        e = new EncryptionException();
        e = new EncryptionException("m1","m2");
        e = new EncryptionException("m1","m2",new Throwable());
        e = new ExecutorException();
        e = new ExecutorException("m1","m2");
        e = new ExecutorException("m1","m2",new Throwable());
        e = new ValidationException();
        e = new ValidationException("m1","m2");
        e = new ValidationException("m1","m2",new Throwable());
        e = new ValidationException("m1","m2","context");
        e = new ValidationException("m1","m2",new Throwable(),"context");

        e = new IntegrityException();
        e = new IntegrityException("m1","m2");
        e = new IntegrityException("m1","m2",new Throwable());
        e = new AuthenticationHostException();
        e = new AuthenticationHostException("m1","m2");
        e = new AuthenticationHostException("m1","m2",new Throwable());

        e = new AuthenticationAccountsException();
        e = new AuthenticationAccountsException("m1","m2");
        e = new AuthenticationAccountsException("m1","m2",new Throwable());
        e = new AuthenticationCredentialsException();
        e = new AuthenticationCredentialsException("m1","m2");
        e = new AuthenticationCredentialsException("m1","m2",new Throwable());
        e = new AuthenticationLoginException();
        e = new AuthenticationLoginException("m1","m2");
        e = new AuthenticationLoginException("m1","m2",new Throwable());
        e = new ValidationAvailabilityException();
        e = new ValidationAvailabilityException("m1","m2");
        e = new ValidationAvailabilityException("m1","m2",new Throwable());
        e = new ValidationUploadException();
        e = new ValidationUploadException("m1","m2");
        e = new ValidationUploadException("m1","m2",new Throwable());

        ValidationException ve = new ValidationException();
        ve.setContext("test");
        assertEquals( "test", ve.getContext() );

        IntrusionException ex = new IntrusionException( "test", "test details");
        ex = new IntrusionException("m1","m2");
        ex = new IntrusionException("m1","m2", new Throwable());
        assertEquals( ex.getUserMessage(), "m1" );
        assertEquals( ex.getLogMessage(), "m2" );
    }

}
