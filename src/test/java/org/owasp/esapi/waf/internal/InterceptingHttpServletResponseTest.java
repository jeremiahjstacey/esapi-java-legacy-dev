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
package org.owasp.esapi.waf.internal;

import java.util.ArrayList;

import org.junit.Test;
import org.owasp.esapi.http.MockHttpServletResponse;

/**
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class InterceptingHttpServletResponseTest {

    /**
     * Test.
     */
    @Test
    public void testRequest() throws Exception {
        System.out.println("InterceptingHTTPServletResponse");
           MockHttpServletResponse mres = new MockHttpServletResponse();
        InterceptingHTTPServletResponse ires = new InterceptingHTTPServletResponse(mres, false, new ArrayList() );
        // isos.println( "Hello" );
        // ires.getOutputStream().println( "Hello" );
        // ires.getWriter().println("Hello");
        // assertEquals( "Hello\r\n", new String( ires.getInterceptingServletOutputStream().getResponseBytes() ) );
    }
}
