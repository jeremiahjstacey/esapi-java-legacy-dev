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
package org.owasp.esapi.filters;

import static org.junit.Assert.*;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterConfig;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.owasp.esapi.http.MockFilterChain;
import org.owasp.esapi.http.MockFilterConfig;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

/**
 * The Class ClickjackFilterTest.
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ClickjackFilterTest {

    @Before
    public void setUp() throws Exception {
        // none
    }

    @After
    public void tearDown() throws Exception {
        // none
    }


    /**
     * Test of update method, of class org.owasp.esapi.AccessReferenceMap.
     * @throws Exception
     */
    @Test
    public void testFilter() throws Exception {
        System.out.println("ClickjackFilter");

        Map map = new HashMap();
        FilterConfig mfc = new MockFilterConfig( map );
        ClickjackFilter filter = new ClickjackFilter();
        filter.init( mfc );
        MockHttpServletRequest request = new MockHttpServletRequest();

        // the mock filter chain writes the requested URI to the response body
        MockFilterChain chain = new MockFilterChain();

        URL url = new URL( "http://www.example.com/index.jsp" );
        System.out.println( "\nTest request: " + url );
        request = new MockHttpServletRequest( url );
        MockHttpServletResponse response = new MockHttpServletResponse();
        try {
            filter.doFilter(request, response, chain);
        } catch( Exception e ) {
            e.printStackTrace();
            fail();
        }
        String header = response.getHeader( "X-FRAME-OPTIONS");
        System.out.println(">>>" + header );
        assertEquals( "DENY", header );
    }

}