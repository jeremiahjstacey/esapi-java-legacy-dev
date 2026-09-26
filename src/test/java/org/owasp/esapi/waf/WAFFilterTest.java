/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf;


import org.junit.jupiter.api.Test;


/**
 * This is the main TestSuite for all the WAF tests. Some of the WAF
 * tests utilize a large policy file containing a bunch of unrelated
 * rules, and some use very small policy files that only exercise
 * specific functionality. Some may use both.
 *
 * There is an unlimited combination of rules to be exercised together,
 * so the small policy files test the strict functionality, while the
 * larger policy files (hopefully) give us assurance that the rules
 * won't interfere with each other.
 */

public class WAFFilterTest {

    @Test
    public void testConfigurationCanBeRead() throws Exception {

        ESAPIWebApplicationFirewallFilter waf = new ESAPIWebApplicationFirewallFilter();
        WAFTestUtility.setWAFPolicy(waf, "waf-policy.xml");

    }

}
