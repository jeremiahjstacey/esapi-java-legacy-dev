/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2019 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author kevin.w.wall@gmail.com
 * @since 2019
 */
package org.owasp.esapi.reference.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.owasp.esapi.PropNames.VALIDATOR_HTML_VALIDATION_ACTION;
import static org.owasp.esapi.PropNames.VALIDATOR_HTML_VALIDATION_CONFIGURATION_FILE;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.validator.html.PolicyException;

/**
 * The class {@code HTMLValidationRuleClasspathTest} is used to test ESAPI where
 * the AntiSamy policy file is located in a non-standard place. It is based
 * on te original test cases, testGetValidSafeHTML() and
 * testIsValidSafeHTML() from the file {@code ValidatorTest} originally written
 * by
 *      Mike Fauzy (mike.fauzy@aspectsecurity.com) and
 *      Jeff Williams (jeff.williams@aspectsecurity.com)
 * that were originally part of "src/test/java/org/owasp/esapi/reference/ValidatorTest.java".
 *
 * This class tests the case of a non-standard AntiSamy policy file along with
 * the case where the new ESAPI.property
 *      <b>Validator.HtmlValidationAction</b>
 * is set to "throw", which causes certain calls to
 *      {@code ESAPI.validator().getValidSafeHTML()}
 * to throw a ValidationException rather than simply logging a warning and returning
 * the cleansed (sanitizied) output when certain unsafe input is encountered.
 */
public class HTMLValidationRuleClasspathTest {
    /** The intentionally non-compliant (to the AntiSamy XSD) AntiSamy policy file. We don't intend to
     * actually <i>use</i> it for anything other than to test that we report
     * non-compliant AntiSamy policy files in a sane manner.
     */
    private static final String INVALID_ANTISAMY_POLICY_FILE = "antisamy-InvalidPolicy.xml";

    /** A compliant AntiSamy policy file that is just located in a non-standard
     * place. We don't intend to * actually <i>use</i> it for anything other
     * than testing. Otherwise, it's mostly identical to the AntiSamy policy
     * file "src/test/resources/esapi/antisamy-esapi.xml".
     */
    private static final String ANTISAMY_POLICY_FILE_NONSTANDARD_LOCATION = "antisamy-esapi-CP.xml";

    private static class ConfOverride extends SecurityConfigurationWrapper {
        private String desiredReturnAction = "clean";
        private String desiredReturnConfigurationFile = null;

        ConfOverride(SecurityConfiguration orig, String desiredReturnAction, String desiredReturnConfigurationFile) {
            super(orig);
            this.desiredReturnAction = desiredReturnAction;
            this.desiredReturnConfigurationFile = desiredReturnConfigurationFile;
        }

        @Override
        public String getStringProp(String propName) {
            // Would it be better making this file a static import?
            if ( propName.equals( VALIDATOR_HTML_VALIDATION_ACTION ) ) {
                return desiredReturnAction;
            } else if ( propName.equals( VALIDATOR_HTML_VALIDATION_CONFIGURATION_FILE ) ) {
                return desiredReturnConfigurationFile;
            } else {
                return super.getStringProp( propName );
            }
        }
    }

    @AfterEach
    public void tearDown() throws Exception {
        ESAPI.override(null);
    }

    @BeforeEach
    public void setUp() throws Exception {
        ESAPI.override(
            new ConfOverride( ESAPI.securityConfiguration(), "throw", ANTISAMY_POLICY_FILE_NONSTANDARD_LOCATION )
        );
    }


    @Test
    public void checkPolicyExceptionWithBadConfig() throws Exception {
        ESAPI.override(null);
        assertThrows(PolicyException.class, () -> {
            HTMLValidationRule.loadAntisamyPolicy(INVALID_ANTISAMY_POLICY_FILE);
        });
    }
    @Test
    public void testGetValid() throws Exception {
        System.out.println("getValidCP");
        Validator instance = ESAPI.validator();
        HTMLValidationRule rule = new HTMLValidationRule("testCP");
        ESAPI.validator().addRule(rule);

        ValidationException exEx = assertThrows(ValidationException.class, () -> {
            instance.getRule("testCP").getValid("test", "Test. <script>alert(document.cookie)</script>");
        });
        assertTrue(exEx.getMessage().contains("test: Invalid HTML input"));
    }
    @Test
    public void testGetValidSafeHTML() throws Exception {
        System.out.println("getValidSafeHTML");
        Validator instance = ESAPI.validator();

        HTMLValidationRule rule = new HTMLValidationRule("test");
        ESAPI.validator().addRule(rule);

        String[] testInput = {
                                // These first two don't cause AntiSamy to throw.
                                // They are only listed here for completeness.
                        // "Test. <a href=\"http://www.aspectsecurity.com\">Aspect Security</a>",
                        // "Test. <<div on<script></script>load=alert()",
                        "Test. <script>alert(document.cookie)</script>",
                        "Test. <script>alert(document.cookie)</script>",
                        "Test. <div style={xss:expression(xss)}>b</div>",
                        "Test. <s%00cript>alert(document.cookie)</script>",
                        "Test. <s\tcript>alert(document.cookie)</script>",
                        "Test. <s\tcript>alert(document.cookie)</script>"
        };

        int errors = 0;
        for( int i = 0; i < testInput.length; i++ ) {
            try {
                String result = instance.getValidSafeHTML("test", testInput[i], 100, false);
                errors++;
                System.out.println("testGetValidSafeHTML(): testInput '" + testInput[i] + "' failed to throw.");
            }
            catch( ValidationException vex ) {
                System.out.println("testGetValidSafeHTML(): testInput '" + testInput[i] + "' returned:");
                System.out.println("\t" + i + ": logMsg =" + vex.getLogMessage());
                assertEquals( vex.getUserMessage(), "test: Invalid HTML input");
            }
            catch( Exception ex ) {
                errors++;
                System.out.println("testGetValidSafeHTML(): testInput '" + testInput[i] +
                                   "' threw wrong exception type: " + ex.getClass().getName() );
            }
        }

        if ( errors > 0 ) {
            fail("testGetValidSafeHTML() encountered " + errors + " failures.");
        }
    }

}
