package org.owasp.esapi.reference.accesscontrol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.esapi.AccessController;
import org.owasp.esapi.errors.AccessControlException;

/**
 * Answers the question: is the AccessController itself working properly?
 * @author Mike H. Fauzy
 *
 */
public class AccessControllerTest {

    protected AccessController accessController;

    @BeforeEach
    public void setup() {
        Map accessControlRules = new HashMap(3);
        accessControlRules.put("AlwaysTrue", new AlwaysTrueACR());
        accessControlRules.put("AlwaysFalse", new AlwaysFalseACR());
        accessControlRules.put("EchoRuntimeParameter", new EchoRuntimeParameterACR());
        accessController = new ExperimentalAccessController(accessControlRules);
    }

    @Test
    public void isAuthorized() {
        assertEquals("Rule Not Found: null", accessController.isAuthorized(null, null), false);
        assertEquals("Rule Not Found: Invalid Key", accessController.isAuthorized("A key that does not map to a rule", null), false);

        assertEquals("AlwaysTrue", accessController.isAuthorized("AlwaysTrue", null), true);
        assertEquals("AlwaysFalse", accessController.isAuthorized("AlwaysFalse", null), false);

        assertEquals("EchoRuntimeParameter: True", accessController.isAuthorized("EchoRuntimeParameter", Boolean.TRUE), true );
        assertEquals("EchoRuntimeParameter: False", accessController.isAuthorized("EchoRuntimeParameter", Boolean.FALSE), false);
        assertEquals("EchoRuntimeParameter: ClassCastException", accessController.isAuthorized("EchoRuntimeParameter", "This is not a boolean"), false);
        assertEquals("EchoRuntimeParameter: null Runtime Parameter", accessController.isAuthorized("EchoRuntimeParameter", null), false);
    }

    @Test
    public void enforceAuthorizationRuleNotFoundNullKey() throws Exception {
        assertThrows (AccessControlException.class, () -> {
            accessController.assertAuthorized(null, null);
        });
    }
    @Test
    public void enforceAuthorizationRuleAKeyThatDoesNotMapToARule() throws Exception {
        assertThrows (AccessControlException.class, () -> {
            accessController.assertAuthorized("A key that does not map to a rule", null);
        });
    }


    @Test
    //Should not throw an exception
    public void enforceAuthorizationAlwaysTrue() throws Exception {
        accessController.assertAuthorized("AlwaysTrue", null);
    }

    @Test
    public void enforceAuthorizationAlwaysFalse() throws Exception {
        assertThrows (AccessControlException.class, () -> {
            accessController.assertAuthorized("AlwaysFalse", null);
        });
    }

    /**
     * Ensure that isAuthorized does nothing if enforceAuthorization
     * is called and isAuthorized returns true
     */
    @Test
    //Should not throw an exception
    public void enforceAuthorizationEchoRuntimeParameterTrue() throws Exception {
        accessController.assertAuthorized("EchoRuntimeParameter", Boolean.TRUE);
    }

    /**
     * Ensure that isAuthorized translates into an exception if enforceAuthorization
     * is called and isAuthorized returns false
     */
    @Test
    public void enforceAuthorizationEchoRuntimeParameterFalse() throws Exception {
        assertThrows (AccessControlException.class, () -> {
            accessController.assertAuthorized("EchoRuntimeParameter", Boolean.FALSE);
        });
    }

    @Test
    public void enforceAuthorizationEchoRuntimeParameterClassCastException() throws Exception {
        assertThrows (AccessControlException.class, () -> {
            accessController.assertAuthorized("EchoRuntimeParameter", "This is not a boolean");
        });
    }

    @Test
    public void enforceAuthorizationEchoRuntimeParameterNullRuntimeParameter() throws Exception {
        assertThrows (AccessControlException.class, () -> {
            accessController.assertAuthorized("EchoRuntimeParameter", null);
        });
    }

    @Test
    public void delegatingACR() throws Exception {
        DelegatingACR delegatingACR = new DelegatingACR();
        DynaBeanACRParameter policyParameter = new DynaBeanACRParameter();

        delegatingACR = new DelegatingACR();
        policyParameter = new DynaBeanACRParameter();
        policyParameter.set("delegateClass", "java.lang.Object");
        policyParameter.set("delegateMethod", "equals");
        policyParameter.set("parameterClasses", new String[] {"java.lang.Object"});
        delegatingACR.setPolicyParameters(policyParameter);
        org.junit.Assert.assertFalse(delegatingACR.isAuthorized(new Object[] {new Object()}));
        org.junit.Assert.assertFalse(delegatingACR.isAuthorized(new Object[] {delegatingACR}));


        policyParameter.set("delegateClass", "org.owasp.esapi.reference.accesscontrol.AlwaysTrueACR");
        policyParameter.set("delegateMethod", "isAuthorized");
        policyParameter.set("parameterClasses", new String[] {"java.lang.Object"});
        delegatingACR.setPolicyParameters(policyParameter);
        org.junit.Assert.assertTrue(delegatingACR.isAuthorized(new Object[] {null}));

        delegatingACR = new DelegatingACR();
        policyParameter = new DynaBeanACRParameter();
        policyParameter.set("delegateClass", "org.owasp.esapi.reference.accesscontrol.AlwaysFalseACR");
        policyParameter.set("delegateMethod", "isAuthorized");
        policyParameter.set("parameterClasses", new String[] {"java.lang.Object"});
        delegatingACR.setPolicyParameters(policyParameter);
        org.junit.Assert.assertFalse(delegatingACR.isAuthorized(new Object[] {null}));
    }

}
