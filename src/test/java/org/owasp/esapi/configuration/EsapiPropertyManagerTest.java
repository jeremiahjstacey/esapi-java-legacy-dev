package org.owasp.esapi.configuration;



import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.configuration.consts.EsapiConfiguration;
import org.owasp.esapi.errors.ConfigurationException;

public class EsapiPropertyManagerTest {

    private static String propFilename1;
    private static String propFilename2;
    private static String xmlFilename1;
    private static String xmlFilename2;
    private static final String noSuchFile = "/invalidDir/noSubDir/nosuchFile.xml";

    private EsapiPropertyManager testPropertyManager;
    private static String DEVTEAM_CFG = "";
    private static String OPSTEAM_CFG = "";

    @BeforeAll
    public static void captureEsapiConfigurations() {
        DEVTEAM_CFG = System.getProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(),"");
        OPSTEAM_CFG = System.getProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(),"");
    }

    @AfterAll
    public static void restoreEsapiConfigurations() {
         System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), DEVTEAM_CFG);
         System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), OPSTEAM_CFG);
    }


    @BeforeEach
    public void init() {
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), "");
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), "");
        propFilename1 = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.properties";
        propFilename2 = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test-2.properties";
        xmlFilename1 = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test.xml";
        xmlFilename2 = "src" + File.separator + "test" + File.separator + "resources" + File.separator +
                "esapi" + File.separator + "ESAPI-test-2.xml";

    }
    @Test
    public void testPropertyManagerInitialized() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), propFilename2);

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // then
        assertNotNull(testPropertyManager.loaders);
        assertNotSame(0, testPropertyManager.loaders.size());
    }
    @Test
    public void testStringPropFoundInLoader() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        String propertyKey = "string_property";
        String expectedPropertyValue = "test_string_property";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedPropertyValue, propertyValue);
    }
    @Test
    public void testStringPropertyLoadedFromFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);

        String propertyKey = "string_property";
        String expectedValue = "test_string_property_2";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }
    @Test
    public void testStringPropertyLoadedFromPropFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), propFilename2);
        String propertyKey = "string_property";
        String expectedValue = "test_string_property_2";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }
    @Test
    public void testStringPropertyLoadedFromXmlFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);
        String propertyKey = "string_property";
        String expectedValue = "test_string_property_2";

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        String propertyValue = testPropertyManager.getStringProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }


    @Test
    public void testStringPropertyNotFoundByLoaderAndThrowException() {
        assertThrows (ConfigurationException.class, () -> {
            // given
            System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
            String propertyKey = "non.existing.property";

            // when
            try {
                testPropertyManager = new EsapiPropertyManager();
            } catch (IOException e) {
                fail(e.getMessage());
            }
            testPropertyManager.getStringProp(propertyKey);
        });

        // then expect exception
    }
    @Test
    public void testIntPropFoundInLoader() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        String propertyKey = "int_property";
        int expectedPropertyValue = 5;

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedPropertyValue, propertyValue);
    }
    @Test
    public void testIntPropertyLoadedFromFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);
        String propertyKey = "int_property";
        int expectedValue = 52;

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }
    @Test
    public void testIntPropertyLoadedFromPropFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), propFilename2);
        String propertyKey = "int_property";
        int expectedValue = 52;    // value from ESAPI-test-2.properties file

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }
    @Test
    public void testIntPropertyLoadedFromXmlFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);
        String propertyKey = "int_property";
        int expectedValue = 52;

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        int propertyValue = testPropertyManager.getIntProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }


    @Test
    public void testIntPropertyNotFoundByLoaderAndThrowException() {
        assertThrows (ConfigurationException.class, () -> {
            // given
            String propertyKey = "non.existing.property";

            // when
            try {
                testPropertyManager = new EsapiPropertyManager();
            } catch (IOException e) {
                fail(e.getMessage());
            }
            testPropertyManager.getIntProp(propertyKey);
        });
        // then expect exception
    }
    
    @Test
    public void testBooleanPropFoundInLoader() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        String propertyKey = "boolean_property";
        boolean expectedPropertyValue = true;

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        boolean propertyValue = testPropertyManager.getBooleanProp(propertyKey);

        // then
        assertEquals(expectedPropertyValue, propertyValue);
    }

    @Test
    public void testBooleanPropertyNotFoundByLoaderAndThrowException() {
        assertThrows (ConfigurationException.class, () -> {
            // given
            String propertyKey = "non.existing.property";

            // when
            try {
                testPropertyManager = new EsapiPropertyManager();
            } catch (IOException e) {
                fail(e.getMessage());
            }
            testPropertyManager.getBooleanProp(propertyKey);
        });
        // then expect exception
    }
    
    @Test
    public void testByteArrayPropFoundInLoader() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }
    @Test
    public void testByteArrayPropertyLoadedFromFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property_2");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }
    @Test
    public void testByteArrayPropertyLoadedFromPropFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), propFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), propFilename2);
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property_2");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }
    @Test
    public void testByteArrayPropertyLoadedFromXmlFileWithHigherPriority() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), xmlFilename1);
        System.setProperty(EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName(), xmlFilename2);
        String propertyKey = "string_property";
        byte[] expectedValue = new byte[0];
        try {
            expectedValue = ESAPI.encoder().decodeFromBase64("test_string_property_2");
        } catch (IOException e) {
            fail(e.getMessage());
        }

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            fail(e.getMessage());
        }
        byte[] propertyValue = testPropertyManager.getByteArrayProp(propertyKey);

        // then
        assertEquals(expectedValue, propertyValue);
    }

    @Test
    public void testByteArrayPropertyNotFoundByLoaderAndThrowException() {
        assertThrows (ConfigurationException.class, () -> {
            // given
            String propertyKey = "non.existing.property";

            // when
            try {
                testPropertyManager = new EsapiPropertyManager();
            } catch (IOException e) {
                fail(e.getMessage());
            }
            testPropertyManager.getByteArrayProp(propertyKey);
        });

        // then expect exception
    }
    @Test
    public void testExpectFileNotFoundException() {
        // given
        System.setProperty(EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName(), noSuchFile);

        // when
        try {
            testPropertyManager = new EsapiPropertyManager();
        } catch (IOException e) {
            if ( e instanceof FileNotFoundException ) {
                return;
            } else {
                fail("testExpectFileNotFoundException(): Was expecting FileNotFoundException for IOException. Exception:" + e);
            }
        }

        fail("Did not throw expected IOException for property file " + noSuchFile);
    }
}
