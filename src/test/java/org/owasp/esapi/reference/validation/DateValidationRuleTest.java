package org.owasp.esapi.reference.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.owasp.esapi.PropNames.ACCEPT_LENIENT_DATES;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;

import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.ValidationException;
import org.powermock.reflect.Whitebox;

public class DateValidationRuleTest {

    private String testName;
    private ParseException testParseEx = new ParseException("Test Exception", 0);
    private Date testDate = new Date();
    private String dateString;
    private String canonDateString ;

    private String contextStr;
    private Encoder mockEncoder;
    private DateFormat testFormat = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.US);
    private DateValidationRule uit;

    @BeforeEach
    public void setup(TestInfo testInfo) {
        testName = testInfo.getDisplayName();
        mockEncoder = Mockito.mock(Encoder.class);
        testFormat = Mockito.spy(testFormat);
        uit = new DateValidationRule(testName, mockEncoder, testFormat);
        contextStr = testName;

        dateString = testFormat.format(testDate);
        canonDateString = dateString;
    }
    @Test
    public void testCtrNullDateFormatThrows() {
        IllegalArgumentException exEx = assertThrows(IllegalArgumentException.class, () ->{
            new DateValidationRule("context", mockEncoder, null);
        });
        
        assertTrue(exEx.getMessage().contains("DateValidationRule.setDateFormat requires a non-null DateFormat"));
    }
    @Test
    public void testCtrSetDateFormat() {
        DateFormat uitFormat = Whitebox.getInternalState(uit, "format");
        Assert.assertEquals(testFormat, uitFormat);
    }
    @Test
    public void testsetDateFormatNullThrows() {
        IllegalArgumentException exEx = assertThrows(IllegalArgumentException.class, () ->{
            uit.setDateFormat(null);
        });
        assertTrue(exEx.getMessage().contains("DateValidationRule.setDateFormat requires a non-null DateFormat"));
    }
    @Test
    public void testsetDateFormat() {
        boolean acceptLenient = ESAPI.securityConfiguration().getBooleanProp( ACCEPT_LENIENT_DATES );
        DateFormat newFormat = DateFormat.getDateInstance(DateFormat.SHORT, Locale.US);
        newFormat.setLenient(!acceptLenient);

        newFormat = Mockito.spy(newFormat);

        uit.setDateFormat(newFormat);
        DateFormat uitFormat = Whitebox.getInternalState(uit, "format");
        Assert.assertEquals(newFormat, uitFormat);
        Mockito.verify(newFormat).setLenient(acceptLenient);
    }
    @Test
    public void testGetValidNullInputAllowed() throws ValidationException {
        uit.setAllowNull(true);
        Date vDate = uit.getValid(contextStr, null);
        Assert.assertNull(vDate);
    }
    @Test
    public void testGetValidNullInputNotAllowed() throws ValidationException {
        ValidationException exEx = assertThrows(ValidationException.class, () ->{
            uit.setAllowNull(false);
            uit.getValid(contextStr, null);
        });        
        assertTrue(exEx.getMessage().contains("Input date required"));
    }
    @Test
    public void testGetValidNullInputNotAllowedEmptyString() throws ValidationException {
        ValidationException exEx = assertThrows(ValidationException.class, () ->{
            uit.setAllowNull(false);
            uit.getValid(contextStr, "");
        });
        assertTrue(exEx.getMessage().contains("Input date required"));
    }
    @Test
    public void testGetValidBadDateThrows() throws ValidationException, ParseException {

        Mockito.when(mockEncoder.canonicalize(dateString)).thenReturn(canonDateString);
        Mockito.doThrow(testParseEx).when(testFormat).parse(canonDateString);
        ValidationException exEx = assertThrows(ValidationException.class, () ->{
            uit.getValid(contextStr, dateString);
        });
        assertTrue(exEx.getMessage().contains(contextStr + ": Invalid date"));
        assertEquals(testParseEx, exEx.getCause());
    }
    @Test
    public void testGetValidHappyPath() throws ValidationException, ParseException {
        Mockito.when(mockEncoder.canonicalize(dateString)).thenReturn(canonDateString);
        Mockito.doReturn(testDate).when(testFormat).parse(canonDateString);

        Date date = uit.getValid(contextStr, dateString);
        Assert.assertEquals(testDate, date);
    }
    @Test
    public void testGetValidDateWithCruft() throws ValidationException, ParseException {
        String cruftyDate = canonDateString + "' union select * from another_table where user_id like '%";
        Mockito.when(mockEncoder.canonicalize(cruftyDate)).thenReturn(cruftyDate);
        Mockito.doReturn(testDate).when(testFormat).parse(cruftyDate);

        Date date = uit.getValid(contextStr, cruftyDate);
        Assert.assertEquals(testDate, date);
    }
    @Test
    public void testSanitizeNullInputAllowed() throws ValidationException {
        uit.setAllowNull(true);
        Date vDate = uit.sanitize(contextStr, null);
        Assert.assertNull(vDate);
    }
    @Test
    public void testSanitizeNullInputNotAllowed() throws ValidationException {
        uit.setAllowNull(false);
        Date date = uit.sanitize(contextStr, null);
        Assert.assertEquals(0, date.getTime());
    }
    @Test
    public void testSanitizeNullInputNotAllowedEmptyString() throws ValidationException {
        uit.setAllowNull(false);
        Date date = uit.sanitize(contextStr, "");
        Assert.assertEquals(0, date.getTime());
    }
    @Test
    public void testSanitizeBadDateReturnsDefault() throws ValidationException, ParseException {
        Mockito.when(mockEncoder.canonicalize(dateString)).thenReturn(canonDateString);
        Mockito.doThrow(testParseEx).when(testFormat).parse(canonDateString);

        Date date =  uit.sanitize(contextStr, dateString);
        Assert.assertEquals(0, date.getTime());
    }
    @Test
    public void testSanitizeErrorListContainsError() throws ValidationException, ParseException {
        ValidationErrorList vel = new ValidationErrorList();
        Mockito.when(mockEncoder.canonicalize(dateString)).thenReturn(canonDateString);
        Mockito.doThrow(testParseEx).when(testFormat).parse(canonDateString);

        Date date =  uit.sanitize(contextStr, dateString, vel);
        Assert.assertEquals(0, date.getTime());
        Assert.assertEquals(1, vel.size());
        ValidationException wrapper = vel.errors().get(0);
        Assert.assertEquals(testParseEx, wrapper.getCause());
    }
    @Test
    public void testSanitizeHappyPath() throws ValidationException, ParseException {
        Mockito.when(mockEncoder.canonicalize(dateString)).thenReturn(canonDateString);
        Mockito.doReturn(testDate).when(testFormat).parse(canonDateString);

        Date date = uit.sanitize(contextStr, dateString);
        Assert.assertEquals(testDate, date);
    }
    @Test
    public void testSanitizeDateWithCruft() throws ValidationException, ParseException {
        String cruftyDate = canonDateString + "' union select * from another_table where user_id like '%";
        Mockito.when(mockEncoder.canonicalize(cruftyDate)).thenReturn(cruftyDate);
        Mockito.doReturn(testDate).when(testFormat).parse(cruftyDate);

        Date date = uit.sanitize(contextStr, cruftyDate);
        Assert.assertEquals(0, date.getTime());
    }
    @Test
    public void testGithubIssue299() throws ParseException, ValidationException {
        Map<DateFormat, String> formatDateMap = new HashMap<>();
        formatDateMap.put(new SimpleDateFormat("dd/MM/yyyy"), "01/01/2aaa");
        formatDateMap.put(new SimpleDateFormat("yyyy/dd/MM"), "2aaa/01/01");
        formatDateMap.put(new SimpleDateFormat("dd/yyyy/MM"), "01/2012'SELECT * FROM user_table'/01");
        formatDateMap.put(new SimpleDateFormat("dd/MM/yyyy"),"01/01/2012'SELECT * FROM user_table'");
        formatDateMap.put(new SimpleDateFormat("dd/yyyy/MM"),"01/2aaa/01");
        formatDateMap.put(SimpleDateFormat.getDateInstance(SimpleDateFormat.LONG, Locale.US), "September 11, 2001' union select * from another_table where user_id like '%");

        for (Entry<DateFormat, String> pair : formatDateMap.entrySet()) {
            String cruftyDate = pair.getValue();
            Mockito.when(mockEncoder.canonicalize(cruftyDate)).thenReturn(cruftyDate);

            DateFormat lenientFormat = Mockito.spy(pair.getKey());
            lenientFormat.setLenient(true);
            Mockito.doNothing().when(lenientFormat).setLenient(ArgumentMatchers.anyBoolean());
            Mockito.doReturn(testDate).when(lenientFormat).parse(cruftyDate);

            DateFormat strictFormat = Mockito.spy(pair.getKey());
            strictFormat.setLenient(false);
            Mockito.doNothing().when(strictFormat).setLenient(ArgumentMatchers.anyBoolean());
            Mockito.doReturn(testDate).when(strictFormat).parse(cruftyDate);

            uit.setDateFormat(lenientFormat);
            Date lenientValidDate = uit.getValid(contextStr, cruftyDate);
            Assert.assertEquals("calls to getValid should not change the parsed date regardless of cruft",testDate, lenientValidDate);
            Date lenientSanitizedDate = uit.sanitize(contextStr, cruftyDate);
            Assert.assertEquals("calls to sanitize should return default date if cruft exists in input string",0, lenientSanitizedDate.getTime());

            uit.setDateFormat(strictFormat);
            Date strictValidDate = uit.getValid(contextStr, cruftyDate);
            Assert.assertEquals("calls to getValid should not change the parsed date regardless of cruft",testDate, strictValidDate);
            Date strictSanitizedDate = uit.sanitize(contextStr, cruftyDate);
            Assert.assertEquals("calls to sanitize should return default date if cruft exists in input string",0, strictSanitizedDate.getTime());
        }
    }
}
