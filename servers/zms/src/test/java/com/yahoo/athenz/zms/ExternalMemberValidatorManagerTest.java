/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.ExternalMemberValidator;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.testng.Assert.*;

public class ExternalMemberValidatorManagerTest {

    private static final String TEST_VALIDATOR_CLASS = "com.yahoo.athenz.zms.TestExternalMemberValidator";

    @Mock private DBService dbService;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testRefreshValidatorsNewDomains() {

        Map<String, String> domainValidators = new HashMap<>();
        domainValidators.put("domain1", TEST_VALIDATOR_CLASS);
        domainValidators.put("domain2", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator()).thenReturn(domainValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        assertEquals(manager.getValidators().size(), 2);
        assertNotNull(manager.getValidators().get("domain1"));
        assertNotNull(manager.getValidators().get("domain2"));
        assertEquals(manager.getDomainValidatorClasses().size(), 2);

        manager.shutdown();
    }

    @Test
    public void testRefreshValidatorsRemoveDomains() {

        Map<String, String> initialValidators = new HashMap<>();
        initialValidators.put("domain1", TEST_VALIDATOR_CLASS);
        initialValidators.put("domain2", TEST_VALIDATOR_CLASS);

        Map<String, String> updatedValidators = new HashMap<>();
        updatedValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(initialValidators)
                .thenReturn(updatedValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        assertEquals(manager.getValidators().size(), 2);
        assertNotNull(manager.getValidators().get("domain1"));
        assertNotNull(manager.getValidators().get("domain2"));

        manager.refreshValidators();

        assertEquals(manager.getValidators().size(), 1);
        assertNotNull(manager.getValidators().get("domain1"));
        assertNull(manager.getValidators().get("domain2"));

        manager.shutdown();
    }

    @Test
    public void testRefreshValidatorsUpdateClass() {

        Map<String, String> initialValidators = new HashMap<>();
        initialValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Map<String, String> updatedValidators = new HashMap<>();
        updatedValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(initialValidators)
                .thenReturn(updatedValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        ExternalMemberValidator firstInstance = manager.getValidators().get("domain1");
        assertNotNull(firstInstance);

        manager.refreshValidators();

        ExternalMemberValidator secondInstance = manager.getValidators().get("domain1");
        assertNotNull(secondInstance);
        assertSame(firstInstance, secondInstance);

        manager.shutdown();
    }

    @Test
    public void testRefreshValidatorsClassChanged() {

        Map<String, String> initialValidators = new HashMap<>();
        initialValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Map<String, String> updatedValidators = new HashMap<>();
        updatedValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(initialValidators)
                .thenReturn(updatedValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);
        ExternalMemberValidator firstInstance = manager.getValidators().get("domain1");
        assertNotNull(firstInstance);

        manager.refreshValidators();

        ExternalMemberValidator secondInstance = manager.getValidators().get("domain1");
        assertSame(firstInstance, secondInstance);

        manager.shutdown();
    }

    @Test
    public void testRefreshValidatorsDbFailure() {

        Map<String, String> initialValidators = new HashMap<>();
        initialValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(initialValidators)
                .thenThrow(new ResourceException(500, "DB Error"));

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        assertEquals(manager.getValidators().size(), 1);

        manager.refreshValidators();

        assertEquals(manager.getValidators().size(), 1);
        assertNotNull(manager.getValidators().get("domain1"));

        manager.shutdown();
    }

    @Test
    public void testRefreshValidatorsInvalidClass() {

        Map<String, String> domainValidators = new HashMap<>();
        domainValidators.put("domain1", TEST_VALIDATOR_CLASS);
        domainValidators.put("domain2", "com.yahoo.athenz.zms.NonExistentValidator");

        Mockito.when(dbService.getDomainsWithExternalMemberValidator()).thenReturn(domainValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        assertEquals(manager.getValidators().size(), 1);
        assertNotNull(manager.getValidators().get("domain1"));
        assertNull(manager.getValidators().get("domain2"));

        manager.shutdown();
    }

    @Test
    public void testRefreshValidatorsEmptyMap() {

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(Collections.emptyMap());

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        assertTrue(manager.getValidators().isEmpty());

        manager.shutdown();
    }

    @Test
    public void testRefreshValidatorsAddNewDomain() {

        Map<String, String> initialValidators = new HashMap<>();
        initialValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Map<String, String> updatedValidators = new HashMap<>();
        updatedValidators.put("domain1", TEST_VALIDATOR_CLASS);
        updatedValidators.put("domain2", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(initialValidators)
                .thenReturn(updatedValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        assertEquals(manager.getValidators().size(), 1);

        manager.refreshValidators();

        assertEquals(manager.getValidators().size(), 2);
        assertNotNull(manager.getValidators().get("domain1"));
        assertNotNull(manager.getValidators().get("domain2"));

        manager.shutdown();
    }

    @Test
    public void testValidateMemberSuccess() {

        Map<String, String> domainValidators = new HashMap<>();
        domainValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator()).thenReturn(domainValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        manager.validateMember("domain1", "domain1:ext.user.validuser", "putMembership");

        manager.shutdown();
    }

    @Test
    public void testValidateMemberInvalid() {

        Map<String, String> domainValidators = new HashMap<>();
        domainValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator()).thenReturn(domainValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        try {
            manager.validateMember("domain1", "domain1:ext.user.invalid-member", "putMembership");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("user.invalid-member"));
            assertTrue(ex.getMessage().contains("domain1"));
        }

        manager.shutdown();
    }

    @Test
    public void testValidateMemberNoValidator() {

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(Collections.emptyMap());

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        try {
            manager.validateMember("domain1", "domain-without-validator:ext.user.anyuser", "putMembership");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("domain-without-validator"));
        }

        manager.shutdown();
    }

    @Test
    public void testNewValidatorInstanceSuccess() {

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(Collections.emptyMap());

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        ExternalMemberValidator validator = manager.newValidatorInstance(TEST_VALIDATOR_CLASS);
        assertNotNull(validator);
        assertTrue(validator instanceof TestExternalMemberValidator);

        manager.shutdown();
    }

    @Test
    public void testNewValidatorInstanceInvalidClass() {

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(Collections.emptyMap());

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        ExternalMemberValidator validator = manager.newValidatorInstance("com.invalid.NonExistentClass");
        assertNull(validator);

        manager.shutdown();
    }

    @Test
    public void testNewValidatorInstanceWrongType() {

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(Collections.emptyMap());

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        ExternalMemberValidator validator = manager.newValidatorInstance("java.lang.String");
        assertNull(validator);

        manager.shutdown();
    }

    @Test
    public void testShutdown() {

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(Collections.emptyMap());

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);
        manager.shutdown();
        manager.shutdown();
    }

    @Test
    public void testRefreshValidatorsAllDomainsRemoved() {

        Map<String, String> initialValidators = new HashMap<>();
        initialValidators.put("domain1", TEST_VALIDATOR_CLASS);
        initialValidators.put("domain2", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(initialValidators)
                .thenReturn(Collections.emptyMap());

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        assertEquals(manager.getValidators().size(), 2);

        manager.refreshValidators();

        assertTrue(manager.getValidators().isEmpty());

        manager.shutdown();
    }

    @Test
    public void testRefreshValidatorsClassChangedForDomain() {

        Map<String, String> initialValidators = new HashMap<>();
        initialValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Map<String, String> updatedValidators = new HashMap<>();
        updatedValidators.put("domain1", "com.yahoo.athenz.zms.NonExistentValidator");

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(initialValidators)
                .thenReturn(updatedValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        assertEquals(manager.getValidators().size(), 1);
        assertNotNull(manager.getValidators().get("domain1"));

        manager.refreshValidators();

        assertNull(manager.getValidators().get("domain1"));

        manager.shutdown();
    }

    @Test
    public void testGetDomainNamesWithValidatorMultipleDomains() {

        Map<String, String> domainValidators = new HashMap<>();
        domainValidators.put("domain1", TEST_VALIDATOR_CLASS);
        domainValidators.put("domain2", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator()).thenReturn(domainValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        Set<String> domainNames = manager.getDomainNamesWithValidator();
        assertEquals(domainNames.size(), 2);
        assertTrue(domainNames.contains("domain1"));
        assertTrue(domainNames.contains("domain2"));

        manager.shutdown();
    }

    @Test
    public void testGetDomainNamesWithValidatorEmpty() {

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(Collections.emptyMap());

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        Set<String> domainNames = manager.getDomainNamesWithValidator();
        assertTrue(domainNames.isEmpty());

        manager.shutdown();
    }

    @Test
    public void testGetDomainNamesWithValidatorUnmodifiable() {

        Map<String, String> domainValidators = new HashMap<>();
        domainValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator()).thenReturn(domainValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        Set<String> domainNames = manager.getDomainNamesWithValidator();

        try {
            domainNames.add("domain2");
            fail();
        } catch (UnsupportedOperationException ignored) {
        }

        try {
            domainNames.remove("domain1");
            fail();
        } catch (UnsupportedOperationException ignored) {
        }

        manager.shutdown();
    }

    @Test
    public void testGetDomainNamesWithValidatorAfterRefresh() {

        Map<String, String> initialValidators = new HashMap<>();
        initialValidators.put("domain1", TEST_VALIDATOR_CLASS);

        Map<String, String> updatedValidators = new HashMap<>();
        updatedValidators.put("domain1", TEST_VALIDATOR_CLASS);
        updatedValidators.put("domain2", TEST_VALIDATOR_CLASS);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(initialValidators)
                .thenReturn(updatedValidators);

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        Set<String> domainNames = manager.getDomainNamesWithValidator();
        assertEquals(domainNames.size(), 1);
        assertTrue(domainNames.contains("domain1"));

        manager.refreshValidators();

        domainNames = manager.getDomainNamesWithValidator();
        assertEquals(domainNames.size(), 2);
        assertTrue(domainNames.contains("domain1"));
        assertTrue(domainNames.contains("domain2"));

        manager.shutdown();
    }

    @Test
    public void testValidateMemberWithMockedValidator() {

        ExternalMemberValidator mockValidator = Mockito.mock(ExternalMemberValidator.class);
        Mockito.when(mockValidator.validateMember("domain1", "user.gooduser")).thenReturn(true);
        Mockito.when(mockValidator.validateMember("domain1", "user.baduser")).thenReturn(false);

        Mockito.when(dbService.getDomainsWithExternalMemberValidator())
                .thenReturn(Collections.emptyMap());

        ExternalMemberValidatorManager manager = new ExternalMemberValidatorManager(dbService);

        manager.getValidators().put("domain1", mockValidator);

        manager.validateMember("domain1", "domain1:ext.user.gooduser", "putMembership");

        try {
            manager.validateMember("domain1", "domain1:ext.user.baduser", "putMembership");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        Mockito.verify(mockValidator).validateMember("domain1", "user.gooduser");
        Mockito.verify(mockValidator).validateMember("domain1", "user.baduser");

        manager.shutdown();
    }
}
