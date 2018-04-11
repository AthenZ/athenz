/*
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.auth.util;

import static org.testng.Assert.*;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.util.Validate;

public class ValidateTest {

    @Test
    public void testPrincipalNameValidationInvalid() {
        
        assertFalse(Validate.principalName("user:john%doe"));
        assertFalse(Validate.principalName("user.user:john.doe."));
        assertFalse(Validate.principalName("user.user.:john.doe"));
        assertFalse(Validate.principalName(".user:doe"));
        assertFalse(Validate.principalName(".doe"));
        assertFalse(Validate.principalName(":doe"));
        assertFalse(Validate.principalName("doe:"));
        assertFalse(Validate.principalName("::doe"));
        assertFalse(Validate.principalName("doe::"));
        assertFalse(Validate.principalName("user:john:doe"));
    }
    
    @Test
    public void testPrincipalNameValidationValid() {
        
        assertTrue(Validate.principalName("user:doe"));
        assertTrue(Validate.principalName("user:doe"));
        assertTrue(Validate.principalName("user:john.doe"));
        assertTrue(Validate.principalName("user.user:doe"));
        assertTrue(Validate.principalName("user.user:john.doe"));
        assertTrue(Validate.principalName("user:john_doe"));
        assertTrue(Validate.principalName("john-doe"));
        assertTrue(Validate.principalName("user:john-doe"));
    }
    
    @Test
    public void testDomainNameValidationInvalid() {
        
        assertFalse(Validate.domainName("domain$sub"));
        assertFalse(Validate.domainName("coretech:domain"));
    }
    
    @Test
    public void testDomainNameValidationValid() {
        
        assertTrue(Validate.domainName("55"));
        assertTrue(Validate.domainName("3com.gov"));
        assertTrue(Validate.domainName("domain"));
        assertTrue(Validate.domainName("domain.sub.sub"));
        assertTrue(Validate.domainName("domain_"));
        assertTrue(Validate.domainName("_"));
        assertTrue(Validate.domainName("_test._"));
        assertTrue(Validate.domainName("sub1_sub2"));
        assertTrue(Validate.domainName("sub1_sub2_sub3"));
        assertTrue(Validate.domainName("sub1_sub2.sub3_sub4"));
        assertTrue(Validate.domainName("sub1_sub2_.sub3_sub4_"));
        assertTrue(Validate.domainName("sub1_sub2_.sub3_sub4_-"));
        assertTrue(Validate.domainName("domain-part"));
        assertTrue(Validate.domainName("com-test.gov"));
    }
}
