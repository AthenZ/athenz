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

package com.yahoo.athenz.zts;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import org.testng.annotations.Test;

import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Validator;
import com.yahoo.rdl.Validator.Result;

public class ZTSCoreTest {
    
    @Test
    public void test() {
        ZTSSchema ztsSchema = new ZTSSchema();
        assertNotNull(ztsSchema);

        Schema schema = ZTSSchema.instance();
        assertNotNull(schema);
    }

    @Test
    public void testResourceNames() {
        String [] goodResources = {
            "domain:role.test1_",
            "domain:role._test1_",
            "domain:role._-test1_",
            "domain:role._-----",
            "domain:role._____",
            "3com:role.3role_-",
            "3com:entity",
            "_domain:3entity_",
            "domain:entity",
            "my.domain:entity",
            "my.domain:entity.path"
        };
        
        Schema schema = ZTSSchema.instance();
        Validator validator = new Validator(schema);
        
        for (String s : goodResources) {
            Result result = validator.validate(s, "ResourceName");
            assertTrue(result.valid);
        }

        String [] badResources = {
            "domain:role.-----",
            "-domain:role.role1",
            "Non_ascii:��",
            "cannot-start-with:-dash",
            "cannot-use:Punctuation_except_underbar!"
        };

        for (String s : badResources) {
            Result result = validator.validate(s, "ResourceName");
            assertFalse(result.valid);
        }
    }

    @Test
    public void testPathElement() {
        String [] goodPathElements = {
            "i-132432432143",
            "a-zA-Z0-9-._~=+@$,:",
            "a-23434$asdfdf-343",
            "abc:test-asdfdsf,234333",
            "abc~test"
        };
        
        Schema schema = ZTSSchema.instance();
        Validator validator = new Validator(schema);
        
        for (String s : goodPathElements) {
            Result result = validator.validate(s, "PathElement");
            assertTrue(result.valid, s);
        }

        String [] badPathElements = {
            "abc/test/atest",
            "abc%asdfadsfd",
            "Non_ascii:��",
            "asdf;test",
            "great!test",
            "query&element",
            "query?element"
        };

        for (String s : badPathElements) {
            Result result = validator.validate(s, "PathElement");
            assertFalse(result.valid, s);
        }
    }
    
    @Test
    public void AWSArnRoleName() {
        String [] goodAWSRoles = {
            "test-role",
            "test.role",
            "test@role=again+plus",
            "sso/test@role=again+plus",
            "eng/athenz/product/role_role1-role3",
            "eng/athenz-path/product/role_role1-role3",
            "eng/athenz.path_path2/product/role_role1-role3"
        };
        
        Schema schema = ZTSSchema.instance();
        Validator validator = new Validator(schema);
        
        for (String s : goodAWSRoles) {
            Result result = validator.validate(s, "AWSArnRoleName");
            assertTrue(result.valid, s);
        }

        String [] badAWSRoles = {
            "test:role",
            "Non_ascii:��",
            "/role1",
            "sso:role/role1",
            "sso+role/role2",
            "org//unit/role1"
        };

        for (String s : badAWSRoles) {
            Result result = validator.validate(s, "AWSArnRoleName");
            assertFalse(result.valid, s);
        }
    }
}
