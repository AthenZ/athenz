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
package com.yahoo.athenz.zts;

import static org.testng.Assert.*;

import javax.ws.rs.WebApplicationException;

import org.testng.annotations.Test;

public class ResultObjectTest {

    @Test
    public void testDomainSignedPolicyDataResult() {
        GetDomainSignedPolicyDataResult object = new GetDomainSignedPolicyDataResult(null);

        try {
            object.done(101);
            fail();
        } catch (WebApplicationException ignored) {
        }
    }
    
    @Test
    public void testDomainSignedPolicyDataResultException() {
        GetDomainSignedPolicyDataResult object = new GetDomainSignedPolicyDataResult(null);
        DomainSignedPolicyData data = new DomainSignedPolicyData().setKeyId("test");
        try {
            object.done(101, data, "test");
            fail();
        } catch (WebApplicationException ignored) {
        }
    }
    
    @Test
    public void testDomainSignedPolicyDataResultException2() {
        GetDomainSignedPolicyDataResult object = new GetDomainSignedPolicyDataResult(null);
        try {
            object.done(101, "test");
            fail();
        } catch (WebApplicationException ignored) {
        }
    }
    
    @Test
    public void testPostInstanceeRegisterInformationResult() {
        PostInstanceRegisterInformationResult object = new PostInstanceRegisterInformationResult(null);

        try {
            object.done(101);
            fail();
        } catch (WebApplicationException ignored) {
        }
        
        try {
            InstanceIdentity identity = new InstanceIdentity();
            object.done(101, identity, "/zts/v1/instance/provider/domain/service/instanceid");
            fail();
        } catch (WebApplicationException ignored) {
        }
    }
    
    @Test
    public void testPostInstanceeRegisterInformationResultException() {
        PostInstanceRegisterInformationResult object = new PostInstanceRegisterInformationResult(null);
        DomainSignedPolicyData data = new DomainSignedPolicyData().setKeyId("test");
        try {
            object.done(101, data, "test");
            fail();
        } catch (WebApplicationException ignored) {
        }
    }
    
    @Test
    public void testPostInstanceeRegisterInformationResultException2() {
        PostInstanceRegisterInformationResult object = new PostInstanceRegisterInformationResult(null);
        try {
            object.done(101, "test");
            fail();
        } catch (WebApplicationException ignored) {
        }
    }
}
