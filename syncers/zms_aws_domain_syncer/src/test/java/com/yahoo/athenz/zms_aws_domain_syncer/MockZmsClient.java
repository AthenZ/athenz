/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms_aws_domain_syncer;

import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;

public class MockZmsClient {

    final static String[] domainUploadNames = { "coretech", "clouds", "moon", "pluto" };
    final static String[] domainDontUploadNames = { "coriander" };

    final static Timestamp CUR_TIME = Timestamp.fromMillis(Timestamp.fromCurrentTime().millis());
    final static Timestamp OLD_TIME = Timestamp.fromString("2016-04-19T12:04:32.044Z");

    public ZMSClient createClient() {

        ZMSClient mockZMSClient = Mockito.mock(ZMSClient.class);

        final SignedDomains sdList = setupSignedDomList();
        final Map<String, JWSDomain> jwsMap = setupJWSDomMap();

        // public SignedDomains getSignedDomains(String domainName, String metaOnly, String metaAttr,
        //      boolean masterCopy, String matchingTag, Map<String, List<String>> responseHeaders) {
        Mockito.doAnswer(new Answer<>() {
            public Object answer(InvocationOnMock invocation) {
                Object[] args = invocation.getArguments();
                if (args[5] != null) {
                    List<String> tagData = new ArrayList<>();
                    tagData.add(Timestamp.fromCurrentTime().toString());
                    ((HashMap) args[5]).put("tag", tagData);
                }
                return sdList;
            }
        }).when(mockZMSClient).getSignedDomains(eq(null), eq("true"), eq(null), eq(true), eq(null), eq(null));

        //public getJWSDomain(domainName, null, responseHeaders);
        Mockito.doAnswer(new Answer<JWSDomain>() {
            public JWSDomain answer(InvocationOnMock invocation) {
                return jwsMap.get((String) invocation.getArgument(0));
            }
        }).when(mockZMSClient).getJWSDomain(anyString(), eq(null), anyMap());
        return mockZMSClient;
    }

    static SignedDomains setupSignedDomList() {

        List<SignedDomain> sdList = new ArrayList<>();
        for (String domName: domainUploadNames) {
            SignedDomain signedDomain = new SignedDomain();
            DomainData domainData = new DomainData().setName(domName);
            signedDomain.setDomain(domainData);
            domainData.setModified(CUR_TIME);
            sdList.add(signedDomain);
        }

        for (String domName: domainDontUploadNames) {
            SignedDomain signedDomain = new SignedDomain();
            DomainData domainData = new DomainData().setName(domName);
            signedDomain.setDomain(domainData);
            domainData.setModified(OLD_TIME);
            sdList.add(signedDomain);
        }

        final SignedDomains sdoms = new SignedDomains();
        sdoms.setDomains(sdList);
        return sdoms;
    }

    static Map<String, JWSDomain> setupJWSDomMap() {

        Map<String, JWSDomain> jwsMap = new HashMap<>();
        for (String domName: domainUploadNames) {
            jwsMap.put(domName, TestUtils.createJWSDomain(domName, CUR_TIME));
        }

        for (String domName: domainDontUploadNames) {
            jwsMap.put(domName, TestUtils.createJWSDomain(domName, OLD_TIME));
        }

        return jwsMap;
    }
}
