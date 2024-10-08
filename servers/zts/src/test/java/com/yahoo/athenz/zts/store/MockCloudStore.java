/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.store;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import io.athenz.server.aws.common.creds.impl.TempCredsProvider;
import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.any;

public class MockCloudStore extends CloudStore {
    private String account = null;
    private String roleName = null;
    private String principal = null;
    private boolean returnSuperAWSRole = false;

    public MockCloudStore() {
        super();
        tempCredsProvider = Mockito.mock(TempCredsProvider.class);
    }

    @Override
    public boolean isAwsEnabled() {
        return true;
    }

    public void setMockFields(String account, String roleName, String principal) {
        this.account = account;
        this.roleName = roleName;
        this.principal = principal;
    }

    void setReturnSuperAWSRole(boolean returnSuperAWSRole) {
        this.returnSuperAWSRole = returnSuperAWSRole;
    }

    @Override
    public AWSTemporaryCredentials assumeAWSRole(String account, String roleName, String principal,
            Integer durationSeconds, String externalId, StringBuilder errorMessage) {

        if (!returnSuperAWSRole) {
            AWSTemporaryCredentials tempCreds = null;
            if (this.account.equals(account) && this.roleName.equals(roleName)
                    && this.principal.equals(principal)) {
                tempCreds = new AWSTemporaryCredentials();
            }

            return tempCreds;
        } else {
            return super.assumeAWSRole(account, roleName, principal, durationSeconds, externalId, errorMessage);
        }
    }

    public void setGetServiceException(int statusCode, boolean amazonException) throws ServerResourceException {
        int exStatusCode = amazonException ? statusCode : 400;
        Mockito.reset(tempCredsProvider);
        Mockito.when(tempCredsProvider.getTemporaryCredentials(any(), any(), any(), any(), any(), any()))
                .thenThrow(new ServerResourceException(exStatusCode, "error"));
    }
}
