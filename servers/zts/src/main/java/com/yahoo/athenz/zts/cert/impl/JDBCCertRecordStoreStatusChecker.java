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

package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.status.StatusCheckException;
import com.yahoo.athenz.common.server.status.StatusChecker;

public class JDBCCertRecordStoreStatusChecker implements StatusChecker {

    private JDBCCertRecordStore jdbcCertRecordStore;

    JDBCCertRecordStoreStatusChecker(JDBCCertRecordStore jdbcCertRecordStore) {
        this.jdbcCertRecordStore = jdbcCertRecordStore;
    }

    @Override
    public void check() throws StatusCheckException {
        try (CertRecordStoreConnection certRecordStoreConnection = jdbcCertRecordStore.getConnection()) {
        } catch (Throwable e) {
            throw new StatusCheckException(e);
        }
    }
}
