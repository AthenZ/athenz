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

public class TestConsts {
    private TestConsts() {
        // Blocking CTOR for Consts class
    }
    // syncer config
    public final static String TEST_STATE_DIR = "state";
    public final static String TEST_STATE_DIR_EXPLICIT = "/etc/var/zmsyncstate";
    public final static String TEST_STATE_DIR_DEFAULT = "/opt/zms_syncer";
    public final static String TEST_SLEEP_INTERVAL = "120";
    public final static String TEST_AWS_BUCKET = "challenger_athenz_sync";
    public final static String TEST_AWS_CONNECT_TIMEOUT = "1976";
    public final static String TEST_AWS_REQUEST_TIMEOUT = "2016";
    public final static String TEST_AWS_KEY_ID = "alpharomeo";
    public final static String TEST_AWS_ACCESS_KEY = "a1b2c3";
    public final static String TEST_SVC_KEY_FILE = "test/keyFile";
    public final static String TEST_SVC_CERT_FILE = "test/certFile";
    public final static String TEST_TRUST_STORE_PATH = "/trustsource";
    public final static String TEST_TRUST_STORE_PASSWORD = "password";
    public final static String TEST_AWS_S3_REGION = "MARS";
    public final static String TEST_STATE_BUILDER_THREADS = "10";
    public final static String TEST_STATE_BUILDER_TIMEOUT = "1800";
}
