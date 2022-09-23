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
package com.yahoo.athenz.zms_aws_json_domain_syncer;

public class TestConsts {
    private TestConsts() {
        // Blocking CTOR for Consts class
    }
    // syncer config
    public final static String TEST_STATE_DIR = "state";
    public final static String TEST_STATE_DIR_EXPLICIT = "/etc/var/zmsyncstate";
    public final static String TEST_STATE_DIR_DEFAULT = "/opt/zms_syncer";
    public final static String TEST_SLEEPINT = "120";
    public final static String TEST_IGNDOMS = "alpha,beta, gamma, delta , theta";
    public final static String TEST_AWSBUCK = "challenger_athenz_sync";
    public final static String TEST_AWSCONTO = "1976";
    public final static String TEST_AWSREQTO = "2016";
    public final static String TEST_ZMSCLTFACT = "com.yahoo.zms.cltfactimpl";
    public final static String TEST_AWSKEYID = "alpharomeo";
    public final static String TEST_AWSACCKEY = "a1b2c3";
    public final static String TEST_SVCKEYFILE = "test/keyFile";
    public final static String TEST_SVCCERTFILE = "test/certFile";
    public final static String TEST_TRUSTSOURCEPATH = "/trustsource";
    public final static String TEST_TRUSTSOURCEPASSWORD = "password";
    public final static String TEST_AWSREGION = "MARS";
    public final static String TEST_STATEBUILDERTHREADS = "10";
    public final static String TEST_STATEBUILDERTIMEOUT = "1800";
}
