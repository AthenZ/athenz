/**
 * Copyright 2017 Yahoo Inc.
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
package com.yahoo.athenz.zts.cert;

public class SSHCertificate {

    private String pem;
    private String cn;
    private String type;

    public SSHCertificate() {
    }
    
    public String getPem() {
        return pem;
    }
    
    public SSHCertificate setPem(String pem) {
        this.pem = pem;
        return this;
    }
    
    public String getCn() {
        return cn;
    }

    public SSHCertificate setCn(String cn) {
        this.cn = cn;
        return this;
    }

    public String getType() {
        return type;
    }

    public SSHCertificate setType(String type) {
        this.type = type;
        return this;
    }
}
