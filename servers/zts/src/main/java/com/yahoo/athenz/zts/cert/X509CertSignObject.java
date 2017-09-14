/**
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
package com.yahoo.athenz.zts.cert;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(include = JsonSerialize.Inclusion.ALWAYS)
public class X509CertSignObject {

    private String pem;
    private String extusage;
    private int expire;
    
    public X509CertSignObject() {
    }
    
    public String getPem() {
        return pem;
    }
    
    public X509CertSignObject setPem(String pem) {
        this.pem = pem;
        return this;
    }

    public String getExtusage() {
        return extusage;
    }

    public X509CertSignObject setExtusage(String extusage) {
        this.extusage = extusage;
        return this;
    }

    public int getExpire() {
        return expire;
    }

    public X509CertSignObject setExpire(int expire) {
        this.expire = expire;
        return this;
    }
}
