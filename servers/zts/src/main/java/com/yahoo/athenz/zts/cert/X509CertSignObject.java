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
package com.yahoo.athenz.zts.cert;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.ALWAYS)
public class X509CertSignObject {

    private String pem;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Integer expiryTime;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<Integer> x509ExtKeyUsage;
    
    public X509CertSignObject() {
    }
    
    public String getPem() {
        return pem;
    }
    
    public void setPem(String pem) {
        this.pem = pem;
    }

    public List<Integer> getX509ExtKeyUsage() {
        return x509ExtKeyUsage;
    }

    public void setX509ExtKeyUsage(List<Integer> x509ExtKeyUsage) {
        this.x509ExtKeyUsage = x509ExtKeyUsage;
    }

    public void setExpiryTime(Integer expiryTime) {
        this.expiryTime = expiryTime;
    }

    public Integer getExpiryTime() {
        return expiryTime;
    }
}
