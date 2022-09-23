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

package com.yahoo.athenz.zts.cert.impl.crypki;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yahoo.athenz.common.server.cert.Priority;

@JsonInclude(JsonInclude.Include.ALWAYS)
public class X509CertificateSigningRequest {

    private KeyMeta keyMeta;
    private String csr;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public Integer validity;
    
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<Integer> extKeyUsage;
    
    public X509CertificateSigningRequest() {
    }
    
    public String getCsr() {
        return csr;
    }
    
    public void setCsr(String csr) {
        this.csr = csr;
    }

    @JsonProperty("ext_key_usage")
    public List<Integer> getExtKeyUsage() {
        return extKeyUsage;
    }

    public void setExtKeyUsage(List<Integer> extKeyUsage) {
        this.extKeyUsage = extKeyUsage;
    }

    public void setValidity(Integer validity) {
        this.validity = validity;
    }

    public Integer getValidity() {
        return validity;
    }
    
    @JsonProperty("key_meta")
    public KeyMeta getKeyMeta() {
        return keyMeta;
    }

    public void setKeyMeta(KeyMeta keyMeta) {
        this.keyMeta = keyMeta;
    }

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private Priority priority;

    public void setPriority(Priority priority) {
        this.priority = priority;
    }

    public Priority getPriority() {
        return priority;
    }
}
