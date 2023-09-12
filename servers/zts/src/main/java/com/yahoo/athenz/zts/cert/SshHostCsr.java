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

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A temporary class to help with transitioning to SSHCertRequest
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public class SshHostCsr {

    private String[] principals;
    private String[] xPrincipals;
    private String pubkey;
    private String reqip;
    private String requser;
    private String certtype;
    private String transid;

    public SshHostCsr() {
    }
    
    public String[] getPrincipals() {
        return principals;
    }
    public void setPrincipals(String[] principals) {
        this.principals = principals;
    }

    public String[] getXPrincipals() {
        return xPrincipals;
    }
    public void setXPrincipals(String[] xPrincipals) {
        this.xPrincipals = xPrincipals;
    }

    public String getPubkey() {
        return pubkey;
    }
    public void setPubkey(String pubkey) {
        this.pubkey = pubkey;
    }

    public String getReqip() {
        return reqip;
    }

    public void setReqip(String reqip) {
        this.reqip = reqip;
    }

    public String getRequser() {
        return requser;
    }

    public void setRequser(String requser) {
        this.requser = requser;
    }

    public String getCerttype() {
        return certtype;
    }

    public void setCerttype(String certtype) {
        this.certtype = certtype;
    }

    public String getTransid() {
        return transid;
    }

    public void setTransid(String transid) {
        this.transid = transid;
    }
}
