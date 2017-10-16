/**
 * Copyright 2017 Yahoo Holdings, Inc.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;

public class SSHRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(SSHRequest.class);

    String ssh;
    String sshCertType;
    String sshReqType;
    
    public SSHRequest(String ssh, String sshCertType) {
        this.ssh = ssh;
        this.sshCertType = sshCertType;
    }

    public boolean validateType() {
        
        sshReqType = getSshKeyReqType();
        if (sshReqType == null) {
            return false;
        }
        
        // check if we need to validate the type
        
        if (sshCertType != null && !sshReqType.equals(sshCertType)) {
            LOGGER.error("validateType: Unable to validate ssh cert type: request {} vs required {}",
                    sshCertType, sshReqType);
            return false;
        }
        
        return true;
    }
    
    public String getSshReqType() {
        return sshReqType;
    }
    
    String getSshKeyReqType() {
        
        Struct keyReq = JSON.fromString(ssh, Struct.class);
        if (keyReq == null) {
            LOGGER.error("getSshKeyReqType: Unable to parse ssh key req: " + ssh);
            return null;
        }
        
        String sshType = keyReq.getString(ZTSConsts.ZTS_SSH_TYPE);
        if (sshType == null) {
            LOGGER.error("getSshKeyReqType: SSH Key request does not have certtype: " + ssh);
        }
        return sshType;
    }
}
