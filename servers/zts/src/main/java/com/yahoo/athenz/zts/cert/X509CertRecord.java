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

import java.util.Date;

public class X509CertRecord {

    private String provider;
    private String instanceId;
    private String service;
    private String currentSerial;
    private Date currentTime;
    private String currentIP;
    private String prevSerial;
    private Date prevTime;
    private String prevIP;
    
    public X509CertRecord() {
    }
    
    public String getInstanceId() {
        return instanceId;
    }

    public void setInstanceId(String instanceId) {
        this.instanceId = instanceId;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }
    
    public String getCurrentSerial() {
        return currentSerial;
    }

    public void setCurrentSerial(String currentSerial) {
        this.currentSerial = currentSerial;
    }

    public Date getCurrentTime() {
        return currentTime;
    }

    public void setCurrentTime(Date currentTime) {
        this.currentTime = currentTime;
    }

    public String getCurrentIP() {
        return currentIP;
    }

    public void setCurrentIP(String currentIP) {
        this.currentIP = currentIP;
    }

    public String getPrevSerial() {
        return prevSerial;
    }

    public void setPrevSerial(String prevSerial) {
        this.prevSerial = prevSerial;
    }

    public Date getPrevTime() {
        return prevTime;
    }

    public void setPrevTime(Date prevTime) {
        this.prevTime = prevTime;
    }

    public String getPrevIP() {
        return prevIP;
    }

    public void setPrevIP(String prevIP) {
        this.prevIP = prevIP;
    }
}
