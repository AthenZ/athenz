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
package com.yahoo.athenz.common.config;

import java.util.ArrayList;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.ALWAYS)
public class AthenzConfig {
    private String zmsUrl;
    private String ztsUrl;
    private ArrayList<PublicKeyEntry> zmsPublicKeys;
    private ArrayList<PublicKeyEntry> ztsPublicKeys;
    
    public String getZmsUrl() {
        return zmsUrl;
    }
    public void setZmsUrl(String zmsUrl) {
        this.zmsUrl = zmsUrl;
    }
    public String getZtsUrl() {
        return ztsUrl;
    }
    public void setZtsUrl(String ztsUrl) {
        this.ztsUrl = ztsUrl;
    }
    public ArrayList<PublicKeyEntry> getZmsPublicKeys() {
        return zmsPublicKeys;
    }
    public void setZmsPublicKeys(ArrayList<PublicKeyEntry> zmsPublicKeys) {
        this.zmsPublicKeys = zmsPublicKeys;
    }
    public ArrayList<PublicKeyEntry> getZtsPublicKeys() {
        return ztsPublicKeys;
    }
    public void setZtsPublicKeys(ArrayList<PublicKeyEntry> ztsPublicKeys) {
        this.ztsPublicKeys = ztsPublicKeys;
    }
}
