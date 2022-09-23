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
package com.yahoo.athenz.zms.config;

import java.util.Set;
import java.util.Map;

public class AllowedOperation {
    private String name;
    private Map<String, Set<String>> items;

    public enum MatchType {
        EQUALS,
        STARTS_WITH
    }

    public Map<String, Set<String>> getItems() {
        return items;
    }
    
    public void setItems(Map<String, Set<String>> items) {
        this.items = items;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public boolean isOperationAllowedOn(String opItemType, String opItemValue, MatchType matchType) {
        
        // if no operationItems are defined, always allow all 
        if (this.items == null || this.items.isEmpty()) {
            return true;
        }
        
        // if there are operations defined, and opItemType or opItemValue are empty, return false
        if (opItemType == null || opItemValue == null) {
            return false;
        }
        
        // if not empty, check and make sure the opItem type + value is found.
        opItemType = opItemType.toLowerCase();
        opItemValue = opItemValue.toLowerCase();
        Set<String> opItems = this.items.get(opItemType);
        if (opItems == null) {
            return false;
        }

        boolean result = false;
        switch (matchType) {
            case EQUALS:
                result = opItems.contains(opItemValue);
                break;
            case STARTS_WITH:
                for (String value : opItems) {
                    if (opItemValue.startsWith(value)) {
                        result = true;
                        break;
                    }
                }
                break;
        }
        return result;
    }
    
    @Override
    public int hashCode() {
        return items.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        
        if (obj == null) {
            return false;
        }
        
        if (getClass() != obj.getClass()) {
            return false;
        }
        
        AllowedOperation other = (AllowedOperation) obj;
        
        if (name == null) {
            return other.name == null;
        } else {
            return name.equals(other.name);
        }
    }
}
