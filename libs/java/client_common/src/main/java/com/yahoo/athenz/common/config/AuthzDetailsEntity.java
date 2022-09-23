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

import java.util.List;

public class AuthzDetailsEntity {

    public final static String ENTITY_NAME_PREFIX = "zts.authorization_details_";

    private String type;
    private List<AuthzDetailsField> roles;
    private List<AuthzDetailsField> fields;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<AuthzDetailsField> getRoles() {
        return roles;
    }

    public void setRoles(List<AuthzDetailsField> roles) {
        this.roles = roles;
    }

    public List<AuthzDetailsField> getFields() {
        return fields;
    }

    public void setFields(List<AuthzDetailsField> fields) {
        this.fields = fields;
    }

    public boolean isValidField(final String fieldName) {

        if (fields != null) {
            for (AuthzDetailsField field : fields) {
                if (field.getName().equalsIgnoreCase(fieldName)) {
                    return true;
                }
            }
        }
        return false;
    }
}
