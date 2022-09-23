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
package com.yahoo.athenz.zts.cache;

public class MemberRole {
    
    final String role;
    final long expiration;
    
    public MemberRole(String role, long expiration) {
        this.role = role;
        this.expiration = expiration;
    }

    public String getRole() {
        return role;
    }

    public long getExpiration() {
        return expiration;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (expiration ^ (expiration >>> 32));
        result = prime * result + ((role == null) ? 0 : role.hashCode());
        return result;
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
        MemberRole other = (MemberRole) obj;
        if (expiration != other.expiration) {
            return false;
        }
        if (role == null) {
            return other.role == null;
        } else {
            return role.equals(other.role);
        }
    }
}
