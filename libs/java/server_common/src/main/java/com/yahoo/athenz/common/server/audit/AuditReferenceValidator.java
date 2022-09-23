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
package com.yahoo.athenz.common.server.audit;

public interface AuditReferenceValidator {

    /**
     * Validate the Audit Reference for audit enabled domains
     * @param auditRef - Audit Reference provided for the change requested
     * @param principal - Domain principal for which the Audit Reference will be validated
     * @param operation - Operation requiring Audit Reference Validation
     * @return true if valid, else false
     */
    boolean validateReference(String auditRef, String principal, String operation);
}
