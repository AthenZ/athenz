/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.common.server.log.impl;

import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;

/**
 * Used for testing AuditLogFactory.
 */
public class TestLogger implements AuditLogger {
   
   Boolean throwException = false;
   
   public TestLogger() {
   }
   
   public TestLogger(Boolean throwExc) {
      if (throwExc != null) {
          throwException = throwExc;
      }
   }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogger#log(java.lang.String, java.lang.String)
     */
    @Override
    public void log(String logMsg, String msgVersionTag) {
        if (throwException.booleanValue()) {
           throw new RuntimeException(logMsg);
        }
    }

    /* (non-Javadoc)
     * @see com.yahoo.athenz.common.server.log.AuditLogger#log(com.yahoo.athenz.common.server.log.AuditLogMsgBuilder)
     */
    @Override
    public void log(AuditLogMsgBuilder msgBldr) {
       if (throwException.booleanValue()) {
           throw new RuntimeException(msgBldr.build());
        }
    }
 
}
