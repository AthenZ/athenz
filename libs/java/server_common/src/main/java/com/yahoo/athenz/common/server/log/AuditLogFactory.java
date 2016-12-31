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
package com.yahoo.athenz.common.server.log;

import com.yahoo.athenz.common.server.log.impl.DefaultAuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.impl.DefaultAuditLogger;

/**
 * Factory to produce Audit logging components.
 */
public class AuditLogFactory {

    /**
     * Get the default AuditLogger implementation.
     * @return default AuditLogger instance
     */
    static public AuditLogger getLogger() {
        return new DefaultAuditLogger();
    }

    /**
     * Create the AuditLogger from the given class name using its default constructor.
     * If the class name is null, then it returns the default AuditLogger.
     * @param auditLoggerClassName is name of class to instantiate as the AuditLogger
     * @return AuditLogger instance
     * @throws Exception class instantiation errors, ie. ReflectiveOperationException
     */
    static public AuditLogger getLogger(String auditLoggerClassName) throws Exception {
        if (auditLoggerClassName == null) {
            return getLogger();
        }
        
        AuditLogger impl = null;
        impl = (AuditLogger) Class.forName(auditLoggerClassName).newInstance();
 
        return impl;
    }

    /**
     * Create the AuditLogger from the given class name and provided parameter, using
     * the classes constructor that will take the parameter.
     * ex: AuditLogger logger = AuditLogFactory.getLogger("my_logger_class", new Integer(5));
     * @param auditLoggerClassName is name of class to instantiate as the AuditLogger
     * @param param is a parameter passed to the constructor of the specified Logger class
     * @return AuditLogger instance
     * @throws Exception class instantiation errors, ie. ReflectiveOperationException
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    static public AuditLogger getLogger(String auditLoggerClassName, Object param) throws Exception {
        if (param == null) {
            return getLogger(auditLoggerClassName);
        }
        Class paramClass  = param.getClass();
        Class loggerClass = Class.forName(auditLoggerClassName);
        return (AuditLogger) loggerClass.getConstructor(new Class[] {paramClass}).newInstance(paramClass.cast(param));
    }

    /**
     * Get the default AuditLogMsgBuilder implementation.
     * @return default AuditLogMsgBuilder instance
     */
    static public AuditLogMsgBuilder getMsgBuilder() {
        return new DefaultAuditLogMsgBuilder();
    }

    /**
     * Create the AuditLogMsgBuilder from the given class name using its default constructor.
     * If the class name is null, return the default AuditLogMsgBuilder.
     * @param auditLogMsgBuilderClassName is name of class to instantiate as an AuditLogMsgBuilder
     * @return AuditLogMsgBuilder instance
     * @throws Exception class instantiation errors, ie. ReflectiveOperationException
     */
    static public AuditLogMsgBuilder getMsgBuilder(String auditLogMsgBuilderClassName) throws Exception {
        if (auditLogMsgBuilderClassName == null) {
            return getMsgBuilder();
        }
        
        AuditLogMsgBuilder impl = null;
        impl = (AuditLogMsgBuilder) Class.forName(auditLogMsgBuilderClassName).newInstance();
 
        return impl;
    }
}
