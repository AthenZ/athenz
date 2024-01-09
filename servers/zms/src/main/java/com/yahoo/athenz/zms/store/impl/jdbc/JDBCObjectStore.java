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
package com.yahoo.athenz.zms.store.impl.jdbc;

import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zms.DomainOptions;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;

public class JDBCObjectStore implements ObjectStore {

    final PoolableDataSource rwSrc;
    PoolableDataSource roSrc;
    private int opTimeout = 60; //in seconds
    private int roleTagsLimit;
    private int domainTagsLimit;
    private int groupTagsLimit;
    private int serviceTagsLimit;
    private int policyTagsLimit;
    private DomainOptions domainOptions;
    private final Object synchronizer = new Object();

    public JDBCObjectStore(PoolableDataSource rwSrc, PoolableDataSource roSrc) {
        this.rwSrc = rwSrc;
        this.roSrc = roSrc;
        
        // if we're not given read-only source pool then we'll
        // be using the read-write for all operations
        
        if (this.roSrc == null) {
            this.roSrc = this.rwSrc;
        }
    }
    
    @Override
    public ObjectStoreConnection getConnection(boolean autoCommit, boolean readWrite) {
        final String caller = "getConnection";
        try {
            PoolableDataSource src = readWrite ? rwSrc : roSrc;
            JDBCConnection jdbcConn = new JDBCConnection(src.getConnection(), autoCommit);
            jdbcConn.setObjectSynchronizer(synchronizer);
            jdbcConn.setOperationTimeout(opTimeout);
            jdbcConn.setTagLimit(domainTagsLimit, roleTagsLimit, groupTagsLimit, policyTagsLimit, serviceTagsLimit);
            jdbcConn.setDomainOptions(domainOptions);
            return jdbcConn;
        } catch (Exception ex) {
            
            // if this was a read-only operation and we failed to get a connection
            // then we're going to try to get a connection from our read-write
            // pool first before throwing an exception
            
            if (!readWrite) {
                return getConnection(autoCommit, true);
            }
            
            // otherwise our service is not available and let the caller
            // retry the request if necessary
            
            throw ZMSUtils.error(ResourceException.SERVICE_UNAVAILABLE, ex.getMessage(), caller);
        }
    }
    
    @Override
    public void setOperationTimeout(int opTimeout) {
        this.opTimeout = opTimeout;
    }

    @Override
    public void setDomainOptions(DomainOptions domainOptions) {
        this.domainOptions = domainOptions;
    }

    @Override
    public void setTagLimit(int domainLimit, int roleLimit, int groupLimit, int policyLimit, int serviceLimit) {
        this.domainTagsLimit = domainLimit;
        this.roleTagsLimit = roleLimit;
        this.groupTagsLimit = groupLimit;
        this.policyTagsLimit = policyLimit;
        this.serviceTagsLimit = serviceLimit;
    }
    
    /**
     * Clear all connections to the object store. This is called when
     * the server tries to write some object to the database yet
     * database reports that it's not in write-only mode thus indicating
     * it failed over to another master. So we need to clear all our
     * connections and start new ones.
     */
    @Override
    public void clearConnections() {
        rwSrc.clearPoolConnections();
    }
}
