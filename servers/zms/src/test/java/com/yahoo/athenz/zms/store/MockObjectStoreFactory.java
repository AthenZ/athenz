package com.yahoo.athenz.zms.store;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.common.server.store.ObjectStoreConnection;
import com.yahoo.athenz.common.server.store.ObjectStoreFactory;
import com.yahoo.athenz.zms.Domain;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class MockObjectStoreFactory implements ObjectStoreFactory {

    @Override
    public ObjectStore create(PrivateKeyStore pkeyStore) {
        ObjectStore mockObjectStore = mock(ObjectStore.class);
        try {
            ObjectStoreConnection mockObjectStoreCon = mock(ObjectStoreConnection.class);
            when(mockObjectStoreCon.getDomain(any())).thenReturn(mock(Domain.class));
            when(mockObjectStoreCon.insertDomain(any())).thenReturn(true);
            when(mockObjectStoreCon.insertRole(any(), any())).thenReturn(true);
            when(mockObjectStoreCon.insertRoleMember(any(), any(), any(), any(), any())).thenReturn(true);
            when(mockObjectStoreCon.insertPolicy(any(), any())).thenReturn(true);
            when(mockObjectStoreCon.insertAssertion(any(), any(), any(), any())).thenReturn(true);
            when(mockObjectStoreCon.insertServiceIdentity(any(), any())).thenReturn(true);
            when(mockObjectStoreCon.insertPublicKeyEntry(any(), any(), any())).thenReturn(true);
            when(mockObjectStore.getConnection(anyBoolean(), anyBoolean())).thenReturn(mockObjectStoreCon);
        } catch (ServerResourceException ex) {
            throw new RuntimeException(ex);
        }
        return mockObjectStore;
    }
}
