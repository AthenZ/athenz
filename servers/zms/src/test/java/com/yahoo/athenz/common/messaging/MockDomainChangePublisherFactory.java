package com.yahoo.athenz.common.messaging;

import com.yahoo.athenz.auth.PrivateKeyStore;

public class MockDomainChangePublisherFactory implements ChangePublisherFactory<DomainChangeMessage> {

    @Override
    public ChangePublisher<DomainChangeMessage> create(PrivateKeyStore keyStore, String topicName) {
        return new MockDomainChangePublisher(topicName);
    }
}
