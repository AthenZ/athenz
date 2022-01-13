package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.messaging.ChangePublisher;
import com.yahoo.athenz.common.messaging.ChangePublisherFactory;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;

public class FaultyDomainChangeFactory implements ChangePublisherFactory<DomainChangeMessage> {
    @Override
    public ChangePublisher<DomainChangeMessage> create(PrivateKeyStore keyStore, String topicName) {
        throw new IllegalStateException("invalid publisher");
    }
}