package com.yahoo.athenz.common.messaging;

public class MockDomainChangePublisherFactory implements DomainChangePublisherFactory {

    @Override
    public DomainChangePublisher create(String topicName) {
        return new MockDomainChangePublisher(topicName);
    }
}
