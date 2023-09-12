package com.yahoo.athenz.common.messaging;

import org.mockito.Mockito;

public class MockDomainChangePublisher implements ChangePublisher<DomainChangeMessage> {
    
    private final Recorder recorder = Mockito.mock(Recorder.class);
    private final String topicName;
    private boolean throwPublishExceptions = false;

    public MockDomainChangePublisher(String topicName) {
        this.topicName = topicName;
    }
    
    public Recorder getRecorder() {
        return recorder;
    }

    public String getTopicName() {
        return topicName;
    }

    public void setThrowPublishExceptions(boolean throwPublishExceptions) {
        this.throwPublishExceptions = throwPublishExceptions;
    }

    @Override
    public void publish(DomainChangeMessage message) {
        if (throwPublishExceptions) {
            throw new IllegalArgumentException();
        } else {
            recorder.record(message);
        }
    }

    @Override
    public void close() {
    }

    public static class Recorder {
        public void record(DomainChangeMessage domainChangeMessage) {
        }
    } 
}
