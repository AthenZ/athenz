package com.yahoo.athenz.common.messaging;

import org.mockito.Mockito;

public class MockDomainChangePublisher implements DomainChangePublisher {
    
    private final Recorder recorder = Mockito.mock(Recorder.class);
    private final String topicName;

    public MockDomainChangePublisher(String topicName) {
        this.topicName = topicName;
    }
    
    @Override
    public void publishMessage(DomainChangeMessage domainChangeMessage) {
        recorder.record(domainChangeMessage);
    }

    public Recorder getRecorder() {
        return recorder;
    }

    public String getTopicName() {
        return topicName;
    }

    public static class Recorder {
        public void record(DomainChangeMessage domainChangeMessage) {
        }
    } 
}
