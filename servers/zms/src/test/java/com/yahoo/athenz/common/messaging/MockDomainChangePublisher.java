package com.yahoo.athenz.common.messaging;

import org.mockito.Mockito;

public class MockDomainChangePublisher implements DomainChangePublisher {
    
    private final Recorder recorder = Mockito.mock(Recorder.class);
    
    @Override
    public void publishMessage(DomainChangeMessage domainChangeMessage) {
        recorder.record(domainChangeMessage);
    }

    public Recorder getRecorder() {
        return recorder;
    }

    public static class Recorder {
        public void record(DomainChangeMessage domainChangeMessage) {
        }
    } 
}
