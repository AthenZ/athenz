package io.athenz.syncer.common.zms;

import java.util.Map;

public interface StateFileBuilder {
    Map<String, DomainState> buildStateMap();
}
