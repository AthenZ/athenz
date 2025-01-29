package com.yahoo.athenz.common.server.notification;

import java.util.Objects;
import java.util.Set;

public class NotificationSlackMessage {

    private final String message;
    private final Set<String> recepients;

    public NotificationSlackMessage(String message, Set<String> recepients) {
        this.recepients = recepients;
        this.message = message;
    }

    public String getMessage() {
        return message;
    }


    public Set<String> getRecepients() {
        return recepients;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        NotificationSlackMessage that = (NotificationSlackMessage) o;
        return  Objects.equals(getMessage(), that.getMessage()) &&
                Objects.equals(getRecepients(), that.getRecepients());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getMessage(), getRecepients());
    }
}
