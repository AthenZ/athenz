package com.yahoo.athenz.zms.messaging;

import com.yahoo.athenz.common.messaging.DomainChangeMessage;

import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class DomainChangeMessageGenerator {

    public static DomainChangeMessage fromUri(String uri, Object... methodArgs) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        List<String> uriArgs = Arrays.stream(uri.split("/"))
            .filter(str -> !str.isEmpty())
            .collect(Collectors.toList());

        DomainChangeMessage domainChangeMessage = null;
        
        if (uriArgs.size() > 2) {
            DomainChangeMessage.ObjectType objectType = null;
            switch (uriArgs.get(2)) {
                case "entity":
                    objectType = DomainChangeMessage.ObjectType.ENTITY;
                    break;
                case "role":
                case "member":
                    objectType = DomainChangeMessage.ObjectType.ROLE;
                    break;
                case "group":
                    objectType = DomainChangeMessage.ObjectType.GROUP;
                    break;
                case "policy":
                    objectType = DomainChangeMessage.ObjectType.POLICY;
                    break;
                case "service":
                case "provDomain":
                case "tenancy":
                    objectType = DomainChangeMessage.ObjectType.SERVICE;
                    break;
                case "quota":
                    objectType = DomainChangeMessage.ObjectType.DOMAIN;
                    break;
            }
            if (objectType != null) {
                domainChangeMessage = genericUri(uriArgs, methodArgs, objectType);
            }
        }
        
        if (domainChangeMessage == null) {
            if (uriArgs.get(0).contains("domain")) {
                domainChangeMessage = domainUri(uriArgs, methodArgs);
            } else if (uriArgs.get(0).equals("user")) {
                domainChangeMessage = userUri(uriArgs, methodArgs);
            }
        }

        return domainChangeMessage;
    }
    
    public static DomainChangeMessage domainUri(List<String> uriArgs, Object[] methodArgs) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {

        String domainName = null;

        if (!uriArgs.get(0).equals("subdomain") && methodArgs[0] instanceof String) {
            domainName = (String) methodArgs[0];
        }

        // special case for sub-domain
        if (domainName == null && uriArgs.get(0).equals("subdomain") && uriArgs.size() == 3) {
            domainName = (String) methodArgs[1];
        }

        if (domainName == null) {
            // domain name is not part of the uri - fetch in reflection
            for (Object arg : methodArgs) {
                if (domainName == null && arg != null && !(arg instanceof String)) {
                    domainName = (String) arg.getClass().getMethod("getName").invoke(arg);
                }
            }
        }

        String objectName = domainName;
        long uriPlaceholderCount = uriArgs.stream()
            .filter(arg -> arg.startsWith("{"))
            .count();
        if (uriPlaceholderCount > 1) {
            objectName = (String) methodArgs[1];
        }

        if (domainName != null) {
            return new DomainChangeMessage()
                .setObjectType(DomainChangeMessage.ObjectType.DOMAIN)
                .setDomainName(domainName)
                .setObjectName(objectName);

        }
        return null;
    }

    private static DomainChangeMessage userUri(List<String> uriArgs, Object[] methodArgs) {
        String objectName = (String) methodArgs[0];
        return new DomainChangeMessage()
            .setObjectType(DomainChangeMessage.ObjectType.USER)
            .setObjectName(objectName);
    }

    private static DomainChangeMessage genericUri(List<String> uriArgs, Object[] methodArgs, DomainChangeMessage.ObjectType objectType) {

        String domainName = (String) methodArgs[0];
        String objectName;
        switch (uriArgs.get(2)) {
            case "provDomain":
                objectName = (String) methodArgs[2];
                break;
            case "quota":
                objectName = uriArgs.get(2);
                break;
            default:
                objectName = (String) methodArgs[1];
                break;
        }
        
        if (domainName != null) {
            return new DomainChangeMessage()
                .setObjectType(objectType)
                .setDomainName(domainName)
                .setObjectName(objectName);

        }
        return null;
    }
}
