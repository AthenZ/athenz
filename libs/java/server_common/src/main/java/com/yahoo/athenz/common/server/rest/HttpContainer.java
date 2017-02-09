/**
 * Copyright 2016 Yahoo Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.common.server.rest;

import java.util.HashSet;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.glassfish.hk2.utilities.binding.AbstractBinder;

public class HttpContainer {

    protected Server server = null;
    protected String banner = null;
    private HandlerCollection handlers = null;
    
    /** Currently not a public class. Use JettyContainer */
    protected HttpContainer() {
    }

    protected HashSet<Class<?>> resources = new HashSet<Class<?>>();
    protected HashSet<Object> singletons = new HashSet<Object>();
    protected HashSet<Class<?>> singletonsCheck = new HashSet<Class<?>>();

    /**
     * registers the resource classes with the jersey server.
     * @param classes the resource classes to register
     * @return this container, so calls may be chained
     */
    public HttpContainer resource(Class<?>... classes) {
        for (Class<?> classObject : classes) {
            resources.add(classObject);
        }
        return this;
    }

    /**
     * Inject the specified object as a singleton corresponding to the specified
     * target type. Any registered resource can access this with the @Context
     * injector.
     * @param <T> Describes the container type
     * @param targetType the type of the target injection (often an interface class object)
     * @param obj the object to use as a singleton for that type
     * @return this container, so calls may be chained
     */
    public <T> HttpContainer injectSingleton(final Class<T> targetType, final Object obj) {

        AbstractBinder binder = new AbstractBinder() {
            Class<T> type      = targetType;
            Object   singleton = obj;

            @Override
            protected void configure() {
                bind(type).in(javax.inject.Singleton.class);
                bind(type.cast(singleton)).to(type);
            }

            @Override
            public String toString() {
                StringBuilder sb = new StringBuilder(256);
                sb.append("Binder: contains type=").append(type).append(" and object=").append(singleton);
                return sb.toString();
            }
        };

        try {
            Class<?> componentClass = binder.getClass();
            if (singletonsCheck.contains(componentClass)) {
                throw new RuntimeException("Cannot create new registration for component type class "
                        + componentClass + ": Existing previous registration found for the type.");
            } else {
                singletonsCheck.add(componentClass);
            }
            singletons.add(binder);
            return this;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Register javax.ws.rs.container.ContainerRequestFilter's with this method.
     */
    public <T> HttpContainer addContainerRequestFilter(final Class<T> targetType) {

        AbstractBinder binder = new AbstractBinder() {
            Class<T> type = targetType;

            @Override
            protected void configure() {
                bind(type).to(javax.ws.rs.container.ContainerRequestFilter.class);
            }
        };

        try {
            singletons.add(binder);
            return this;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public <T> HttpContainer delegate(Class<T> targetType, Object singleton) {
        return injectSingleton(targetType, singleton);
    }

    public <T> HttpContainer delegate(AbstractBinder abstractBinder) {
        return injectSingleton(abstractBinder);
    }

    public HttpContainer injectSingleton(AbstractBinder abstractBinder) {
        singletons.add(abstractBinder);
        return this;
    }
    
    /**
     * Set the banner that get displayed when server is started up.
     * @param banner Banner text to be displayed
     */
    public void setBanner(String banner) {
        this.banner = banner;
    }
    
    public void createServer(int maxThreads) {
        
        // Setup Thread pool
        
        QueuedThreadPool threadPool = new QueuedThreadPool();
        threadPool.setMaxThreads(maxThreads);

        server = new Server(threadPool);
        setHandlers(new HandlerCollection());
        server.setHandler(getHandlers());
    }

    public Server getServer() {
        return server;
    }
    
    public void run(String base) {
        try {
            server.start();
            System.out.println("Jetty server running at " + banner);
            server.join();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }
    
    public void stop() {
        try {
            server.stop();
        } catch (Exception e) {
        }
    }

    public HandlerCollection getHandlers() {
        return handlers;
    }

    public void setHandlers(HandlerCollection handlers) {
        this.handlers = handlers;
    }
}
