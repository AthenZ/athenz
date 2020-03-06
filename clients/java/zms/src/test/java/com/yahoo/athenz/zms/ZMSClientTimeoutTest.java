package com.yahoo.athenz.zms;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.servlet.Servlets;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import org.jboss.resteasy.core.ResteasyDeploymentImpl;
import org.jboss.resteasy.plugins.server.undertow.UndertowJaxrsServer;
import org.jboss.resteasy.spi.ResteasyDeployment;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.servlet.ServletException;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashSet;
import java.util.Set;

import static com.yahoo.athenz.zms.ZMSClient.ZMS_CLIENT_PROP_CONNECT_TIMEOUT;
import static com.yahoo.athenz.zms.ZMSClient.ZMS_CLIENT_PROP_READ_TIMEOUT;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class ZMSClientTimeoutTest {

  private static final int sleep = 2000; // mock api call sleeps for 2 seconds
  private int timeout = 1000; // http client should timeout after 1 second
  private String host = "0.0.0.0";
  private int port = 8080;
  private UndertowServer server;

  @BeforeMethod
  public void setUp() {
    System.setProperty(ZMS_CLIENT_PROP_READ_TIMEOUT, String.valueOf(timeout));
    System.setProperty(ZMS_CLIENT_PROP_CONNECT_TIMEOUT, String.valueOf(timeout));
  }

  @AfterMethod
  public void tearDown() {
    if (server != null) {
      server.stop();
    }
  }

  @Test
  public void testZMSClientReadTimeoutForRestEasy() throws ServletException {

    server = new UndertowServer(host, port);
    server.start();

    String baseUri = "http://localhost:" + port;
    ZMSClient zmsClient = new ZMSClient(baseUri);

    try {
      zmsClient.getDomain("test");
      fail("read timeout not set");
    } catch (ZMSClientException expected) {
      assertEquals(expected.code, ZMSClientException.BAD_REQUEST);
      assertEquals(
          expected.getMessage(),
          "ResourceException (400): RESTEASY004655: Unable to invoke request: java.net.SocketTimeoutException: Read timed out");
    }
  }

  private class UndertowServer {
    private String host;
    private int port;
    private Undertow undertow;

    public UndertowServer(final String host, final int port) {
      this.host = host;
      this.port = port;
    }

    public void start() throws ServletException {
      final HttpHandler restHandler = createRestHandler();
      final Undertow.Builder builder =
          Undertow.builder().addHttpListener(port, host).setHandler(restHandler);

      undertow = builder.build();
      undertow.start();
    }

    public void stop() {
      if (undertow != null) {
        undertow.stop();
        undertow = null;
      }
    }

    private HttpHandler createRestHandler() throws ServletException {
      ResteasyDeployment deployment = new ResteasyDeploymentImpl();
      deployment.setApplication(new Application());

      UndertowJaxrsServer server = new UndertowJaxrsServer();
      DeploymentInfo deploymentInfo =
          server
              .undertowDeployment(deployment, "/")
              .setClassLoader(UndertowServer.class.getClassLoader())
              .setContextPath("/zms")
              .setDeploymentName("ZMS");
      DeploymentManager deploymentManager =
          Servlets.defaultContainer().addDeployment(deploymentInfo);
      deploymentManager.deploy();
      return deploymentManager.start();
    }
  }

  class Application extends javax.ws.rs.core.Application {
    private final Set<Object> singletons;

    public Application() {
      this.singletons = new HashSet<>();
      this.singletons.add(new ZMSMockResource());
    }

    @Override
    public Set<Object> getSingletons() {
      return singletons;
    }
  }

  @Path("/v1")
  public static class ZMSMockResource {

    @Path("domain/{domainName}")
    @GET
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getDomain(@PathParam("domainName") String name) throws InterruptedException {
      Thread.sleep(sleep);
      Domain domain = new Domain();
      domain.name = name;
      return Response.status(Response.Status.OK).entity(domain).build();
    }
  }
}
