package com.yahoo.athenz.zms;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.servlet.Servlets;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.glassfish.jersey.servlet.ServletContainer;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.jboss.resteasy.core.ResteasyDeploymentImpl;
import org.jboss.resteasy.plugins.server.undertow.UndertowJaxrsServer;
import org.jboss.resteasy.spi.ResteasyDeployment;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.servlet.ServletException;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashSet;
import java.util.Set;

import static com.yahoo.athenz.zms.ZMSClient.ZMS_CLIENT_PROP_CONNECT_TIMEOUT;
import static com.yahoo.athenz.zms.ZMSClient.ZMS_CLIENT_PROP_READ_TIMEOUT;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

@PowerMockIgnore("javax.net.ssl.*")
@PrepareForTest(ClientBuilder.class)
public class ZMSClientTimeoutTest extends PowerMockTestCase {

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
  public void testZTSClientReadTimeoutForJerseyContainer() throws ServletException {

    JerseyClientBuilder builder = new JerseyClientBuilder();
    PowerMockito.spy(ClientBuilder.class);
    PowerMockito.when(ClientBuilder.newBuilder()).thenReturn(builder);

    server = new UndertowServer(host, port, createJerseyRestHandler());
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
          "ResourceException (400): java.net.SocketTimeoutException: Read timed out");
    }
  }

  @Test
  public void testZTSClientReadTimeoutForRestEasyContainer() throws ServletException {

    ResteasyClientBuilder builder = new ResteasyClientBuilderImpl();
    PowerMockito.mockStatic(ClientBuilder.class);
    PowerMockito.when(ClientBuilder.newBuilder()).thenReturn(builder);

    server = new UndertowServer(host, port, createRestEasyRestHandler());
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

  private HttpHandler createRestEasyRestHandler() throws ServletException {
    ResteasyDeployment deployment = new ResteasyDeploymentImpl();
    deployment.setApplication(new Application());

    UndertowJaxrsServer server = new UndertowJaxrsServer();
    DeploymentInfo deploymentInfo =
        server
            .undertowDeployment(deployment, "/")
            .setClassLoader(UndertowServer.class.getClassLoader())
            .setContextPath("/zms")
            .setDeploymentName("ZMS");
    DeploymentManager deploymentManager = Servlets.defaultContainer().addDeployment(deploymentInfo);
    deploymentManager.deploy();
    return deploymentManager.start();
  }

  private HttpHandler createJerseyRestHandler() throws ServletException {
    DeploymentInfo deploymentInfo =
        Servlets.deployment()
            .setClassLoader(Application.class.getClassLoader())
            .setContextPath("/zms")
            .addServlets(
                Servlets.servlet("jerseyServlet", ServletContainer.class)
                    .setLoadOnStartup(1)
                    .addInitParam("javax.ws.rs.Application", Application.class.getName())
                    .addMapping("/*"))
            .setDeploymentName("ZMS");
    DeploymentManager deploymentManager = Servlets.defaultContainer().addDeployment(deploymentInfo);
    deploymentManager.deploy();
    return deploymentManager.start();
  }

  private class UndertowServer {
    private final String host;
    private final int port;
    private final HttpHandler restHandler;
    private Undertow undertow;

    public UndertowServer(final String host, final int port, final HttpHandler restHandler) {
      this.host = host;
      this.port = port;
      this.restHandler = restHandler;
    }

    public void start() {
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
  }

  private static class Application extends javax.ws.rs.core.Application {
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
  static class ZMSMockResource {

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
