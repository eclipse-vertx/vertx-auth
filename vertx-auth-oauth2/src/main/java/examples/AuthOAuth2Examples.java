/*
 * Copyright 2014 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package examples;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.*;

/**
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
public class AuthOAuth2Examples {

  public void example1(Vertx vertx) {

    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, new OAuth2ClientOptions()
            .setClientID("YOUR_CLIENT_ID")
            .setClientSecret("YOUR_CLIENT_SECRET")
            .setSite("https://github.com/login")
            .setTokenPath("/oauth/access_token")
            .setAuthorizationPath("/oauth/authorize")
    );

    // when there is a need to access a protected resource or call a protected method,
    // call the authZ url for a challenge

    String authorization_uri = oauth2.authorizeURL(new JsonObject()
        .put("redirect_uri", "http://localhost:8080/callback")
        .put("scope", "notifications")
        .put("state", "3(#0/!~"));

    // when working with web application use the above string as a redirect url

    // in this case GitHub will call you back in the callback uri one should now complete the handshake as:


    String code = "xxxxxxxxxxxxxxxxxxxxxxxx"; // the code is provided as a url parameter by github callback call

    oauth2.getToken(new JsonObject().put("code", code).put("redirect_uri", "http://localhost:8080/callback"), res -> {
      if (res.failed()) {
        // error, the code provided is not valid
      } else {
        // save the token and continue...
      }
    });
  }

  public void example2(Vertx vertx, HttpServerResponse response) {

    // Set the client credentials and the OAuth2 server
    OAuth2ClientOptions credentials = new OAuth2ClientOptions()
        .setClientID("<client-id>")
        .setClientSecret("<client-secret>")
        .setSite("https://api.oauth.com");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.AUTH_CODE, credentials);

    // Authorization oauth2 URI
    String authorization_uri = oauth2.authorizeURL(new JsonObject()
        .put("redirect_uri", "http://localhost:8080/callback")
        .put("scope", "<scope>")
        .put("state", "<state>"));

    // Redirect example using Vert.x
    response.putHeader("Location", authorization_uri)
        .setStatusCode(302)
        .end();

    JsonObject tokenConfig = new JsonObject()
        .put("code", "<code>")
        .put("redirect_uri", "http://localhost:3000/callback");

    // Callbacks
    // Save the access token
    oauth2.getToken(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        AccessToken token = res.result();
      }
    });
  }

  public void example3(Vertx vertx) {

    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.PASSWORD);

    JsonObject tokenConfig = new JsonObject()
        .put("username", "username")
        .put("password", "password");

    // Callbacks
    // Save the access token
    oauth2.getToken(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        AccessToken token = res.result();

        oauth2.api(HttpMethod.GET, "/users", new JsonObject().put("access_token", token.principal().getString("access_token")), res2 -> {
          // the user object should be returned here...
        });
      }
    });
  }

  public void example4(Vertx vertx) {

    // Set the client credentials and the OAuth2 server
    OAuth2ClientOptions credentials = new OAuth2ClientOptions()
        .setClientID("<client-id>")
        .setClientSecret("<client-secret>")
        .setSite("https://api.oauth.com");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.CLIENT, credentials);

    JsonObject tokenConfig = new JsonObject();

    // Callbacks
    // Save the access token
    oauth2.getToken(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        AccessToken token = res.result();
      }
    });
  }

  public void example5(AccessToken token) {
    // Check if the token is expired. If expired it is refreshed.
    if (token.expired()) {
      // Callbacks
      token.refresh(res -> {
        if (res.succeeded()) {
          // success
        } else {
          // error handling...
        }
      });
    }
  }

  public void example6(AccessToken token) {
    // Revoke only the access token
    token.revoke("access_token", res -> {
      // Session ended. But the refresh_token is still valid.

      // Revoke the refresh_token
      token.revoke("refresh_token", res1 -> {
        System.out.println("token revoked.");
      });
    });
  }

  public void example7(Vertx vertx) {
    // Set the client credentials and the OAuth2 server
    OAuth2ClientOptions credentials = new OAuth2ClientOptions()
        .setClientID("CLIENT_ID")
        .setClientSecret("CLIENT_SECRET")
        .setSite("https://accounts.google.com")
        .setTokenPath("https://www.googleapis.com/oauth2/v3/token")
        .setAuthorizationPath("/o/oauth2/auth");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.CLIENT, credentials);
  }

  public void example8(Vertx vertx) {
    // Set the client credentials and the OAuth2 server
    OAuth2ClientOptions credentials = new OAuth2ClientOptions()
        .setClientID("CLIENT_ID")
        .setClientSecret("CLIENT_SECRET")
        .setSite("https://github.com/login")
        .setTokenPath("/oauth/access_token")
        .setAuthorizationPath("/oauth/authorize");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.CLIENT, credentials);
  }

  public void example9(Vertx vertx) {
    // Set the client credentials and the OAuth2 server
    OAuth2ClientOptions credentials = new OAuth2ClientOptions()
        .setClientID("CLIENT_ID")
        .setClientSecret("CLIENT_SECRET")
        .setSite("https://www.linkedin.com")
        .setAuthorizationPath("/uas/oauth2/authorization")
        .setTokenPath("/uas/oauth2/accessToken");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.CLIENT, credentials);
  }

  public void example10(Vertx vertx) {
    // Set the client credentials and the OAuth2 server
    OAuth2ClientOptions credentials = new OAuth2ClientOptions()
        .setClientID("CLIENT_ID")
        .setClientSecret("CLIENT_SECRET")
        .setSite("https://api.twitter.com")
        .setAuthorizationPath("/oauth/authorize")
        .setTokenPath("/oauth/access_token");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.CLIENT, credentials);
  }

  public void example11(Vertx vertx) {
    // Set the client credentials and the OAuth2 server
    OAuth2ClientOptions credentials = new OAuth2ClientOptions()
        .setClientID("CLIENT_ID")
        .setClientSecret("CLIENT_SECRET")
        .setSite("https://www.facebook.com")
        .setAuthorizationPath("/dialog/oauth")
        .setTokenPath("https://graph.facebook.com/oauth/access_token");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.CLIENT, credentials);
  }

  public void example12(Vertx vertx) {
    // After setting up the application and users in keycloak export
    // the configuration json file from the web interface and save it to a file e.g.:

    JsonObject keycloakJson = new JsonObject(
        "{\n" +
        "  \"realm\": \"master\",\n" +
        "  \"realm-public-key\": " +
            "\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqGQkaBkiZWpUjFOuaabgfXgjzZzfJd0wozrS1" +
            "czX5qHNKG3P79P/UtZeR3wGN8r15jVYiH42GMINMs7R7iP5Mbm1iImge5p/7/dPmXirKOKOBhjA3hNTiV5B" +
            "lPDTQyiuuTAUEms5dY4+moswXo5zM4q9DFu6B7979o+v3kX6ZB+k3kNhP08wH82I4eJKoenN/0iCT7ALoG3" +
            "ysEJf18+HEysSnniLMJr8R1pYF2QRFlqaDv3Mqyp7ipxYkt4ebMCgE7aDzT6OrfpyPowObpdjSMTUXpcwIc" +
            "H8mIZCWFmyfF675zEeE0e+dHKkL1rPeCI7rr7Bqc5+1DS5YM54fk8xQwIDAQAB\",\n" +
        "  \"auth-server-url\": \"http://localhost:9000/auth\",\n" +
        "  \"ssl-required\": \"external\",\n" +
        "  \"resource\": \"frontend\",\n" +
        "  \"credentials\": {\n" +
        "    \"secret\": \"2fbf5e18-b923-4a83-9657-b4ebd5317f60\"\n" +
        "  }\n" +
        "}");

    // you can now use this config with the OAuth2 provider like this:
    KeycloakClientOptions keycloakConfig = new KeycloakClientOptions(keycloakJson);

    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.CLIENT, keycloakConfig);
  }

  public void example13(Vertx vertx) {
    // you can now use this config with the OAuth2 provider like this:
    KeycloakClientOptions keycloakConfig = new KeycloakClientOptions(new JsonObject("{...}"));

    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, OAuth2FlowType.PASSWORD, keycloakConfig);

    // first get a token (authenticate)
    oauth2.getToken(new JsonObject().put("username", "user").put("password", "secret"), res -> {
      if (res.failed()) {
        // error handling...
      } else {
        AccessToken token = res.result();

        // now check for permissions
        token.isAuthorised("account:manage-account", r -> {
          if (r.result()) {
            // this user is authorized to manage its account
          }
        });
      }
    });
  }
}
