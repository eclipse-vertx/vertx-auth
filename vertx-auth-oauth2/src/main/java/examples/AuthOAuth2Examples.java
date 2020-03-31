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
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.AuthorizationProvider;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import io.vertx.ext.auth.oauth2.*;
import io.vertx.ext.auth.oauth2.authorization.KeycloakAuthorization;
import io.vertx.ext.auth.oauth2.providers.*;

/**
 * @author <a href="mailto:plopes@redhat.com">Paulo Lopes</a>
 */
public class AuthOAuth2Examples {

  public void example1(Vertx vertx) {

    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, new OAuth2Options()
      .setFlow(OAuth2FlowType.AUTH_CODE)
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

    oauth2.authenticate(new JsonObject().put("code", code).put("redirect_uri", "http://localhost:8080/callback"), res -> {
      if (res.failed()) {
        // error, the code provided is not valid
      } else {
        // save the token and continue...
      }
    });
  }

  public void example2(Vertx vertx, HttpServerResponse response) {

    // Set the client credentials and the OAuth2 server
    OAuth2Options credentials = new OAuth2Options()
      .setFlow(OAuth2FlowType.AUTH_CODE)
      .setClientID("<client-id>")
      .setClientSecret("<client-secret>")
      .setSite("https://api.oauth.com");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, credentials);

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
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        User token = res.result();
      }
    });
  }

  public void example3(Vertx vertx) {

    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, new OAuth2Options().setFlow(OAuth2FlowType.PASSWORD));

    JsonObject tokenConfig = new JsonObject()
      .put("username", "username")
      .put("password", "password");

    // Callbacks
    // Save the access token
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        User user = res.result();
        // you can now make requests using the `Authorization` header and the value:
        String httpAuthorizationHeader = user.principal().getString("access_token");
      }
    });
  }

  public void example4(Vertx vertx) {

    // Set the client credentials and the OAuth2 server
    OAuth2Options credentials = new OAuth2Options()
      .setFlow(OAuth2FlowType.CLIENT)
      .setClientID("<client-id>")
      .setClientSecret("<client-secret>")
      .setSite("https://api.oauth.com");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, credentials);

    JsonObject tokenConfig = new JsonObject();

    // Callbacks
    // Save the access token
    oauth2.authenticate(tokenConfig, res -> {
      if (res.failed()) {
        System.err.println("Access Token Error: " + res.cause().getMessage());
      } else {
        // Get the access token object (the authorization code is given from the previous step).
        User token = res.result();
      }
    });
  }

  public void example5(OAuth2Auth oauth2, User user) {
    // Check if the token is expired. If expired it is refreshed.
    if (user.expired()) {
      // Callbacks
      oauth2.refresh(user, res -> {
        if (res.succeeded()) {
          // success
        } else {
          // error handling...
        }
      });
    }
  }

  public void example6(OAuth2Auth oauth2, User user) {
    // Revoke only the access token
    oauth2.revoke(user, "access_token", res -> {
      // Session ended. But the refresh_token is still valid.

      // Revoke the refresh_token
      oauth2.revoke(user, "refresh_token", res1 -> System.out.println("token revoked."));
    });
  }

  public void example13(Vertx vertx) {
    // you would get this config from the keycloak admin console
    JsonObject keycloakJson = new JsonObject()
      .put("realm", "master")
      .put("realm-public-key", "MIIBIjANBgkqhk...wIDAQAB")
      .put("auth-server-url", "http://localhost:9000/auth")
      .put("ssl-required", "external")
      .put("resource", "frontend")
      .put("credentials", new JsonObject()
        .put("secret", "2fbf5e18-b923-4a83-9657-b4ebd5317f60"));

    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = KeycloakAuth.create(vertx, OAuth2FlowType.PASSWORD, keycloakJson);

    // first get a token (authenticate)
    oauth2.authenticate(new JsonObject().put("username", "user").put("password", "secret"), res -> {
      if (res.failed()) {
        // error handling...
      } else {
        User user = res.result();

        // now check for permissions
        AuthorizationProvider authz = KeycloakAuthorization.create();

        authz.getAuthorizations(user, res1 -> {
          if (res1.succeeded()) {
            if (RoleBasedAuthorization.create("manage-account").setResource("account").match(user)) {
              // this user is authorized to manage its account
            }
          }
        });
      }
    });
  }

  public void example14(User user) {
    // you can get the decoded `id_token` from the Keycloak principal
    JsonObject idToken = user.attributes().getJsonObject("idToken");

    // you can also retrieve some properties directly from the Keycloak principal
    // e.g. `preferred_username`
    String username = user.principal().getString("preferred_username");
  }


  public void example15(OAuth2Auth oauth2, User user) {
    // OAuth2Auth level
    oauth2.authenticate(new JsonObject().put("access_token", "opaque string"), res -> {
      if (res.succeeded()) {
        // token is valid!
        User accessToken = res.result();
      }
    });

    // User level
    oauth2.authenticate(user.principal(), res -> {
      if (res.succeeded()) {
        // Token is valid!
      }
    });
  }

  public void example16(OAuth2Auth oauth2) {
    // OAuth2Auth level
    oauth2.decodeToken("jwt-token", res -> {
      if (res.succeeded()) {
        // token is valid!
        User accessToken = res.result();
      }
    });
  }


  public void example17(User user) {
    // in this case it is assumed that the role is the current application
    if (PermissionBasedAuthorization.create("print").match(user)) {
      // Yes the user can print
    }
  }

  public void example18(User user) {
    // the resource is "realm"
    // the authority is "add-user"
    if (PermissionBasedAuthorization.create("add-user").setResource("realm").match(user)) {
      // Yes the user can add users to the application
    }
  }

  public void example19(User user) {
    // the role is "finance"
    // the authority is "year-report"
    if (PermissionBasedAuthorization.create("year-report").setResource("finance").match(user)) {
      // Yes the user can access the year report from the finance department
    }
  }

  public void example20(AccessToken user) {
    user.logout(res -> {
      if (res.succeeded()) {
        // the logout call succeeded
      } else {
        // the user might not have been logged out
        // to know why:
        System.err.println(res.cause());
      }
    });
  }

  public void example21(User user) {
    // internal validation against, expiration date
    boolean isExpired = user.expired();
  }

  public void example22(OAuth2Auth oauth2, User user) {
    oauth2.refresh(user, res -> {
      if (res.succeeded()) {
        // the refresh call succeeded
      } else {
        // the token was not refreshed, a best practise would be
        // to forcefully logout the user since this could be a
        // symptom that you're logged out by the server and this
        // token is not valid anymore.
      }
    });
  }

  public void example23(OAuth2Auth oauth2, User user) {
    oauth2.revoke(user, "access_token", res -> {
      if (res.succeeded()) {
        // the refresh call succeeded
      } else {
        // the token was not refreshed, a best practise would be
        // to forcefully logout the user since this could be a
        // symptom that you're logged out by the server and this
        // token is not valid anymore.
      }
    });
  }

  public void example24(OAuth2Auth oauth2, User user) {
    oauth2.authenticate(user.principal(), res -> {
      if (res.succeeded()) {
        // the introspection call succeeded
      } else {
        // the token failed the introspection. You should proceed
        // to logout the user since this means that this token is
        // not valid anymore.
      }
    });
  }

  public void example25(Vertx vertx) {

    OpenIDConnectAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientID("clientId")
        .setClientSecret("clientSecret")
        .setSite("https://accounts.google.com"),
      res -> {
        if (res.succeeded()) {
          // the setup call succeeded.
          // at this moment your auth is ready to use and
          // google signature keys are loaded so tokens can be decoded and verified.
        } else {
          // the setup failed.
        }
      });
  }

  public void example25b(Vertx vertx) {
    // keycloak example
    KeycloakAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientID("clientId")
        .setClientSecret("clientSecret")
        .setSite("http://keycloakhost:keycloakport/auth/realms/{realm}")
        .setTenant("your-realm"),
      res -> {
        // ...
      });

    // Google example
    GoogleAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientID("clientId")
        .setClientSecret("clientSecret"),
      res -> {
        // ...
      });

    // Salesforce example
    SalesforceAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientID("clientId")
        .setClientSecret("clientSecret"),
      res -> {
        // ...
      });

    // Azure AD example
    AzureADAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientID("clientId")
        .setClientSecret("clientSecret")
        .setTenant("your-app-guid"),
      res -> {
        // ...
      });

    // IBM Cloud example
    IBMCloudAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientID("clientId")
        .setClientSecret("clientSecret")
        .setSite("https://<region-id>.appid.cloud.ibm.com/oauth/v4/{tenant}")
        .setTenant("your-tenant-id"),
      res -> {
        // ...
      });
  }

  public void example26(Vertx vertx) {

    OpenIDConnectAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientID("clientId")
        .setTenant("your_realm")
        .setSite("http://server:port/auth/realms/{tenant}"),
      res -> {
        if (res.succeeded()) {
          // the setup call succeeded.
          // at this moment your auth is ready to use and
          // google signature keys are loaded so tokens can be decoded and verified.
        } else {
          // the setup failed.
        }
      });
  }
}
