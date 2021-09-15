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
      .setClientId("YOUR_CLIENT_ID")
      .setClientSecret("YOUR_CLIENT_SECRET")
      .setSite("https://github.com/login")
      .setTokenPath("/oauth/access_token")
      .setAuthorizationPath("/oauth/authorize")
    );

    // when there is a need to access a protected resource
    // or call a protected method, call the authZ url for
    // a challenge

    String authorization_uri = oauth2.authorizeURL(new JsonObject()
      .put("redirect_uri", "http://localhost:8080/callback")
      .put("scope", "notifications")
      .put("state", "3(#0/!~"));

    // when working with web application use the above string as a redirect url

    // in this case GitHub will call you back in the callback uri one
    // should now complete the handshake as:

    // the code is provided as a url parameter by github callback call
    String code = "xxxxxxxxxxxxxxxxxxxxxxxx";

    oauth2.authenticate(
      new JsonObject()
        .put("code", code)
        .put("redirect_uri", "http://localhost:8080/callback"))
      .onSuccess(user -> {
        // save the token and continue...
      })
      .onFailure(err -> {
        // error, the code provided is not valid
      });
  }

  public void example2(Vertx vertx, HttpServerResponse response) {

    // Set the client credentials and the OAuth2 server
    OAuth2Options credentials = new OAuth2Options()
      .setFlow(OAuth2FlowType.AUTH_CODE)
      .setClientId("<client-id>")
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
    oauth2.authenticate(tokenConfig)
      .onSuccess(user -> {
        // Get the access token object
        // (the authorization code is given from the previous step).
      })
      .onFailure(err -> {
        System.err.println("Access Token Error: " + err.getMessage());
      });
  }

  public void example3(Vertx vertx) {

    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(
      vertx,
      new OAuth2Options()
        .setFlow(OAuth2FlowType.PASSWORD));

    JsonObject tokenConfig = new JsonObject()
      .put("username", "username")
      .put("password", "password");

    oauth2.authenticate(tokenConfig)
      .onSuccess(user -> {
        // Get the access token object
        // (the authorization code is given from the previous step).

        // you can now make requests using the
        // `Authorization` header and the value:
        String httpAuthorizationHeader = user.principal()
          .getString("access_token");

      })
      .onFailure(err -> {
        System.err.println("Access Token Error: " + err.getMessage());
      });
  }

  public void example4(Vertx vertx) {

    // Set the client credentials and the OAuth2 server
    OAuth2Options credentials = new OAuth2Options()
      .setFlow(OAuth2FlowType.CLIENT)
      .setClientId("<client-id>")
      .setClientSecret("<client-secret>")
      .setSite("https://api.oauth.com");


    // Initialize the OAuth2 Library
    OAuth2Auth oauth2 = OAuth2Auth.create(vertx, credentials);

    JsonObject tokenConfig = new JsonObject();

    oauth2.authenticate(tokenConfig)
      .onSuccess(user -> {
        // Success
      })
      .onFailure(err -> {
        System.err.println("Access Token Error: " + err.getMessage());
      });
  }

  public void example5(OAuth2Auth oauth2, User user) {
    // Check if the token is expired. If expired it is refreshed.
    if (user.expired()) {
      // Callbacks
      oauth2.refresh(user)
        .onSuccess(refreshedUser -> {
          // the refreshed user is now available
        })
        .onFailure(err -> {
          // error handling...
        });
    }
  }

  public void example6(OAuth2Auth oauth2, User user) {
    // Revoke only the access token
    oauth2.revoke(user, "access_token")
      .onSuccess(v -> {
        // Session ended. But the refresh_token is still valid.

        // Revoke the refresh_token
        oauth2.revoke(user, "refresh_token")
          .onSuccess(v2 -> {
            System.out.println("token revoked.");
          });
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
    OAuth2Auth oauth2 = KeycloakAuth
      .create(vertx, OAuth2FlowType.PASSWORD, keycloakJson);

    // first get a token (authenticate)
    oauth2.authenticate(
      new JsonObject()
        .put("username", "user")
        .put("password", "secret"))
      .onSuccess(user -> {
        // now check for permissions
        AuthorizationProvider authz = KeycloakAuthorization.create();

        authz.getAuthorizations(user)
          .onSuccess(v -> {
            if (
              RoleBasedAuthorization.create("manage-account")
                .setResource("account")
                .match(user)) {
              // this user is authorized to manage its account
            }
          });
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
    oauth2.authenticate(new JsonObject().put("access_token", "opaque string"))
      .onSuccess(theUser -> {
        // token is valid!
      });

    // User level
    oauth2.authenticate(user.principal())
      .onSuccess(authenticatedUser -> {
        // Token is valid!
      });
  }

  public void example16(OAuth2Auth oauth2) {
    // OAuth2Auth level
    oauth2.authenticate(new JsonObject().put("access_token", "jwt-token"))
      .onSuccess(theUser -> {
        // token is valid!
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
    if (
      PermissionBasedAuthorization.create("add-user")
        .setResource("realm")
        .match(user)) {
      // Yes the user can add users to the application
    }
  }

  public void example19(User user) {
    // the role is "finance"
    // the authority is "year-report"
    if (
      PermissionBasedAuthorization.create("year-report")
        .setResource("finance")
        .match(user)) {
      // Yes the user can access the year report from the finance department
    }
  }

  public void example20(OAuth2Auth oauth2, User user) {
    String logoutUrl = oauth2.endSessionURL(user);
    // redirect the user to the url computed in "logoutUrl"
    // ...
  }

  public void example21(User user) {
    // internal validation against, expiration date
    boolean isExpired = user.expired();
  }

  public void example22(OAuth2Auth oauth2, User user) {
    oauth2.refresh(user)
      .onSuccess(refreshedUser -> {
        // the refresh call succeeded
      })
      .onFailure(err -> {
        // the token was not refreshed, a best practise would be
        // to forcefully logout the user since this could be a
        // symptom that you're logged out by the server and this
        // token is not valid anymore.
      });
  }

  public void example23(OAuth2Auth oauth2, User user) {
    oauth2.revoke(user, "access_token")
      .onSuccess(v -> {
        // the revoke call succeeded
      })
      .onFailure(err -> {
        // the token was not revoked.
      });
  }

  public void example24(OAuth2Auth oauth2, User user) {
    oauth2.authenticate(user.principal())
      .onSuccess(validUser -> {
        // the introspection call succeeded
      })
      .onFailure(err -> {
        // the token failed the introspection. You should proceed
        // to logout the user since this means that this token is
        // not valid anymore.
      });
  }

  public void example25(Vertx vertx) {

    OpenIDConnectAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientId("clientId")
        .setClientSecret("clientSecret")
        .setSite("https://accounts.google.com"))
      .onSuccess(oauth2 -> {
        // the setup call succeeded.
        // at this moment your auth is ready to use and
        // google signature keys are loaded so tokens can be decoded and verified.
      })
      .onFailure(err -> {
        // the setup failed.
      });
  }

  public void example25b(Vertx vertx) {
    // keycloak example
    KeycloakAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientId("clientId")
        .setClientSecret("clientSecret")
        .setSite("http://keycloakhost:keycloakport/auth/realms/{realm}")
        .setTenant("your-realm"))
      .onSuccess(oauth2 -> {
        // ...
      });

    // Google example
    GoogleAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientId("clientId")
        .setClientSecret("clientSecret"))
      .onSuccess(oauth2 -> {
        // ...
      });

    // Salesforce example
    SalesforceAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientId("clientId")
        .setClientSecret("clientSecret"))
      .onSuccess(oauth2 -> {
        // ...
      });

    // Azure AD example
    AzureADAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientId("clientId")
        .setClientSecret("clientSecret")
        .setTenant("your-app-guid"))
      .onSuccess(oauth2 -> {
        // ...
      });

    // IBM Cloud example
    IBMCloudAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientId("clientId")
        .setClientSecret("clientSecret")
        .setSite("https://<region-id>.appid.cloud.ibm.com/oauth/v4/{tenant}")
        .setTenant("your-tenant-id"))
      .onSuccess(oauth2 -> {
        // ...
      });
  }

  public void example26(Vertx vertx) {

    OpenIDConnectAuth.discover(
      vertx,
      new OAuth2Options()
        .setClientId("clientId")
        .setTenant("your_realm")
        .setSite("http://server:port/auth/realms/{tenant}"))
      .onSuccess(oauth2 -> {
        // the setup call succeeded.
        // at this moment your auth is ready to use
      });
  }

  public void example21(OAuth2Auth oauth2) {
    // OAuth2Auth level
    oauth2.jWKSet()
      .onSuccess(v -> {
        // load was successful, if the server returned the header
        // `Cache-Control` with a `max-age` then a periodic task
        // will run at that time to refresh the keys
      });
  }

  public void example22(OAuth2Auth oauth2) {
    // OAuth2Auth level
    oauth2.missingKeyHandler(keyId -> {
      // we can now decide what to do:
      // 1. we can inspect the key id, does it make sense?
      if (keyId.equals("the-new-id")) {
        // 2. refresh the keys
        oauth2.jWKSet(res -> {
          // ...
        });
      }
    });
  }
}
