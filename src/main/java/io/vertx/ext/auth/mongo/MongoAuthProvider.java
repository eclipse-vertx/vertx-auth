package io.vertx.ext.auth.mongo;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.mongo.MongoService;

import java.util.List;

/**
 * This implementation of {@link AuthProvider} handles authorization and authentication based on MongoDb
 * 
 * @author mremme
 */

public class MongoAuthProvider implements AuthProvider {

  /**
   * This propertyname is used to set the logged in principal into the context
   */
  public static final String CURRENT_PRINCIPAL_PROPERTY         = "current.principal";

  /**
   * The property name to be used to set the name of the collection inside the config
   */
  public static final String PROPERTY_COLLECTION_NAME           = "collectionName";

  /**
   * The property name to be used to set the name of the field, where the username is stored inside
   */
  public static final String PROPERTY_USERNAME_FIELD            = "usernameField";

  /**
   * The property name to be used to set the name of the field, where the roles are stored inside
   */
  public static final String PROPERTY_ROLE_FIELD                = "roleField";

  /**
   * The property name to be used to set the name of the field, where the password is stored inside
   */
  public static final String PROPERTY_PASSWORD_FIELD            = "passwordField";

  /**
   * The property name to be used to set the name of the field, where the username for the credentials is stored inside
   */
  public static final String PROPERTY_CREDENTIAL_USERNAME_FIELD = "usernameCredentialField";

  /**
   * The property name to be used to set the name of the field, where the password for the credentials is stored inside
   */
  public static final String PROPERTY_CREDENTIAL_PASSWORD_FIELD = "passwordCredentialField";

  /**
   * The property name to be used to set the name of the field, where the SALT is stored inside
   */
  public static final String PROPERTY_SALT_FIELD                = "saltField";

  /**
   * The property name to be used to set the name of the field, where the salt style is stored inside
   * 
   * @see SaltStyle
   */
  public static final String PROPERTY_SALT_STYLE                = "saltStyle";

  /**
   * The property name to be used to set the name of the field, where the permissionsLookupEnabled is stored inside
   */
  public static final String PROPERTY_PERMISSIONLOOKUP_ENABLED  = "permissionsLookupEnabled";

  /**
   * The default name of the collection to be used
   */
  public static final String DEFAULT_COLLECTION_NAME            = "user";

  /**
   * The default name of the property for the username, like it is stored in mongodb
   */
  public static final String DEFAULT_USERNAME_FIELD             = "username";

  /**
   * The default name of the property for the password, like it is stored in mongodb
   */
  public static final String DEFAULT_PASSWORD_FIELD             = "password";

  /**
   * The default name of the property for the roles, like it is stored in mongodb. Roles are expected to be saved as
   * JsonArray
   */
  public static final String DEFAULT_ROLE_FIELD                 = "roles";

  /**
   * The default name of the property for the username, like it is transported in credentials by method
   * {@link #init(JsonObject)}
   */
  public static final String DEFAULT_CREDENTIAL_USERNAME_FIELD  = DEFAULT_USERNAME_FIELD;

  /**
   * The default name of the property for the password, like it is transported in credentials by method
   * {@link #init(JsonObject)}
   */
  public static final String DEFAULT_CREDENTIAL_PASSWORD_FIELD  = DEFAULT_PASSWORD_FIELD;

  /**
   * The default name of the property for the salt field
   */
  public static final String DEFAULT_SALT_FIELD                 = "salt";

  /**
   * Password hash salt configuration.
   * <ul>
   * <li>NO_SALT - password hashes are not salted.</li>
   * <li>CRYPT - password hashes are stored in unix crypt format.</li>
   * <li>COLUMN - salt is in a separate column in the database.</li>
   * <li>EXTERNAL - salt is not stored in the database. {@link #getSaltForUser(String)} will be called to get the salt</li>
   * </ul>
   */
  public enum SaltStyle {
    NO_SALT, CRYPT, COLUMN, EXTERNAL;
  };

  private final Vertx  vertx;
  private MongoService mongoService;
  private String       usernameField           = DEFAULT_USERNAME_FIELD;
  private String       passwordField           = DEFAULT_PASSWORD_FIELD;
  private String       roleField               = DEFAULT_ROLE_FIELD;
  private String       usernameCredentialField = DEFAULT_CREDENTIAL_USERNAME_FIELD;
  private String       passwordCredentialField = DEFAULT_CREDENTIAL_PASSWORD_FIELD;
  private String       saltField               = DEFAULT_SALT_FIELD;
  private String       collectionName          = DEFAULT_COLLECTION_NAME;

  private SaltStyle    saltStyle               = SaltStyle.NO_SALT;
  @SuppressWarnings("unused")
  private JsonObject   config;

  /**
   * 
   */
  public MongoAuthProvider(Vertx vertx, String serviceName, JsonObject config) {
    this(vertx, MongoService.createEventBusProxy(vertx, serviceName), config);
  }

  /**
   * 
   */
  public MongoAuthProvider(Vertx vertx, MongoService service, JsonObject config) {
    this.vertx = vertx;
    this.mongoService = service;
    this.config = config;
    init();
  }

  /**
   * Set the name of the collection to be used. Defaults to DEFAULT_COLLECTION_NAME
   * 
   * @param collectionName
   * @return
   */
  public MongoAuthProvider setCollectionName(String collectionName) {
    this.collectionName = collectionName;
    return this;
  }

  /**
   * Set the saltstyle as defined by enumeration {@link SaltStyle}. Defaults to DEFAULT_SALT_FIELD
   * 
   * @param saltStyle
   * @return
   */
  public MongoAuthProvider setSaltStyle(SaltStyle saltStyle) {
    switch (saltStyle) {
    case NO_SALT:
      break;
    case CRYPT:
      throw new UnsupportedOperationException("Not implemented yet, saltstyle " + saltStyle);
      //break;
    case COLUMN:
      throw new UnsupportedOperationException("Not implemented yet, saltstyle " + saltStyle);
    case EXTERNAL:
      throw new UnsupportedOperationException("Not implemented yet, saltstyle " + saltStyle);
    }
    this.saltStyle = saltStyle;
    return this;
  }

  /**
   * Set the name of the field to be used for the username. Defaults to DEFAULT_USERNAME_FIELD
   * 
   * @param fieldName
   * @return
   */
  public MongoAuthProvider setUsernameField(String fieldName) {
    this.usernameField = fieldName;
    return this;
  }

  /**
   * Set the name of the field to be used for the password Defaults to DEFAULT_PASSWORD_FIELD
   * 
   * @param fieldName
   * @return
   */
  public MongoAuthProvider setPasswordField(String fieldName) {
    this.passwordField = fieldName;
    return this;
  }

  /**
   * Set the name of the field to be used for the roles. Defaults to DEFAULT_ROLE_FIELD. Roles are expected to be saved
   * as JsonArray
   * 
   * @param fieldName
   * @return
   */
  public MongoAuthProvider setRoleField(String fieldName) {
    this.roleField = fieldName;
    return this;
  }

  /**
   * Set the name of the field to be used for the username. Defaults to DEFAULT_CREDENTIAL_USERNAME_FIELD
   * 
   * @param fieldName
   * @return
   */
  public MongoAuthProvider setUsernameCredentialField(String fieldName) {
    this.usernameCredentialField = fieldName;
    return this;
  }

  /**
   * Set the name of the field to be used for the password of credentials. Defaults to DEFAULT_CREDENTIAL_PASSWORD_FIELD
   * 
   * @param fieldName
   * @return
   */
  public MongoAuthProvider setPasswordCredentialField(String fieldName) {
    this.passwordCredentialField = fieldName;
    return this;
  }

  /**
   * Set the name of the field to be used for the salt ( if needed )
   * 
   * @param fieldName
   * @return
   */
  public MongoAuthProvider setSaltField(String fieldName) {
    this.saltField = fieldName;
    return this;
  }

  /**
   * Initializes the current provider by using the defined config object
   * 
   * @param config
   */
  private void init() {

    String collectionName = config.getString(PROPERTY_COLLECTION_NAME);
    if (collectionName != null) {
      setCollectionName(collectionName);
    }

    String usernameField = config.getString(PROPERTY_USERNAME_FIELD);
    if (usernameField != null) {
      setUsernameField(usernameField);
    }

    String passwordField = config.getString(PROPERTY_PASSWORD_FIELD);
    if (passwordField != null) {
      setPasswordField(passwordField);
    }

    String roleField = config.getString(PROPERTY_ROLE_FIELD);
    if (roleField != null) {
      setRoleField(roleField);
    }

    String usernameCredField = config.getString(PROPERTY_CREDENTIAL_USERNAME_FIELD);
    if (usernameCredField != null) {
      setUsernameCredentialField(usernameCredField);
    }

    String passwordCredField = config.getString(PROPERTY_CREDENTIAL_PASSWORD_FIELD);
    if (passwordCredField != null) {
      setPasswordCredentialField(passwordCredField);
    }

    String saltField = config.getString(PROPERTY_SALT_FIELD);
    if (saltField != null) {
      setSaltField(saltField);
    }

    String saltstyle = config.getString(PROPERTY_SALT_STYLE);
    if (saltstyle != null) {
      setSaltStyle(SaltStyle.valueOf(saltstyle));
    }

  }

  /*
   * (non-Javadoc)
   * @see io.vertx.ext.auth.AuthProvider#login(io.vertx.core.json.JsonObject, io.vertx.core.json.JsonObject,
   * io.vertx.core.Handler)
   */
  @Override
  public void login(JsonObject principal, JsonObject credentials, Handler<AsyncResult<Void>> resultHandler) {
    String username = principal.getString(this.usernameCredentialField);
    String password = credentials.getString(this.passwordCredentialField);

    // Null username is invalid
    if (username == null) {
      resultHandler.handle((Future.failedFuture(new AuthenticationException("Username must be set."))));
    }
    AuthToken token = new AuthToken(username, password);

    JsonObject query = createQuery(username);
    mongoService.find(this.collectionName, query, res -> {

      try {
        if (res.succeeded()) {
          JsonObject result = handleSelection(res, token);
          vertx.getOrCreateContext().put(CURRENT_PRINCIPAL_PROPERTY, result);
          resultHandler.handle(Future.succeededFuture());
        } else {
          resultHandler.handle(Future.failedFuture(res.cause()));
        }
      } catch (Throwable e) {
        resultHandler.handle(Future.failedFuture(e));
      }

    });

  }

  /*
   * (non-Javadoc)
   * @see io.vertx.ext.auth.AuthProvider#hasRole(io.vertx.core.json.JsonObject, java.lang.String, io.vertx.core.Handler)
   */
  @Override
  public void hasRole(JsonObject principalRequest, String role, Handler<AsyncResult<Boolean>> resultHandler) {
    if (!(principalRequest instanceof JsonObject))
      resultHandler.handle(Future.failedFuture(new IllegalArgumentException("JsonObject expected")));

    String username = principalRequest.getString(this.usernameCredentialField, null);

    // Null username is invalid
    if (username == null || username.isEmpty()) {
      resultHandler.handle((Future.failedFuture(new AuthenticationException("Username must be set."))));
    }

    JsonObject query = createQuery(username);
    mongoService.find(this.collectionName, query, res -> {

      try {
        if (res.succeeded()) {
          JsonObject principal = handleSelection(res, username);
          vertx.getOrCreateContext().put(CURRENT_PRINCIPAL_PROPERTY, principal);
          JsonArray roles = readRoles(principal);
          resultHandler.handle(Future.succeededFuture(roles != null && roles.contains(role)));
        } else {
          resultHandler.handle(Future.failedFuture(res.cause()));
        }
      } catch (Throwable e) {
        resultHandler.handle(Future.failedFuture(e));
      }

    });

  }

  protected JsonArray readRoles(JsonObject principal) {
    return principal.getJsonArray(this.roleField);
  }

  /**
   * Currently this is a call to {@link #hasRole(Object, String, Handler)}
   */
  @Override
  public void hasPermission(JsonObject principal, String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    hasRole(principal, permission, resultHandler);
  }

  /**
   * The default implementation uses the usernameField as search field
   * 
   * @param username
   * @return
   */
  protected JsonObject createQuery(String username) {
    return new JsonObject().put(usernameField, username);
  }

  /**
   * Examine the selection of found users and return one, if password is fitting,
   * 
   * @param resultList
   * @param username
   * @return
   */
  private JsonObject handleSelection(AsyncResult<List<JsonObject>> resultList, AuthToken authToken)
      throws AuthenticationException {
    if (resultList.result().size() > 1)
      throw new AuthenticationException("More than one user row found for user [" + authToken.username
          + "]. Usernames must be unique.");
    JsonObject principal = null;
    for (JsonObject json : resultList.result()) {
      if (handleObject(json, authToken) && principal != null)
        throw new AuthenticationException("Duplicate account [" + authToken.username + "]");
      principal = json;
    }
    if (principal == null)
      throw new AuthenticationException("No account found for user [" + authToken.username + "]");
    return principal;
  }

  /**
   * Examine the selection of found users and return first fitting one,
   * 
   * @param resultList
   * @param username
   * @return
   */
  private JsonObject handleSelection(AsyncResult<List<JsonObject>> resultList, String username)
      throws AuthenticationException {
    if (resultList.result().size() > 1)
      throw new AuthenticationException("More than one user row found for user [" + username
          + "]. Usernames must be unique.");
    if (resultList.result().isEmpty())
      throw new AuthenticationException("No account found for user [" + username + "]");
    return resultList.result().get(0);
  }

  /**
   * Examine the given user object. Returns true, if object fits the given authentication
   * 
   * @param userObject
   * @param authToken
   * @return
   * @throws AuthenticationException
   */
  private boolean handleObject(JsonObject userObject, AuthToken authToken) throws AuthenticationException {
    String password = getPasswordForUser(userObject);
    return password != null && password.equals(authToken.password);
  }

  private String getPasswordForUser(JsonObject userObject) {
    switch (saltStyle) {
    case NO_SALT:
      return userObject.getString(passwordField);

    default:
      throw new UnsupportedOperationException("Not implemented yet, saltstyle " + saltStyle);
    }
  }

  protected String getSaltForUser(String username) {
    return username;
  }

  /**
   * The incoming data from an authentication request
   * 
   * @author mremme
   */
  class AuthToken {
    String username;
    String password;

    AuthToken(String username, String password) {
      this.username = username;
      this.password = password;
    }
  }

  /**
   * @return the collectionName
   */
  public String getCollectionName() {
    return collectionName;
  }

  /**
   * @return the usernameField
   */
  public final String getUsernameField() {
    return usernameField;
  }

  /**
   * @return the passwordField
   */
  public final String getPasswordField() {
    return passwordField;
  }

  /**
   * @return the roleField
   */
  public final String getRoleField() {
    return roleField;
  }

  /**
   * @return the usernameCredentialField
   */
  public final String getUsernameCredentialField() {
    return usernameCredentialField;
  }

  /**
   * @return the passwordCredentialField
   */
  public final String getPasswordCredentialField() {
    return passwordCredentialField;
  }

  /**
   * @return the saltField
   */
  public final String getSaltField() {
    return saltField;
  }

  /**
   * @return the saltStyle
   */
  public final SaltStyle getSaltStyle() {
    return saltStyle;
  }

}
