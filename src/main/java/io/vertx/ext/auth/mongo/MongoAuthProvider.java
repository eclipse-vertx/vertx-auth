package io.vertx.ext.auth.mongo;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.spi.AuthProvider;
import io.vertx.ext.mongo.MongoService;

import java.util.List;

/**
 * This implementation of {@link AuthProvider} handles authorization and authentication based on MongoDb
 * 
 * @author mremme
 */

public class MongoAuthProvider implements AuthProvider {

  /**
   * The property name to be used to set the name of the collection inside the config
   */
  public static final String PROPERTY_COLLECTION_NAME           = "collectionName";

  /**
   * The property name to be used to set the name of the field, where the username is stored inside
   */
  public static final String PROPERTY_USERNAME_FIELD            = "usernameField";

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
   * The property name to be used to set the name of the field, where the usernameMustUnique is stored inside
   */
  public static final String PROPERTY_USERNAME_UNIQUE           = "usernameMustUnique";

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
  private String       usernameField            = DEFAULT_USERNAME_FIELD;
  private String       passwordField            = DEFAULT_PASSWORD_FIELD;
  private String       usernameCredentialField  = DEFAULT_CREDENTIAL_USERNAME_FIELD;
  private String       passwordCredentialField  = DEFAULT_CREDENTIAL_PASSWORD_FIELD;
  private String       saltField                = DEFAULT_SALT_FIELD;
  private String       collectionName           = DEFAULT_COLLECTION_NAME;
  private boolean      usernameMustUnique       = false;
  private boolean      permissionsLookupEnabled = false;

  private SaltStyle    saltStyle                = SaltStyle.NO_SALT;
  @SuppressWarnings("unused")
  private JsonObject   config;

  /**
   * 
   */
  public MongoAuthProvider(Vertx vertx, String serviceName) {
    this(vertx, MongoService.createEventBusProxy(vertx, serviceName));
  }

  /**
   * 
   */
  public MongoAuthProvider(Vertx vertx, MongoService service) {
    this.vertx = vertx;
    this.mongoService = service;
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
   * Defines wether a username in the store must be unique or not. If not, then the combination of username and password
   * will define a fitting user
   * 
   * @param unique
   * @return
   */
  public MongoAuthProvider setUsernameMustUnique(boolean unique) {
    this.usernameMustUnique = unique;
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
   * Activate / deactivate permission lookup
   * 
   * @param permissionsLookupEnabled
   *          the permissionsLookupEnabled to set
   */
  public MongoAuthProvider setPermissionsLookupEnabled(boolean permissionsLookupEnabled) {
    this.permissionsLookupEnabled = permissionsLookupEnabled;
    return this;
  }

  /*
   * (non-Javadoc)
   * @see io.vertx.ext.auth.spi.AuthProvider#init(io.vertx.core.json.JsonObject)
   */
  @Override
  public void init(JsonObject config) {
    this.config = config;

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

    boolean permissionsLookupEnabled = config.getBoolean(PROPERTY_PERMISSIONLOOKUP_ENABLED, false);
    setPermissionsLookupEnabled(permissionsLookupEnabled);

    boolean usernameMustUnique = config.getBoolean(PROPERTY_USERNAME_UNIQUE, true);
    setUsernameMustUnique(usernameMustUnique);

  }

  /*
   * (non-Javadoc)
   * @see io.vertx.ext.auth.spi.AuthProvider#login(io.vertx.core.json.JsonObject, io.vertx.core.Handler)
   */
  @Override
  public void login(JsonObject credentials, Handler<AsyncResult<Object>> resultHandler) {
    String username = credentials.getString(this.usernameCredentialField);
    String password = credentials.getString(this.passwordCredentialField);

    // Null username is invalid
    if (username == null) {
      resultHandler.handle((Future.failedFuture(new AuthenticationException("Username must be set."))));
    }
    AuthToken token = new AuthToken(username, password);

    JsonObject query = createQuery(username);
    InternalHandler handler = new InternalHandler(token);
    mongoService.find(this.collectionName, query, handler);
    if (handler.result != null)
      resultHandler.handle(Future.succeededFuture(handler.result));
    else
      resultHandler.handle(Future.failedFuture(handler.exception));
  }

  /*
   * (non-Javadoc)
   * @see io.vertx.ext.auth.spi.AuthProvider#hasRole(java.lang.Object, java.lang.String, io.vertx.core.Handler)
   */
  @Override
  public void hasRole(Object principal, String role, Handler<AsyncResult<Boolean>> resultHandler) {
  }

  /*
   * (non-Javadoc)
   * @see io.vertx.ext.auth.spi.AuthProvider#hasPermission(java.lang.Object, java.lang.String, io.vertx.core.Handler)
   */
  @Override
  public void hasPermission(Object principal, String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    if (permissionsLookupEnabled) {
      throw new UnsupportedOperationException();
    }
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
    if (usernameMustUnique && resultList.result().size() > 1)
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
   * Handler for executing the query on Mongo.
   */
  class InternalHandler implements Handler<AsyncResult<List<JsonObject>>> {
    JsonObject result = null;
    Throwable  exception;

    AuthToken  authToken;

    InternalHandler(AuthToken authToken) {
      this.authToken = authToken;
    }

    @Override
    public void handle(AsyncResult<List<JsonObject>> res) {
      try {
        if (res.succeeded()) {
          result = handleSelection(res, authToken);
        } else {
          exception = res.cause();
        }
      } catch (Throwable e) {
        exception = e;
      }
    }

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

}
