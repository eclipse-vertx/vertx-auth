# Authentication and Authorisation Service for Vert.x

This Vert.x service provides authentication and authorisation functionality for use in your Vert.x applications.

Internally it currently delegates to [Apache Shiro](http://shiro.apache.org/) to handle the actual authentication and
authorisation but the design allows other, non Shiro auth providers to be used in the future.

The service uses a familiar user/role/permission model that you will probably be familiar with already:

Users can have one or more roles (e.g. "manager", "developer"). Roles can have one or more permissions (e.g.
"approve expenses", "submit_expenses").

Please see the service documentation (TODO - once docgen is complete this will be generated from the JavaDoc) for more 
information on this service.

## Authentication

The service allows you to *authenticate* (i.e. log-in) users with some *credentials* (usually username and password).

## Authorisation

The service allows you to check if users have specific roles or a set of roles, and it allows you to check if users
have specific permissions.

## Realm implementations

We currently support the following realm implementations out of the box:

### Properties

You store your user/role/permission information in a simple properties file.

### LDAP

Your user/role/permission information is stored in an LDAP server. This service will interact with the LDAP server
in order to authenticate and authorise your users.

### JDBC

TODO (waiting on JDBC service)

Your user/role/permission information is stored in a database. This service will interact with the database via JDBC
in order to authenticate and authorise your users.

### Other Shiro realms

You can plug-in any other Shiro `Realm` implementation and use that if you prefer.

## Configuration

### Properties realm

#### Properties file

Create a properties file, e.g. `vertx-users.properties`.

Each line should contain the username, password and roles for a user or permisions in a role.

For a user line it should be of the form:

    user.{username}={password},{roleName1},{roleName2},...,{roleNameN}
    
For a role line it should be of the form:
    
    role.{roleName}={permissionName1},{permissionName2},...,{permissionNameN}


Here's an example:

    user.tim = sausages,administrator,developer
    user.bob = socks,developer
    user.joe = manager
    role.administrator=*
    role.manager=play_golf,say_buzzwords
    role.developer=do_actual_work
    
#### How the properties file is found

You use the `properties_path` configuration element to define how the properties file is found.

The default value is `classpath:vertx-users.properties`.

If the value is prefixed with `classpath:` then the classpath will be searched for a properties file of that name.

If the value is prefixed with `file:` then it specifies a file on the file system.

If the value is prefixed with `url:` then it specifies a URL from where to load the properties.

### LDAP Realm

#### LDAP configuration

The following configuration properties are used to configure the LDAP realm:

* `ldap-user-dn-template` - this is used to determine the actual lookup to use when looking up a user with a particular
id. An example is `uid={0},ou=users,dc=foo,dc=com` - the element `{0}` is substituted with the user id to create the
actual lookup. This setting is mandatory.
* `ldap_url` - the url to the LDAP server. The url must start with `ldap://` and a port must be specified.
An example is `ldap:://myldapserver.mycompany.com:10389`
* `ldap-authentication-mechanism`
* `ldap-context-factory-class-name`
* `ldap-pooling-enabled`
* `ldap-referral`
* `ldap-system-username`
* `ldap-system-password`

## Examples

### Authentication
 
    Vertx vertx = Vert.vertx();
    JsonObject config = new JsonObject().put("classpath:myapp-users.properties");
    AuthService auth = AuthService.create(vertx, config);
    
    auth.login(new JsonObject().put("username", "tim").put("password", "sausages"), res -> {
      if (res.succeeded()) {
        if (res.result()) {
          System.out.println("Logged in ok");          
        } else {
          System,out.println("Login attempt failed");
        }
      } else {
        res.cause().printStackTrace();
    });
    
### Authorisation
  
    Vertx vertx = Vert.vertx();
    JsonObject config = new JsonObject().put("classpath:myapp-users.properties");
    AuthService auth = AuthService.create(vertx, config);
    
    auth.hasRole("tim", "developer", res -> {
      if (res.succeeded()) {
        System.out.println("Tim " + (res.result() ? "is" : "is not") + " developer");
      } else {
        res.cause().printStackTrace();
    });  
      