package io.vertx.tests.audit;

import io.vertx.core.net.SocketAddress;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.audit.Marker;
import io.vertx.ext.auth.audit.SecurityAudit;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;
import io.vertx.ext.auth.authorization.AndAuthorization;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.RoleBasedAuthorization;
import org.junit.*;

public class AuditLoggerTest {

  @Test
  public void testSync() {

    SecurityAudit audit = SecurityAudit.create();

    // fake a request coming in
    audit.source(SocketAddress.inetSocketAddress(12345, "localhost"));
    audit.destination(SocketAddress.inetSocketAddress(8080, "localhost"));

    audit.credentials(new UsernamePasswordCredentials("paulo", "password"));
    audit.audit(Marker.AUTHENTICATION, true);
    // [AUTHENTICATION epoch="1674814080597" source="localhost" destination="localhost" password="********" username="paulo"] OK

    audit.user(User.fromName("paulo"));
    audit.authorization(
      AndAuthorization.create()
        .addAuthorization(PermissionBasedAuthorization.create("permission1"))
        .addAuthorization(RoleBasedAuthorization.create("role1"))
        .addAuthorization(PermissionBasedAuthorization.create("permission2"))
        .addAuthorization(RoleBasedAuthorization.create("role2")));

    audit.audit(Marker.AUTHORIZATION, false);
    // [AUTHORIZATION epoch="1674814080617" source="localhost" destination="localhost" subject="paulo" authorization="AND(PERMISSION[permission1], ROLE[role1], PERMISSION[permission2], ROLE[role2])"] FAIL

    audit.status(403);
    audit.audit(Marker.REQUEST, true);
    //[REQUEST epoch="1674814080618" source="localhost" destination="localhost" status=403] OK
  }
}
