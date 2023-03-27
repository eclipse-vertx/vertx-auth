package io.vertx.ext.auth;

import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.authorization.Attribute;
import io.vertx.ext.auth.authorization.Policy;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertTrue;

@RunWith(VertxUnitRunner.class)
public class PolicyTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void createPolicy() {
    Policy policy = new Policy();

    policy.addAttribute(Attribute.create("/principal/amr").in("mfa"));

    assertTrue(policy.getAttributes().size() == 1);
    User paulo = User.fromName("paulo");
    paulo.principal().put("amr", new JsonArray().add("mfa").add("pwd"));

    for (Attribute attribute : policy.getAttributes()) {
      assertTrue(attribute.match(paulo));
    }
  }
}
