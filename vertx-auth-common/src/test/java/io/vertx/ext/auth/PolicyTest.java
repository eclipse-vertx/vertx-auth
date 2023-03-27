package io.vertx.ext.auth;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.authorization.Attribute;
import io.vertx.ext.auth.authorization.Policy;
import io.vertx.ext.unit.junit.RunTestOnContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

@RunWith(VertxUnitRunner.class)
public class PolicyTest {

  @Rule
  public final RunTestOnContext rule = new RunTestOnContext();

  @Test
  public void createPolicy() {
    Policy policy = new Policy();

    policy.addAttribute(Attribute.create("/principal/amr").has("mfa"));

    assertEquals(1, policy.getAttributes().size());
    User paulo = User.fromName("paulo");
    paulo.principal().put("amr", new JsonArray().add("mfa").add("pwd"));

    for (Attribute attribute : policy.getAttributes()) {
      assertTrue(attribute.match(paulo));
    }
  }

  @Test
  public void testReadPolicyWithAttributes() {
    JsonObject json = new JsonObject(
      "{\n" +
        "  \"name\" : \"EU users\",\n" +
        "  \"attributes\" : {\n" +
        "    \"/attributes/location\" : {\n" +
        "      \"eq\" : \"EU\"\n" +
        "    }\n" +
        "  },\n" +
        "  \"authorizations\" : [ {\n" +
        "    \"type\" : \"wildcard\",\n" +
        "    \"permission\" : \"web:GET\",\n" +
        "    \"resource\" : \"/gdpr\"\n" +
        "  } ]\n" +
        "}"
    );

    Policy policy = new Policy(json);

    assertEquals(1, policy.getAttributes().size());
    for (Attribute attribute : policy.getAttributes()) {
      User user = User.fromName("paulo");
      user.attributes().put("location", "EU");
      assertTrue(attribute.match(user));
    }
  }
}
