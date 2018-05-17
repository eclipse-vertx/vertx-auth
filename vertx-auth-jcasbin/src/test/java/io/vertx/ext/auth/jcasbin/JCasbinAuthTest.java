// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package io.vertx.ext.auth.jcasbin;

import io.vertx.ext.auth.jcasbin.impl.JCasbinUser;
import io.vertx.test.core.VertxTestBase;
import org.junit.Test;


/**
 *
 * @author Yang Luo
 */
public class JCasbinAuthTest extends VertxTestBase {

  private void testAuthzRequest(String username, String path, String method, boolean res) {
    JCasbinUser user = new JCasbinUser(username);

    user.isAuthorized(path + "::" + method, result -> {
      boolean myRes = result.succeeded();
      if (myRes != res) {
        org.junit.Assert.fail(String.format("%s, %s, %s: %b, supposed to be %b", username, path, method, myRes, res));
      }
    });
  }

  @Test
  public void testBasic() {
    // This example shows how to control the access to any RESTful path with jCasbin.
    // true -> permit
    // false -> deny

    testAuthzRequest("alice", "/dataset1/resource1", "GET", true);
    testAuthzRequest("alice", "/dataset1/resource1", "POST", true);
    testAuthzRequest("alice", "/dataset1/resource2", "GET", true);
    testAuthzRequest("alice", "/dataset1/resource2", "POST", false);
  }

  @Test
  public void testPathWildcard() {
    // This example shows how to control the access to any RESTful path with jCasbin.
    // true -> permit
    // false -> deny

    testAuthzRequest("bob", "/dataset2/resource1", "GET", true);
    testAuthzRequest("bob", "/dataset2/resource1", "POST", true);
    testAuthzRequest("bob", "/dataset2/resource1", "DELETE", true);
    testAuthzRequest("bob", "/dataset2/resource2", "GET", true);
    testAuthzRequest("bob", "/dataset2/resource2", "POST", false);
    testAuthzRequest("bob", "/dataset2/resource2", "DELETE", false);

    testAuthzRequest("bob", "/dataset2/folder1/item1", "GET", false);
    testAuthzRequest("bob", "/dataset2/folder1/item1", "POST", true);
    testAuthzRequest("bob", "/dataset2/folder1/item1", "DELETE", false);
    testAuthzRequest("bob", "/dataset2/folder1/item2", "GET", false);
    testAuthzRequest("bob", "/dataset2/folder1/item2", "POST", true);
    testAuthzRequest("bob", "/dataset2/folder1/item2", "DELETE", false);
  }

  @Test
  public void testRBAC() {
    // This example shows how to control the access to any RESTful path with jCasbin.
    // true -> permit
    // false -> deny

    // cathy can access all /dataset1/* resources via all methods because it has the dataset1_admin role.
    testAuthzRequest("cathy", "/dataset1/item", "GET", true);
    testAuthzRequest("cathy", "/dataset1/item", "POST", true);
    testAuthzRequest("cathy", "/dataset1/item", "DELETE", true);
    testAuthzRequest("cathy", "/dataset2/item", "GET", false);
    testAuthzRequest("cathy", "/dataset2/item", "POST", false);
    testAuthzRequest("cathy", "/dataset2/item", "DELETE", false);

    // delete all roles on user cathy, so cathy cannot access any resources now.
    JCasbinUser.enforcer.deleteRolesForUser("cathy");

    testAuthzRequest("cathy", "/dataset1/item", "GET", false);
    testAuthzRequest("cathy", "/dataset1/item", "POST", false);
    testAuthzRequest("cathy", "/dataset1/item", "DELETE", false);
    testAuthzRequest("cathy", "/dataset2/item", "GET", false);
    testAuthzRequest("cathy", "/dataset2/item", "POST", false);
    testAuthzRequest("cathy", "/dataset2/item", "DELETE", false);
  }
}
