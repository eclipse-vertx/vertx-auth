import io.vertx.ext.auth.hashing.HashingAlgorithm;
import io.vertx.ext.auth.htpasswd.impl.hash.APR1;
import io.vertx.ext.auth.htpasswd.impl.hash.Crypt;
import io.vertx.ext.auth.htpasswd.impl.hash.Plaintext;
import io.vertx.ext.auth.htpasswd.impl.hash.SHA1;

module io.vertx.auth.htpasswd {

  requires transitive io.vertx.auth.common;
  requires org.apache.commons.codec;

  requires static io.vertx.codegen.api;
  requires static io.vertx.codegen.json;
  requires static vertx.docgen;

  exports io.vertx.ext.auth.htpasswd;

  provides HashingAlgorithm with APR1, Crypt, SHA1;

}
