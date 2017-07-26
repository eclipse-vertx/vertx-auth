package io.vertx.ext.auth.htpasswd.digest;

import org.apache.commons.codec.digest.Crypt;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.Md5Crypt;
import org.mindrot.jbcrypt.BCrypt;

import java.util.Base64;


/**
 * @author Neven Radovanović
 */
public class Digest {

  public static boolean isBcryptHashed(String hashed) {
    return hashed.startsWith("$2y$") || hashed.startsWith("$2a$");
  }

  public static boolean bcryptCheck(String plaintext, String hashed) {
    if (hashed.startsWith("$2a$")) {
      return BCrypt.checkpw(plaintext, hashed);
    }
    throw new IllegalArgumentException("This bcrypt version is currently not supported.");
  }

  public static boolean isMd5Hashed(String hashed) {
    return hashed.startsWith("$apr1$");
  }

  public static boolean md5Check(String plaintext, String hashed) {
    return hashed.equals(Md5Crypt.apr1Crypt(plaintext, hashed));
  }

  public static boolean isShaHashed(String hashed) {
    return hashed.startsWith("{SHA}");
  }

  public static boolean shaCheck(String plaintext, String hashed) {
    String passwd64 = Base64.getEncoder().encodeToString(DigestUtils.sha1(plaintext));
    return hashed.substring("{SHA}".length()).equals(passwd64);
  }

  public static boolean cryptCheck(String plaintext, String hashed) {
    return hashed.equals(Crypt.crypt(plaintext, hashed));
  }

}
