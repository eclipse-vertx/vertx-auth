package io.vertx.ext.auth.htpasswd.digest;

import org.junit.Test;

import static io.vertx.ext.auth.htpasswd.digest.Digest.*;
import static org.junit.Assert.*;

/**
 * Created by nevenr on 17/03/2017.
 */
public class DigestTest {

  @Test
  public void testIsBcryptHashed() {
    assertTrue(isBcryptHashed("$2y$05$QwbS8vp1A/yQ1AlQ8ySDOuzONdR3U6A.xATjBHno/.nvp8O55eVaG"));
    assertFalse(isBcryptHashed("something"));
  }

  @Test
  public void testBcryptCheck() {
    assertTrue(bcryptCheck("myPassword", "$2y$05$QwbS8vp1A/yQ1AlQ8ySDOuzONdR3U6A.xATjBHno/.nvp8O55eVaG"));
    assertFalse(bcryptCheck("myPassword", "$2y$10$rzA1p/MV49PSfigoPaRP.OE3TkamFV0v.eV9dH72SP9lN1wksd.WS"));
  }

  @Test
  public void testIsMd5Hashed() {
    assertTrue(isMd5Hashed("$apr1$V45rK4cb$O6ozhQ3JtwlH94GhuUKRD1"));
    assertFalse(isMd5Hashed("something"));
  }

  @Test
  public void testMd5Check() {
    assertTrue(md5Check("myPassword", "$apr1$V45rK4cb$O6ozhQ3JtwlH94GhuUKRD1"));
    assertFalse(md5Check("myPassword", "$apr1$2wtO/ZUU$LCxwRUmdEdiYq.qNY2zq21"));
  }

  @Test
  public void testIsShaHashed() {
    assertTrue(isShaHashed("{SHA}VBPuJHI7uixaa6LQGWx4s+5GKNE="));
    assertFalse(isShaHashed("something"));
  }

  @Test
  public void testShaCheck() {
    assertTrue(shaCheck("myPassword", "{SHA}VBPuJHI7uixaa6LQGWx4s+5GKNE="));
    assertFalse(shaCheck("myPassword", "{SHA}GvF+c3IdvgxAARuC7Uuxp9vjzik="));
  }

  @Test
  public void testCryptCheck() {
    assertTrue(cryptCheck("myPassword", "0MJgtfTc6oYDE"));
    assertFalse(cryptCheck("myPassword", "YbfDVFLu8hSxw"));
  }

}
