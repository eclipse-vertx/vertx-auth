package io.vertx.ext.auth.htpasswd.digest;

/**
 * @author Neven Radovanović
 */
public class Hex {

  final protected static char[] hexArray = "0123456789abcdef".toCharArray();

  public static String bytesToHex(byte[] bytes) {
    if (bytes == null) return null;
    if (bytes.length == 0)  return "";
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

}
