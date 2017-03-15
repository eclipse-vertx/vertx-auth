// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package io.vertx.ext.auth.htpasswd.digest;


import junit.framework.TestCase;

import java.util.HashMap;
import java.util.Map;

/**
 * JUnit unit tests for BCrypt routines
 */
public class BCryptTest extends TestCase {
  String test_vectors[][] = {
    {"", "$2a$06$DCq7YPn5Rq63x1Lad4cll.", "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."},
    {"", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"},
    {"", "$2a$10$k1wbIrmNyFAPwPVPSVa/ze", "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW"},
    {"", "$2a$12$k42ZFHFWqBp3vWli.nIn8u", "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"},
    {"a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"},
    {"a", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V."},
    {"a", "$2a$10$k87L/MF28Q673VKh8/cPi.", "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"},
    {"a", "$2a$12$8NJH3LsPrANStV6XtBakCe", "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS"},
    {"abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"},
    {"abc", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm"},
    {"abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"},
    {"abc", "$2a$12$EXRkfkdmXn2gzds2SSitu.", "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q"},
    {"abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"},
    {"abcdefghijklmnopqrstuvwxyz", "$2a$08$aTsUwsyowQuzRrDqFflhge", "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."},
    {"abcdefghijklmnopqrstuvwxyz", "$2a$10$fVH8e28OQRj9tqiDXs1e1u", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"},
    {"abcdefghijklmnopqrstuvwxyz", "$2a$12$D4G5f18o7aMMfwasBL7Gpu", "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"},
    {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"},
    {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$08$Eq2r4G/76Wv39MzSX262hu", "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"},
    {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"},
    {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO", "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"},
  };


  static final Map<String, String> good$2y$ = new HashMap<String, String>() {{
    // encoded with httpd-tools-2.4.6-45.el7.centos.x86_64 : Tools for use with the Apache HTTP Server
    // htpasswd -nbB myName ''
    put("", "$2y$05$DAJB4D/dKjz2c1nEc4xmEOr3ljZkSHCf26N9z7.OUmt7rW33TWqK2");
    // htpasswd -nbB myName 'a'
    put("a", "$2y$05$7KmTtl6wjds.WIEFyv7T/OVfIpJXWrr3UXVk1zjumQViOKJvYFUw.");
    // htpasswd -nbB myName 'abc'
    put("abc", "$2y$05$KXZdBQ/8ckqQaEUE3vQJmu/yaquEjJjgxxawssqZ8U4kkPw35VbCO");
    // htpasswd -nbB myName 'abcdefghijklmnopqrstuvwxyz'
    put("abcdefghijklmnopqrstuvwxyz", "$2y$05$q.VW8toHCWjklGmNIuQ.X.BRgjhrqZjBsdEaJc.cgECzPJiawAlie");
    // htpasswd -nbB myName '~!@#$%^&*()      ~!@#$%^&*()PNBFRD'
    put("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2y$05$y4v66rxtHfpUUVl.SDkCYOGiOcFIiGfoZjtDUnNUm0s.PBEq9okKa");
    // htpasswd -nbB -C 6 myName '~!@#$%^&*()      ~!@#$%^&*()PNBFRD-06'
    put("~!@#$%^&*()      ~!@#$%^&*()PNBFRD-06", "$2y$06$M8jF1mT7yAPYecjAOY978eNmhNeQXL2YjKJtgii58PunRT8FLDdy.");
    // htpasswd -nbB -C 8 myName '~!@#$%^&*()      ~!@#$%^&*()PNBFRD-08'
    put("~!@#$%^&*()      ~!@#$%^&*()PNBFRD-08", "$2y$08$ZtY1JiYH8jYN0uzK0qhVCOArb1YboWz9J/8r/1rm0JGNEi1fXfBju");
    // htpasswd -nbB -C 10 myName '~!@#$%^&*()      ~!@#$%^&*()PNBFRD-10'
    put("~!@#$%^&*()      ~!@#$%^&*()PNBFRD-10", "$2y$10$i3hBdo/UR///LWZihYKPMuQUJB1enTqgUVKl1qUJyJpqrIVXJjAUm");
    // htpasswd -nbB -C 12 myName '~!@#$%^&*()      ~!@#$%^&*()PNBFRD-12'
    put("~!@#$%^&*()      ~!@#$%^&*()PNBFRD-12", "$2y$12$ilCFyD2Ov.l60m/w1XWpp.LmuYlUg9IYcTuAIuYe6pIuGlYYnEQYi");

    // found on net :)
    put("q", "$2y$10$rzA1p/MV49PSfigoPaRP.OE3TkamFV0v.eV9dH72SP9lN1wksd.WS");
    put("q", "$2y$10$Bnxu9lJ0GMZ5WcrFhE60MuUgMD1l4n27BsPDX2V6o92PkdSRNiLIS");
    put("qqq", "$2y$10$0Ngri58SY3LC18d4sav5LOPzDnTyCGEfdtVFtBhwBP87qmDIz6VSG");
    put("qqq", "$2y$10$FtdRc9b7DqqtVKOSQcRpWeGcFFoSfGOEXeKhxnl3VCBZRt05OL8xm");
    put("rasmuslerdorf", "$2y$10$.vGA1O9wmRjrwAVXD98HNOgsNpDczlqm3Jq7KnEd1rVAGv3Fykk1a");
    put("MyPassword","$2y$07$bmnvU66lzGD9Yu0lDBEXb.FrtLcCkA/YJUXrPLK5iSNCdiyJXt7om");
    put("abc123","$2y$10$aHhnT035EnQGbWAd8PfEROs7PJTHmr6rmzE2SvCQWOygSpGwX2rtW");
    put("ThisIsMyPassword","$2y$10$hZjugx0VE8uZryPWr9mMj.XEyD7qkfS7uxImRRxKERqGkfocg3.SS");
    put("ub3rs3cur3","$2y$10$Ka3/TxAu3UrGX4E8suGkKO4V43dK9CcF.BTT5P8OzOO7/PRjqFn0a");

  }};

  /**
   * Entry point for unit tests
   *
   * @param args unused
   */
  public static void main(String[] args) {
    junit.textui.TestRunner.run(BCryptTest.class);
  }

  /**
   * Test method for 'BCrypt.hashpw(String, String)'
   */
  public void testHashpw() {
    System.out.print("BCrypt.hashpw(): ");
    for (String[] test_vector : test_vectors) {
      String plain = test_vector[0];
      String salt = test_vector[1];
      String expected = test_vector[2];
      String hashed = BCrypt.hashpw(plain, salt);
      assertEquals(hashed, expected);
      System.out.print(".");
    }
    System.out.println("");
  }

  /**
   * Test method for 'BCrypt.gensalt(int)'
   */
  public void testGensaltInt() {
    System.out.print("BCrypt.gensalt(log_rounds):");
    for (int i = 4; i <= 12; i++) {
      System.out.print(" " + Integer.toString(i) + ":");
      for (int j = 0; j < test_vectors.length; j += 4) {
        String plain = test_vectors[j][0];
        String salt = BCrypt.gensalt(i);
        String hashed1 = BCrypt.hashpw(plain, salt);
        String hashed2 = BCrypt.hashpw(plain, hashed1);
        assertEquals(hashed1, hashed2);
        System.out.print(".");
      }
    }
    System.out.println("");
  }

  /**
   * Test method for 'BCrypt.gensalt()'
   */
  public void testGensalt() {
    System.out.print("BCrypt.gensalt(): ");
    for (int i = 0; i < test_vectors.length; i += 4) {
      String plain = test_vectors[i][0];
      String salt = BCrypt.gensalt();
      String hashed1 = BCrypt.hashpw(plain, salt);
      String hashed2 = BCrypt.hashpw(plain, hashed1);
      assertEquals(hashed1, hashed2);
      System.out.print(".");
    }
    System.out.println("");
  }

  /**
   * Test method for 'BCrypt.checkpw(String, String)'
   * expecting success
   */
  public void testCheckpw_success() {
    System.out.print("BCrypt.checkpw w/ good passwords: ");
    for (String[] test_vector : test_vectors) {
      String plain = test_vector[0];
      String expected = test_vector[2];
      assertTrue("plain: " + plain + ", expected: " + expected, BCrypt.checkpw(plain, expected));
      System.out.print(".");
    }
    System.out.println("");
  }

  /**
   * Test method for 'BCrypt.checkpw(String, String)'
   * expecting failure
   */
  public void testCheckpw_failure() {
    System.out.print("BCrypt.checkpw w/ bad passwords: ");
    for (int i = 0; i < test_vectors.length; i++) {
      int broken_index = (i + 4) % test_vectors.length;
      String plain = test_vectors[i][0];
      String expected = test_vectors[broken_index][2];
      assertFalse(BCrypt.checkpw(plain, expected));
      System.out.print(".");
    }
    System.out.println("");
  }

  /**
   * Test for correct hashing of non-US-ASCII passwords
   */
  public void testInternationalChars() {
    System.out.print("BCrypt.hashpw w/ international chars: ");
    String pw1 = "\u2605\u2605\u2605\u2605\u2605\u2605\u2605\u2605";
    String pw2 = "????????";

    String h1 = BCrypt.hashpw(pw1, BCrypt.gensalt());
    assertFalse(BCrypt.checkpw(pw2, h1));
    System.out.print(".");

    String h2 = BCrypt.hashpw(pw2, BCrypt.gensalt());
    assertFalse(BCrypt.checkpw(pw1, h2));
    System.out.print(".");
    System.out.println("");
  }

  /**
   * Test for VERSION_2Y
   */
  public void testGood$2y$() throws Exception {
    System.out.print("BCrypt.checkpw $2y$ good passwords: ");
    good$2y$.forEach((plain, expected) -> {
      assertTrue("plain: " + plain + ", expected: " + expected, BCrypt.checkpw(plain, expected));
      System.out.print(".");
    });
    System.out.println("");
  }
}
