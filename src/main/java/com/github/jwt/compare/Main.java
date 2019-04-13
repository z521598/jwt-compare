package com.github.jwt.compare;

import java.security.Key;
import java.security.KeyPair;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class Main {
    private static int FOREACH_TIME = 100000;

    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        //        testAsymmetric(SignatureAlgorithm.RS256);
        //        testAsymmetric(SignatureAlgorithm.RS384);
        //        testAsymmetric(SignatureAlgorithm.RS512);
        //        testAsymmetric(SignatureAlgorithm.ES256);
        //        testAsymmetric(SignatureAlgorithm.ES384);
        testAsymmetric(SignatureAlgorithm.ES512);
        //        testDes(SignatureAlgorithm.HS256);
        //        testDes(SignatureAlgorithm.HS384);
        //        testDes(SignatureAlgorithm.HS512);
        long end = System.currentTimeMillis();
        System.out.print("all time(ms): ");
        System.out.println(end - start);
        System.out.print("each time(ms): ");
        System.out.println((end - start + 0.0D) / FOREACH_TIME);
    }

    private static void testAsymmetric(SignatureAlgorithm signatureAlgorithm) {
        KeyPair keyPair = Keys.keyPairFor(signatureAlgorithm);
        int i = 0;
        while (i < FOREACH_TIME) {
            JwtsUtils.jwsWithRsa(signatureAlgorithm, keyPair);
            i++;
            if (i % 100 == 0) {
                System.out.println(i);
            }
        }
    }

    private static void testDes(SignatureAlgorithm signatureAlgorithm) {
        Key key = Keys.secretKeyFor(signatureAlgorithm);
        int i = 0;
        while (i < FOREACH_TIME) {
            JwtsUtils.jwsWithSha(signatureAlgorithm, key);
            i++;
        }
    }

}
