package com.github.jwt.compare;

import java.security.Key;
import java.security.KeyPair;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class Main {
    private static int FOREACH_TIME = 10000;

    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        //        testRS(SignatureAlgorithm.RS256);
        //        testRS(SignatureAlgorithm.RS384);
        testRS(SignatureAlgorithm.RS512);
        //        testSHA(SignatureAlgorithm.HS256);
        //        testSHA(SignatureAlgorithm.HS384);
        //        testSHA(SignatureAlgorithm.HS512);
        long end = System.currentTimeMillis();
        System.out.print("all time(ms): ");
        System.out.println(end - start);
        System.out.print("each time(ms): ");
        System.out.println((end - start + 0.0D) / FOREACH_TIME);
    }

    private static void testRS(SignatureAlgorithm signatureAlgorithm) {
        KeyPair keyPair = Keys.keyPairFor(signatureAlgorithm);
        int i = 0;
        while (i < FOREACH_TIME) {
            JwtsUtils.jwsWithRsa(signatureAlgorithm, keyPair);
            i++;
        }
    }

    private static void testSHA(SignatureAlgorithm signatureAlgorithm) {
        Key key = Keys.secretKeyFor(signatureAlgorithm);
        int i = 0;
        while (i < FOREACH_TIME) {
            JwtsUtils.jwsWithSha(signatureAlgorithm, key);
            i++;
        }
    }

}
