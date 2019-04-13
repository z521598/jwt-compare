package com.github.jwt.compare;

import java.security.Key;
import java.security.KeyPair;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class Main {
    public static void main(String[] args) {
        testRS(SignatureAlgorithm.RS256);
        testSHA(SignatureAlgorithm.HS256);
    }

    private static void testRS(SignatureAlgorithm signatureAlgorithm) {
        KeyPair keyPair = Keys.keyPairFor(signatureAlgorithm);
        JwtsUtils.jwsWithRsa(signatureAlgorithm, keyPair);

    }

    private static void testSHA(SignatureAlgorithm signatureAlgorithm) {
        Key key = Keys.secretKeyFor(signatureAlgorithm);
        JwtsUtils.jwsWithSha(signatureAlgorithm, key);
    }

}
