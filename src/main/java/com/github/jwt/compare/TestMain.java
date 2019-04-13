package com.github.jwt.compare;

import java.security.KeyPair;

import org.apache.cxf.common.util.Base64UrlUtility;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class TestMain {
    public static void main(String[] args) {
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256);
        System.out.println(Base64UrlUtility.encode(keyPair.getPublic().getEncoded()));
        System.out.println(Base64UrlUtility.encode(keyPair.getPrivate().getEncoded()));
    }
}
