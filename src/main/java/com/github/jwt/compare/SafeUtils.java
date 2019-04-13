package com.github.jwt.compare;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.apache.cxf.common.util.Base64UrlUtility;

public class SafeUtils {
    private static String randomSecure() {
        return Base64UrlUtility.encode(UUID.randomUUID().toString().getBytes());
    }

    private static void mac() throws NoSuchAlgorithmException, InvalidKeyException {
        String securityText = "text";
        KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
        SecretKey sk = kg.generateKey();
        Mac mac = Mac.getInstance("hmacsha256");
        mac.init(sk);
        byte[] result = mac.doFinal(securityText.getBytes(Charset.forName("utf-8")));
        System.out.println(Base64UrlUtility.encode(result));
    }

    private static void key() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(Base64UrlUtility.encode(secretKey.getEncoded()));

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("rsa");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey puk = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey pik = (RSAPrivateKey) keyPair.getPrivate();
        System.out.println(Base64UrlUtility.encode(puk.getEncoded()));
        System.out.println(Base64UrlUtility.encode(pik.getEncoded()));
    }

    private static void sign()
            throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        String securityText = "text";
        // rsa key
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("rsa");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey puk = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey pik = (RSAPrivateKey) keyPair.getPrivate();

        // 签名
        Signature signWithRsa = Signature.getInstance("sha256WithRsa");
        signWithRsa.initSign(pik);
        signWithRsa.update(securityText.getBytes(Charset.forName("utf-8")));
        byte[] signBytes = signWithRsa.sign();

        // 验证签名
        signWithRsa.initVerify(puk);
        signWithRsa.update(securityText.getBytes(Charset.forName("utf-8")));
        boolean verified = signWithRsa.verify(signBytes);

    }

    private static void messageDigest() throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update("123".getBytes());
        byte[] digestBytes = sha.digest();
        System.out.println(Base64UrlUtility.encode(digestBytes));

    }
}
