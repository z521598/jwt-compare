package com.github.jwt.compare;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.UUID;

import org.apache.commons.lang3.time.DateUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtsUtils {

    public static void jwsWithRsa(SignatureAlgorithm signatureAlgorithm, KeyPair keyPair) {
        // 私钥签名
        PrivateKey privateKey = keyPair.getPrivate();
        Claims claims = Jwts.claims();
        claims.setSubject("xujinfeng");
        claims.setIssuedAt(new Date());
        claims.setExpiration(DateUtils.addDays(new Date(), 1));
        String jws = Jwts.builder().setClaims(claims).signWith(privateKey, signatureAlgorithm).compact();

        // 公钥验签
        PublicKey publicKey = keyPair.getPublic();
        Jwt jwt = Jwts.parser().setSigningKey(publicKey).parse(jws);

    }

    public static void jwsWithSha(SignatureAlgorithm signatureAlgorithm, Key key) {
        // 签名
        String jwt = Jwts.builder()
                         .setId(UUID.randomUUID().toString()) // 保证每次生成的签名都不一样
                         .setIssuer("irepo")
                         .setSubject("langshiquan")
                         .setIssuedAt(new Date())
                         .setExpiration(DateUtils.addDays(new Date(), 1))
                         .setAudience("agile")
                         .signWith(key, signatureAlgorithm)
                         .compact();

        Jwts.parser().setSigningKey(key).parseClaimsJws(jwt);
    }

}
