package com.example.federated_authorization_server.service;

import com.example.federated_authorization_server.security.SecurityContext;
import org.keycloak.OAuth2Constants;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.representations.IDToken;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.keycloak.crypto.KeyType.RSA;

@Service
public class IdentityService {
    private final SecurityContext securityContext;

    private final KeyPair keyPair;

    public IdentityService(SecurityContext securityContext) {
        this.securityContext = securityContext;
        try {
            keyPair = generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String createJWT() {
        long tokenExpirationTime = 600000;
        IDToken idToken = (IDToken) new IDToken()
                .id(UUID.randomUUID().toString())
                .issuer("http://localhost:9000")
                .issuedAt((int) Instant.now().getEpochSecond())
                .expiration((int) Instant.now().plus(tokenExpirationTime, ChronoUnit.SECONDS).getEpochSecond());
        idToken.setPreferredUsername(securityContext.getUser().getName());
        idToken.setOtherClaims("scope","articles.read");
        return new JWSBuilder()
                .type(OAuth2Constants.JWT)
                .jsonContent(idToken)
                .rsa256(keyPair.getPrivate());
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }


    private KeyPair generateKeyPair() throws Exception {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA);
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("Error while generating KeyPair. No such algorithm: RSA",e);
        }
    }
}
