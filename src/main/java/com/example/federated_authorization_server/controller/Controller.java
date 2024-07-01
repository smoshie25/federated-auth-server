package com.example.federated_authorization_server.controller;

import com.example.federated_authorization_server.pojo.JWT;
import com.example.federated_authorization_server.service.IdentityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController()
public class Controller {

    @Autowired
    IdentityService identityService;

    @GetMapping("/oauth2/authorize")
    public JWT getTToken(){
        JWT token = new JWT();
        token.setAccessToken(identityService.createJWT());
        return token;
    }


    @GetMapping(value = "/oidc/jwk", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getPublicKey() {
        RSAPublicKey publicKey = (RSAPublicKey) identityService.getPublicKey();
        Map<String, String> jwk = new HashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("alg", "RS256");
        jwk.put("use", "sig");
        jwk.put("n", Base64.getUrlEncoder().encodeToString(publicKey.getModulus().toByteArray()));
        jwk.put("e", Base64.getUrlEncoder().encodeToString(publicKey.getPublicExponent().toByteArray()));

        Map<String, Object> jwks = new HashMap<>();
        jwks.put("keys", Collections.singletonList(jwk));
        return jwks;
    }

}
