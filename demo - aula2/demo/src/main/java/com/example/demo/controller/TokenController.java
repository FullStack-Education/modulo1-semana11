package com.example.demo.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class TokenController {

    private final JwtEncoder encoder;

    private final long EXPIRY = 36000L; //contante de tempo de expiração em milisegundos

    @PostMapping("login")
    public String token(Authentication authentication){
        Instant now = Instant.now(); // momento atual

        //escopo do token
        String scope =
                authentication.getAuthorities() //permissões do usuário
                        .stream()
                        .map(GrantedAuthority::getAuthority)// Autoridade/Permissões nativas do usuário
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder() // campos do JWT
                .issuer("self") // criado -> "próprio"
                .issuedAt(now) // criado no momento atual
                .expiresAt(now.plusSeconds(EXPIRY)) // expira em 36000L milisegundos
                .subject(authentication.getName()) //nome do usuário
                .claim("scope", scope) // permissões do usuário
                .build();

        //Cria um JWT em string com os campos definidos anteriormente
        return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
