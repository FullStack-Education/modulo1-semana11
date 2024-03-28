package com.example.demo.infra;


import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;





//Configuração padrão do Spring Security
// Faz uso das configurações padrão do spring Security
// No caso -> Basic Authentication
@Configuration // Indica uma configuração no Spring
// Ou seja, essa classe hospeda beans

@EnableWebSecurity // Ativa a configuração personalizada de segurança, sobreecrevem o Spring Security
@EnableMethodSecurity // Ativa os métodos de segurança
public class SecurityConfig {

    @Value("${jwt.public.key}") // indica que um valor está no application.properties
    RSAPublicKey key; // chave publica cria por RSA

    @Value("${jwt.private.key}")
    RSAPrivateKey priv; // chave privada cria por RSA

    // as chaves são criadas ao mesmo tempo em geral
    // são armazenadas de forma segura do lado do servidor da aplicação

    @Bean // Configuração que sobreecreve os filtros do Sprig Security
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http // recebe os filtros e gera o objeto final
                .authorizeHttpRequests(auth -> auth //indicar qual é o comportamento de cada enpoint HTTP
                        .requestMatchers(HttpMethod.POST,"/login").permitAll() // o "/login" com o método POST não requer token
                        .requestMatchers(HttpMethod.POST,"/cadastro").hasAnyRole("ADMIN")
//                        .requestMatchers(HttpMethod.GET, new String[]{"/cadastro", "/login"}).permitAll() // é possível liberar vários endpoints para um mesmo método HTTP
                        .anyRequest().authenticated() // Qualquer outro endpoint irá requerer o token gerado no /login
                )
//                .csrf(csrf -> csrf.disable())
                .csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(oauth2 ->  oauth2.jwt(Customizer.withDefaults()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    ;

        return http.build();


    }

    @Bean // Le JWT
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(this.key).build(); // decriptador -> Chave Publica
    }

    @Bean // Cria JWT
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(this.key).privateKey(this.priv).build(); // encriptador -> Chave Privada
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean // Encriptação de Senhas
    // Cria uma instancia de BCryptEncoder no Spring Boot
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder(); // codifica, ou criptografar, senhas com o software BCrypt
    }

}
