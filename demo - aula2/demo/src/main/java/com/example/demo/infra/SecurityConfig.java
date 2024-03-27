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
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


//@EnableWebSecurity // Ativa a configuração personalizada de segurança, sobreecrevem o Spring Security
//@EnableMethodSecurity // Ativa os métodos de segurança


//Configuração padrão do Spring Security
// Faz uso das configurações padrão do spring Security
// No caso -> Basic Authentication
@Configuration // Indica uma configuração no Spring
public class SecurityConfig {

    @Value("${jwt.public.key}") // indica que um valor está no application.properties
    RSAPublicKey key;

    @Value("${jwt.private.key}")
    RSAPrivateKey priv;

    @Bean // configuração dos filtros de segurança do Spring
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> // a ordem dos fatores import
                        auth
                                .requestMatchers("login").permitAll() // não precisa do token JWT, porém ele precisa de uma autenticação por padra

//                                .requestMatchers("cadastro").permitAll() // endpoint liberado para acesso
                                // Qualquer outra requisição é restrita
                                .anyRequest().authenticated()
                )

                .csrf((csrf) -> csrf.ignoringRequestMatchers("/login")) // desabilita o cors, não é necessário para backend puro, porém é necessário em produção
                // ignoringRequestMatchers -> ignora um endpoint e usa o login basico

                // Sessão Stateless, ou seja, não há memória sobre o ultimo usário que acessou
                // Pede crendeciais para todas as requisições restritas
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                //Controle de excessoes
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint()) // Excessão de Token no Ponto de Entrada -> endpoint
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler())) // Excessão de Token Negado

                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .httpBasic(Customizer.withDefaults())

//                .headers(httpSecurityHeadersConfigurer -> {
//                    httpSecurityHeadersConfigurer.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable);
//                })
    ;

        return http.build(); // build do HttpSecurity


    }

    @Bean
    UserDetailsService users() { // Gerencia os usuários do sistema
        return new InMemoryUserDetailsManager( // cria um usuário em memória
                User.withUsername("user")
                        .password("{noop}ppassword")
                        .authorities("app") //perfil de acesso desse usuário
                        .build()
        );
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

}
