package com.example.demo.infra;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // Indica uma configuração no Spring
@EnableWebSecurity // Ativa a configuração personalizada de segurança
@EnableMethodSecurity // Ativa os métodos de segurança
public class SecurityConfig {

    @Bean // configuração dos filtros de segurança do Spring
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable) // desabilita o cors, não é necessário para backend puro
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("/cadastro/**").permitAll() // endpoint liberado para acesso
                                .requestMatchers("/login/**").permitAll()
                                .requestMatchers("/test/**").permitAll()
                                // Qualquer outra requisição é restrita
                                .anyRequest().authenticated()
                )

                // Sessão Stateless, ou seja, não há memória sobre o ultimo usário que acessou
                // Pede crendeciais para todas as requisições restritas
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                //Controle de excessoes
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint()) // Excessão de Token no Ponto de Entrada -> endpoint
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler())); // Excessão de Token Negado

        return http.build(); // build do HttpSecurity


    }

}
