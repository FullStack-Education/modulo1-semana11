package com.example.demo.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/hello")
public class HelloWorld {

    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    @GetMapping
    public String hello(Authentication authentication){

        if(authentication.getAuthorities().contains("app"))
            System.out.println("Autenticacao APP");

        return "Hello";
    }
}
