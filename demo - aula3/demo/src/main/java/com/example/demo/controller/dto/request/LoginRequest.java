package com.example.demo.controller.dto.request;

import lombok.Data;

public record LoginRequest (
        String nomeUsuario,
        String senha
){
}
