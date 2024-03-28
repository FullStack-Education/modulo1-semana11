package com.example.demo.datasource.repository;

import com.example.demo.datasource.entity.PerfilEntity;
import com.example.demo.datasource.entity.UsuarioEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PerfilRepository extends JpaRepository<PerfilEntity, Long> {
    Optional<PerfilEntity> findByNome(String nome); //query que busca os usuarios pelo nome de usuario
}
