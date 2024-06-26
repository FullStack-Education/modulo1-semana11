package com.example.demo.datasource.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import java.time.Instant;

@Entity
@Table(name = "tarefa")
@Data
public class TarefaEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long id;

    @ManyToOne(cascade = CascadeType.REMOVE, fetch = FetchType.EAGER)
    @JoinColumn(name = "usuario_id")
    private UsuarioEntity usuario;

    private String titulo;
    private String descricao;
    private Boolean finalizada;

    @CreationTimestamp // indica o momento de criação
    private Instant creationTimestamp;
}
