package com.bytmasoft.dss.entities;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "users")
public class User implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(nullable = false)
    private Long schoolId;

    private String firstname;
    private String lastname;



    @Column(unique = true, nullable = false)
    private String username;


    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

@ManyToOne
@JoinColumn(name = "role_id")
private Role role;






}
