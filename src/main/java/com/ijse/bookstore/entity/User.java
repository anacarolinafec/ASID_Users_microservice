package com.ijse.bookstore.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class User {

    // to do the user microservice
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "userid")
    private Long id;

    @Column
    private String fullname;

    @Column(unique = true)
    private String username;

    @Column 
    private String password;

    @Column(unique = true)
    private String email;

    private Long cart;


}
