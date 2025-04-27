package com.ijse.bookstore.controller;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.ijse.bookstore.dto.UserRegistrationDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.ijse.bookstore.dto.LoginDTO;
import com.ijse.bookstore.entity.User;
import com.ijse.bookstore.repository.UserRepository;
import com.ijse.bookstore.service.security.jwt.JwtUtils;

@RestController
public class UserAuthController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping("/auth/register")
    public ResponseEntity<?> registierUser(@RequestBody UserRegistrationDto user){
        
        if(userRepository.existsByUsername(user.getUsername())){

            return ResponseEntity.badRequest().body("Username already exists");

        }

        if(userRepository.existsByEmail(user.getEmail())){

            return ResponseEntity.badRequest().body("Email is already being used");

        }

        User newUser = new User();
        newUser.setFullname(user.getFullName());
        newUser.setUsername(user.getUsername());
        newUser.setEmail(user.getEmail());
        newUser.setPassword(passwordEncoder.encode(user.getPassword()));

        
        userRepository.save(newUser);

        return ResponseEntity.ok(Map.of("message", user));

    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody LoginDTO loginDTO){
    /*@PostMapping("/auth/login") → Indica que este metodo responde a requisições HTTP POST na rota /auth/login
    * ResponseEntity<?> → Representa a resposta HTTP que este metodo vai devolver. O <?> significa que pode retornar qualquer tipo de dado (String, JSON, etc.)
    *
    * */

        try {
            Authentication authentication =authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword())
            /*
            O utilizador enviou username e password.
            Criamos um UsernamePasswordAuthenticationToken com essas credenciais.
            Passamos esse token ao authenticationManager, que verifica se as credenciais estão corretas.
            📌 O que acontece nos bastidores?

            O authenticationManager vai procurar o utilizador na base de dados.
            Se o utilizador existir e a password for igual à que está guardada na base de dados, a autenticação é bem-sucedida.
            Se a password estiver errada ou o utilizador não existir, lança um erro BadCredentialsException*/
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String jwt = jwtUtils.generationJwtToken(authentication);

            return ResponseEntity.ok(Map.of("token", jwt));

        } catch (BadCredentialsException ex) {

            return ResponseEntity.status(401).body("Invalid username or password");

        }
    }


    @GetMapping("/user")
    public ResponseEntity<List<User>> getAllUser(){

        List<User> existUser = userRepository.findAll();


        return new ResponseEntity<>(existUser,HttpStatus.OK);
        
    }

    @GetMapping("/username/{username}")
    public ResponseEntity<Optional<User>> getUserIdByUsername(@PathVariable String username) {
        Optional<User> userId = userRepository.findByUsername(username);

        if (userId != null) {
            return ResponseEntity.ok(userId);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/id/{userId}")
    public ResponseEntity<Optional<User>> getUserIdByUsername(@PathVariable long userId) {
        Optional<User> user = userRepository.findById(userId);
        if (user.isPresent()) {
            return ResponseEntity.ok(user);
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}
