package com.ijse.bookstore.controller;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.ijse.bookstore.dto.UserRegistrationDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.ijse.bookstore.dto.LoginDTO;
import com.ijse.bookstore.entity.User;
import com.ijse.bookstore.repository.UserRepository;
import com.ijse.bookstore.security.JwtUtils;

@RestController
public class UserAuthController {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtUtils jwtUtils;

    private final AuthenticationManager authenticationManager;

    public UserAuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtils jwtUtils, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/auth/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDto user) {

        if (userRepository.existsByUsername(user.getUsername())) {
            return ResponseEntity.badRequest().body("Username already exists");

        }

        if (userRepository.existsByEmail(user.getEmail())) {
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
    public ResponseEntity<?> login(@RequestBody LoginDTO loginDTO) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String jwt = jwtUtils.generationJwtToken(authentication);

            return ResponseEntity.ok(Map.of("token", jwt));

        } catch (BadCredentialsException ex) {

            return ResponseEntity.status(401).body("Invalid username or password");

        }
    }


    @GetMapping("/user")
    public ResponseEntity<List<User>> getAllUsers() {

        List<User> existUser = userRepository.findAll();


        return new ResponseEntity<>(existUser, HttpStatus.OK);

    }

    @GetMapping("/username/{username}")
    public ResponseEntity<Optional<User>> getUserIdByUsername(@PathVariable String username) {
        Optional<User> userId = userRepository.findByUsername(username);

        if (userId.isPresent()) {
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
