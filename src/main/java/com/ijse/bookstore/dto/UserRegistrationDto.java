package com.ijse.bookstore.dto;

import lombok.Data;

@Data
public class UserRegistrationDto {
    private String username;
    private String email;
    private String fullName;
    private String password;
}
