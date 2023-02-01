package dev.sabri.securityjwt.controller.dto;

public record RegisterRequest(String firstname, String lastname, String email, String password) {
}
