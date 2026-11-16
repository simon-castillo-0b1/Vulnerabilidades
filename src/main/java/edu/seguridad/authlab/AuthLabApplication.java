package edu.seguridad.authlab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Laboratorio educativo de Broken Authentication (OWASP): módulos /vulnerable y /seguro. */
@SpringBootApplication
public class AuthLabApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthLabApplication.class, args);
    }
}
