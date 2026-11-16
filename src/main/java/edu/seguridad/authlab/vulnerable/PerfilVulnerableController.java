package edu.seguridad.authlab.vulnerable;

import edu.seguridad.authlab.Usuario;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/** Página protegida y logout del módulo vulnerable: la falla 3 es toda de acá. */
@Controller
@RequestMapping("/vulnerable")
public class PerfilVulnerableController {

    private final UsuariosVulnerables usuarios;

    public PerfilVulnerableController(UsuariosVulnerables usuarios) {
        this.usuarios = usuarios;
    }

    @GetMapping("/perfil")
    public String perfil(@CookieValue(value = "SESSION_ID", required = false) String identificador,
                         Model modelo) {
        // el usuario se identifica por el valor de la cookie, que es el nombre codificado en Base64. Pero
        // el decodificador no está en base64, sino que es un simple reverso de la codificación que hace el login vulnerable.
        // por lo que es trivial de adivinar. Basta con escribir SESSION_ID=YWRtaW4= ("admin" en Base64) para entrar como admin sin conocer ninguna clave.
        String nombre = decodificar(identificador);
        Usuario usuario = usuarios.buscar(nombre);
        if (usuario == null) {
            return "redirect:/vulnerable/login";
        }
        modelo.addAttribute("modulo", "vulnerable");
        modelo.addAttribute("usuario", usuario);
        return "perfil";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse respuesta) {
        //solo borra la cookie del navegador, no hay nada que invalide la sesión en el servidor
        // por lo que basta con volver a poner la cookie para entrar de nuevo
        Cookie borrada = new Cookie("SESSION_ID", "");
        borrada.setMaxAge(0);
        borrada.setPath("/");
        respuesta.addCookie(borrada);
        return "redirect:/vulnerable/login";
    }

    // el decodificador no está en base64, sino que es un simple reverso de la codificación que hace el login vulnerable.
    // Por eso es trivial de adivinar.
    private static String decodificar(String identificador) {
        if (identificador == null || identificador.isEmpty()) {
            return null;
        }
        try {
            return new String(Base64.getDecoder().decode(identificador), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
