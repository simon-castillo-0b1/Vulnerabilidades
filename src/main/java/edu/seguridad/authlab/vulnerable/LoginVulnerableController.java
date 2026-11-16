package edu.seguridad.authlab.vulnerable;

import edu.seguridad.authlab.Usuario;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/vulnerable")
public class LoginVulnerableController {

    private final UsuariosVulnerables usuarios;

    public LoginVulnerableController(UsuariosVulnerables usuarios) {
        this.usuarios = usuarios;
    }

    @GetMapping("/login")
    public String pantallaLogin(Model modelo) {
        modelo.addAttribute("modulo", "vulnerable");
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam(required = false) String nombre,
                        @RequestParam(required = false) String clave,
                        Model modelo,
                        HttpServletResponse respuesta) {
        Usuario usuario = usuarios.buscar(nombre);

        if (usuario == null) {
            // esto permite enumerar los usuarios existentes
            modelo.addAttribute("error", "usuario no existe");
        } else if (!usuarios.claveCorrecta(usuario, clave)) {
            // no hay validacion por intentos fallidos, ni bloqueo de cuenta, ni hash de contraseñas,
            // por lo que se puede adivinar la contraseña de cualquier usuario con fuerza bruta
            modelo.addAttribute("error", "contraseña incorrecta");
        } else {
            // no utiliza sesiones ni cookies seguras, solo un identificador que el cliente puede modificar
            String identificador = Base64.getEncoder()
                    .encodeToString(usuario.nombre().getBytes(StandardCharsets.UTF_8));
            Cookie cookie = new Cookie("SESSION_ID", identificador);
            // la cookie se puede alterar y el servidor no lo detecta, por lo que basta con cambiar el valor
            // para hacerse pasar por otro usuario
            cookie.setPath("/");
            respuesta.addCookie(cookie);
            return "redirect:/vulnerable/perfil";
        }

        modelo.addAttribute("modulo", "vulnerable");
        return "login";
    }
}
