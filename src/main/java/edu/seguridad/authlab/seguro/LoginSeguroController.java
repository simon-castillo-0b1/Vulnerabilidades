package edu.seguridad.authlab.seguro;

import edu.seguridad.authlab.Usuario;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;


@Controller
@RequestMapping("/seguro")
public class LoginSeguroController {

    private static final Logger log = LoggerFactory.getLogger(LoginSeguroController.class);

    private final UsuariosSeguros usuarios;
    private final SesionesSeguras sesiones;

    public LoginSeguroController(UsuariosSeguros usuarios, SesionesSeguras sesiones) {
        this.usuarios = usuarios;
        this.sesiones = sesiones;
    }

    @GetMapping("/login")
    public String pantallaLogin(Model modelo) {
        modelo.addAttribute("modulo", "seguro");
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam(required = false) String nombre,
                        @RequestParam(required = false) String clave,
                        Model modelo,
                        HttpServletResponse respuesta) {
        String cuenta = nombre == null ? "" : nombre;

        // mientras la cuenta esté bloqueada, no se puede saber si existe o no, ni si la contraseña es correcta o no
        if (usuarios.estaBloqueada(cuenta)) {
            log.warn("Login rechazado: cuenta '{}' bloqueada por intentos fallidos", cuenta);
            return credencialesInvalidas(modelo);
        }

        Usuario usuario = usuarios.buscar(cuenta);
        // ahora busca con el hash de la contraseña, no en texto plano. La contraseña se guarda hasheada
        // unico mensaje, no se puede saber si la credencial existe o no, ni si la contraseña es incorrecta, ni si la cuenta está bloqueada
        if (usuario == null || !usuarios.claveCorrecta(usuario, clave)) {
            usuarios.registrarFallo(cuenta);
            log.warn("Intento de login fallido para '{}'", cuenta);
            return credencialesInvalidas(modelo);
        }

        usuarios.reiniciarIntentos(cuenta);
        // sale por httpOnly, no se puede leer con JavaScript, y el path es / para que se envíe a todas las rutas del módulo
        Cookie cookie = new Cookie("SESSION_ID", sesiones.crear(usuario));
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        respuesta.addCookie(cookie);
        return "redirect:/seguro/perfil";
    }

    private String credencialesInvalidas(Model modelo) {
        modelo.addAttribute("error", "credenciales inválidas");
        modelo.addAttribute("modulo", "seguro");
        return "login";
    }
}
