package edu.seguridad.authlab.seguro;

import edu.seguridad.authlab.Usuario;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/** Página protegida y logout del módulo seguro: la falla 3 corregida. */
@Controller
@RequestMapping("/seguro")
public class PerfilSeguroController {

    private final UsuariosSeguros usuarios;
    private final SesionesSeguras sesiones;

    public PerfilSeguroController(UsuariosSeguros usuarios, SesionesSeguras sesiones) {
        this.usuarios = usuarios;
        this.sesiones = sesiones;
    }

    @GetMapping("/perfil")
    public String perfil(@CookieValue(value = "SESSION_ID", required = false) String token,
                         Model modelo) {
        // solo sirve el token si lo emitio el servidor y sigue en el mapa; si no, no hay usuario y se redirige al login
        String nombre = sesiones.usuarioDe(token);
        Usuario usuario = usuarios.buscar(nombre);
        if (usuario == null) {
            return "redirect:/seguro/login";
        }
        modelo.addAttribute("modulo", "seguro");
        modelo.addAttribute("usuario", usuario);
        return "perfil";
    }

    @GetMapping("/logout")
    public String logout(@CookieValue(value = "SESSION_ID", required = false) String token,
                         HttpServletResponse respuesta) {
        // se borra la entrada del mapa de sesiones, así aunque el navegador conserve la cookie ya no sirve
        sesiones.invalidar(token);
        Cookie borrada = new Cookie("SESSION_ID", "");
        borrada.setMaxAge(0);
        borrada.setPath("/");
        respuesta.addCookie(borrada);
        return "redirect:/seguro/login";
    }
}
