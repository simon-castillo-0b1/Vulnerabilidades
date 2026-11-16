package edu.seguridad.authlab.seguro;

import edu.seguridad.authlab.Usuario;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/** Usuarios del módulo seguro, en memoria, con su contador de intentos fallidos. */
@Component
public class UsuariosSeguros {

    // politicas de contraseñas
    private static final int LONGITUD_MINIMA = 12;
    private static final Set<String> COMUNES = Set.of(
            "1234", "123456", "password", "admin", "admin123", "qwerty", "contraseña", "letmein");

    private static final int INTENTOS_PERMITIDOS = 5;
    private static final long BLOQUEO_SEGUNDOS = 60;

    private record IntentosFallidos(int cantidad, Instant seDestrabaEn) { }

    private final Map<String, Usuario> usuarios = new LinkedHashMap<>();
    private final Map<String, IntentosFallidos> contadores = new ConcurrentHashMap<>();
    // se guarda la contraseña hasheada
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public UsuariosSeguros() {
        registrar("admin", "Laboratorio-Admin-2026", "ADMIN");
        registrar("simon", "Laboratorio-Simon-2026", "USER");
    }

    private void registrar(String nombre, String clave, String rol) {
        if (!cumplePolitica(clave)) {
            throw new IllegalStateException("La contraseña de " + nombre + " no cumple la política");
        }
        usuarios.put(nombre, new Usuario(nombre, encoder.encode(clave), rol));
    }

    public boolean cumplePolitica(String clave) {
        return clave != null && clave.length() >= LONGITUD_MINIMA && !COMUNES.contains(clave.toLowerCase());
    }

    public Usuario buscar(String nombre) {
        return nombre == null ? null : usuarios.get(nombre);
    }

    // se compara la contraseña hasheada, no en texto plano
    public boolean claveCorrecta(Usuario usuario, String clave) {
        return clave != null && encoder.matches(clave, usuario.claveAlmacenada());
    }

    // se bloquea la cuenta si hay muchos intentos
    public void registrarFallo(String cuenta) {
        contadores.compute(cuenta, (nombre, previos) -> {
            int cantidad = previos == null ? 1 : previos.cantidad() + 1;
            Instant seDestrabaEn = cantidad >= INTENTOS_PERMITIDOS
                    ? Instant.now().plusSeconds(BLOQUEO_SEGUNDOS) : null;
            return new IntentosFallidos(cantidad, seDestrabaEn);
        });
    }

    public void reiniciarIntentos(String cuenta) {
        contadores.remove(cuenta);
    }

    public boolean estaBloqueada(String cuenta) {
        IntentosFallidos previos = contadores.get(cuenta);
        if (previos == null || previos.seDestrabaEn() == null) {
            return false;
        }
        if (Instant.now().isBefore(previos.seDestrabaEn())) {
            return true;
        }
        reiniciarIntentos(cuenta); // vuelve a 0
        return false;
    }
}
