package edu.seguridad.authlab.seguro;

import edu.seguridad.authlab.Usuario;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class SesionesSeguras {

    // el token es aleatorio e impredecible
    private static final int TOKEN_BYTES = 16;

    private final SecureRandom aleatorio = new SecureRandom();

    // el servidor se acuerda que token emitio y a qué usuario corresponde; si el token no está en este mapa, no sirve
    private final Map<String, String> sesiones = new ConcurrentHashMap<>();

    public String crear(Usuario usuario) {
        byte[] bytes = new byte[TOKEN_BYTES];
        aleatorio.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        sesiones.put(token, usuario.nombre());
        return token;
    }

    public String usuarioDe(String token) {
        return token == null ? null : sesiones.get(token);
    }

    public void invalidar(String token) {
        if (token != null) {
            sesiones.remove(token);
        }
    }
}
