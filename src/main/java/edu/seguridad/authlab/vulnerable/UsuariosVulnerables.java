package edu.seguridad.authlab.vulnerable;

import edu.seguridad.authlab.Usuario;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class UsuariosVulnerables {


    //usuarios hardcodeados
    //las contraseñas se guardan en texto plano, no se hace hashing
    private final Map<String, Usuario> usuarios = new LinkedHashMap<>();

    public UsuariosVulnerables() {
        usuarios.put("admin", new Usuario("admin", "admin", "ADMIN"));
        usuarios.put("simon", new Usuario("simon", "1234", "USER"));
    }

    public Usuario buscar(String nombre) {
        return nombre == null ? null : usuarios.get(nombre);
    }

   //las contraseñas se comparan en texto plano, no se hace hashing
    public boolean claveCorrecta(Usuario usuario, String clave) {
        return usuario.claveAlmacenada().equals(clave);
    }
}
