package edu.seguridad.authlab;


//Clave almacenada hasheada en modo seguro y va en texto plano en modo inseguro
//mismo record para ambos escenarios
public record Usuario(String nombre, String claveAlmacenada, String rol) {
}
