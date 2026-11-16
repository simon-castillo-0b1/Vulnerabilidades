

| Módulo | URLs | Estado |
|---|---|---|
| Vulnerable | `/vulnerable/login`, `/vulnerable/perfil`, `/vulnerable/logout` | las tres fallas presentes |
| Corregido | `/seguro/login`, `/seguro/perfil`, `/seguro/logout` | las tres fallas corregidas |

No se usa Spring Security como framework: toda la autenticación y la sesión están escritas a
mano para que se puedan leer. La única dependencia extra es `spring-security-crypto`, apenas
para tener `BCryptPasswordEncoder`.

---

## Requisitos y cómo ejecutar

- Java 17 o superior (probado con OpenJDK 26 y `--release 17`).
- Maven 3.9 (probado con 3.9.16).
- Nada de base de datos: los usuarios viven en un `Map` en memoria.

```bash
cd authlab
mvn spring-boot:run
```

Abrir **http://127.0.0.1:8080/** (la portada enlaza a los dos módulos). 


```text
$ curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/
200
$ curl -s -o /dev/null -w "%{http_code}\n" http://192.168.0.57:8080/     # IP de la máquina en la red
000                                                                        # conexión rechazada
```

### Credenciales de prueba

| Usuario | Rol | Módulo vulnerable | Módulo seguro |
|---|---|---|---|
| `admin` | ADMIN | `admin` | `Laboratorio-Admin-2026` |
| `simon` | USER | `1234` | `Laboratorio-Simon-2026` |

En el módulo vulnerable las claves están **escritas en claro en el código** (esa es la falla 1);
en el seguro cumplen la política de 12 caracteres y no son comunes.

---


## 3. Guion de demo

Preparación: levantar la app, abrir dos ventanas del navegador una al lado de la otra
(http://127.0.0.1:8080/vulnerable/login y .../seguro/login) y tener la consola de DevTools
abierta en la pestaña *Console*. La terminal donde corriste `mvn spring-boot:run` es parte de la
demo: ahí se ven los intentos fallidos del módulo seguro.

### Falla 1 — contraseñas débiles o por defecto

**Módulo vulnerable.**
1. Entrar con `admin` / `admin`. Funciona a la primera: credencial por defecto.
2. Entrar con `simon` / `1234`.
3. Abrir `src/main/java/edu/seguridad/authlab/vulnerable/UsuariosVulnerables.java` y mostrar el
   constructor: la contraseña figura escrita en claro en el fuente
   (`new Usuario("admin", "admin", "ADMIN")`).
   *Qué observar:* cualquiera que lea el código, un volcado de memoria o un backup tiene las
   claves; y el método `claveCorrecta()` las compara con `equals()`, tal como llegaron.

**Módulo corregido.**
1. Intentar `admin` / `admin`: `credenciales inválidas`.
2. Entrar con `admin` / `Laboratorio-Admin-2026`.
3. Mostrar `seguro/UsuariosSeguros.java`: `LONGITUD_MINIMA = 12`, la lista `COMUNES`, y que lo
   único que queda en el `Map` es el hash BCrypt (`encoder.encode(...)`), nunca la en claro.
4. Demo de que la política se cumple de verdad: cambiar la clave sembrada por `"admin"` y
   reiniciar la app. No arranca:

```text
Caused by: java.lang.IllegalStateException: La contraseña de admin no cumple la política
[INFO] BUILD FAILURE
```

   *Qué explicar:* aquí la política se aplica al sembrar los datos porque el laboratorio no
   tiene alta de usuarios ni cambio de clave; en una app real es la misma validación en el
   formulario de registro.

### Falla 2 — fuerza bruta sin límite de intentos

**Módulo vulnerable (solo navegador).**
1. Escribir un usuario que no existe (`zasu`) con cualquier clave → el login devuelve
   **"usuario no existe"**.
2. Escribir `admin` con una clave mala (`9999`) → devuelve **"contraseña incorrecta"**.
3. *Qué observar:* los dos mensajes son distintos. Con esa diferencia se puede enumerar qué
   usuarios existen antes de atacar las contraseñas, y además se pueden probar todas las que se
   quiera: no hay contador, ni bloqueo, ni registro.

**Módulo vulnerable (bucle de curl, 5 contraseñas).**

```bash
for pass in 0000 qwerty password 12345 admin; do
  printf '%-10s -> ' "$pass"
  curl -s -X POST http://127.0.0.1:8080/vulnerable/login \
       --data-urlencode nombre=simon --data-urlencode "clave=$pass" \
    | grep -o 'contraseña incorrecta'
done
```

```text
0000       -> contraseña incorrecta
qwerty     -> contraseña incorrecta
password   -> contraseña incorrecta
12345      -> contraseña incorrecta
admin      -> contraseña incorrecta
```

Y la sexta, que es la buena, entra sin ninguna resistencia (fijarse en el `Set-Cookie`):

```bash
curl -s -i -X POST http://127.0.0.1:8080/vulnerable/login \
     --data-urlencode nombre=simon --data-urlencode clave=1234 | grep -iE '^(location|set-cookie)'
```

```text
Set-Cookie: SESSION_ID=c2ltb24=; Path=/
Location: http://127.0.0.1:8080/vulnerable/perfil
```

**Módulo corregido (el mismo bucle, con el mismo usuario).**

```bash
for pass in 0000 qwerty password 12345 admin; do
  printf '%-10s -> ' "$pass"
  curl -s -X POST http://127.0.0.1:8080/seguro/login \
       --data-urlencode nombre=simon --data-urlencode "clave=$pass" \
    | grep -o 'credenciales inválidas'
done
```

```text
0000       -> credenciales inválidas
qwerty     -> credenciales inválidas
password   -> credenciales inválidas
12345      -> credenciales inválidas
admin      -> credenciales inválidas
```

*Qué observar:* mensaje único, sin dar pista de si el usuario existe. Ahora, **con la
contraseña correcta** todavía bloqueada:

```bash
curl -s -X POST http://127.0.0.1:8080/seguro/login \
     --data-urlencode nombre=simon --data-urlencode clave=Laboratorio-Simon-2026 \
  | grep -o 'credenciales inválidas'
```

```text
credenciales inválidas
```

Y en la consola del servidor, que es la prueba de que el ataque dejó de ser invisible:

```text
WARN e.s.a.seguro.LoginSeguroController : Intento de login fallido para 'simon'
WARN e.s.a.seguro.LoginSeguroController : Intento de login fallido para 'simon'
WARN e.s.a.seguro.LoginSeguroController : Intento de login fallido para 'simon'
WARN e.s.a.seguro.LoginSeguroController : Intento de login fallido para 'simon'
WARN e.s.a.seguro.LoginSeguroController : Intento de login fallido para 'simon'
WARN e.s.a.seguro.LoginSeguroController : Login rechazado: cuenta 'simon' bloqueada por intentos fallidos
```

Esperar 60 segundos y repetir con la contraseña correcta: entra (se ve
`Set-Cookie: SESSION_ID=...; HttpOnly`). El contador y el bloqueo viven en
`seguro/UsuariosSeguros.java` (`INTENTOS_PERMITIDOS`, `BLOQUEO_SEGUNDOS`, `registrarFallo`,
`estaBloqueada`) y `seguro/LoginSeguroController.login()` los consulta antes de probar la clave.

### Falla 3 — secuestro y falsificación de sesión

**Módulo vulnerable: forjar la cookie de `admin` sin loguearse como admin.**
1. Loguearse como `simon` / `1234`. En la consola de DevTools:

```js
document.cookie
// 'SESSION_ID=c2ltb24='
```

   *Qué observar:* el identificador de sesión **es** el nombre de usuario en Base64
   (`c2ltb24=` → `simon`) y el navegador lo deja leer y escribir porque la cookie salió **sin
   `HttpOnly`**. Se puede comprobar con:

```bash
printf 'simon' | base64   # c2ltb24=
printf 'admin'  | base64  # YWRtaW4=
```

2. Ahora, en la misma consola, sin haber entrado jamás con `admin`:

```js
document.cookie = 'SESSION_ID=YWRtaW4=; path=/';
```

   y abrir **http://127.0.0.1:8080/vulnerable/perfil**. La página muestra
   `Usuario: admin` / `Rol: ADMIN`. Código responsable: `vulnerable/LoginVulnerableController.login()`
   arma el `SESSION_ID` con `Base64.getEncoder()`, y `vulnerable/PerfilVulnerableController.perfil()`
   lo decodifica y confía sin verificar nada más.
3. Equivalente por línea de órdenes, sin cookies guardadas ni login previo:

```bash
curl -s -H 'Cookie: SESSION_ID=YWRtaW4=' http://127.0.0.1:8080/vulnerable/perfil | grep -o '<b>[^<]*'
```

```text
<b>admin
<b>ADMIN
<b>vulnerable
```

4. Cerrar sesión en el módulo vulnerable y recargar con la cookie forjada otra vez: sigue
   adentro, porque `vulnerable/PerfilVulnerableController.logout()` solo borra la cookie del
   navegador y del lado del servidor no había nada que invalidar.

**Módulo corregido: la misma técnica ya no sirve.**
1. Loguearse como `admin` / `Laboratorio-Admin-2026`. En la consola de DevTools:

```js
document.cookie
// ''
```

   *Qué observar:* la cookie **sí** existe (el perfil se ve) pero `document.cookie` no la expone:
   salió con `HttpOnly`. Y el valor es aleatorio: dos logins consecutivos del módulo seguro
   devolvieron `l7t35hPEq47Z447yh4rk1w` y `iYwUE4P6F-qJ_mnSLDpkYA` — 16 bytes de `SecureRandom`
   codificados en Base64.

```bash
curl -s -i -X POST http://127.0.0.1:8080/seguro/login \
     --data-urlencode nombre=admin --data-urlencode clave=Laboratorio-Admin-2026 \
  | grep -i '^set-cookie'
# Set-Cookie: SESSION_ID=iYwUE4P6F-qJ_mnSLDpkYA; Path=/; HttpOnly
```

2. Forjar la cookie con el truco del módulo vulnerable:

```js
document.cookie = 'SESSION_ID=YWRtaW4=; path=/';
```

   y abrir **http://127.0.0.1:8080/seguro/perfil** → devuelve el login (`302 → /seguro/login`).
   Una cookie inventada tampoco funciona:

```bash
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
     -H 'Cookie: SESSION_ID=no-existe-nada' http://127.0.0.1:8080/seguro/perfil
# 302 http://127.0.0.1:8080/seguro/login
```

   *Qué explicar:* el servidor compara contra su propio `Map` (`seguro/SesionesSeguras.java`);
   como ese mapa solo tiene tokens que él generó, no hay nada que adivinar ni que fabricar.
3. Cerrar sesión y reutilizar el token que se tuvo antes del logout (en esta máquina fue
   `t4ILNrfKdtO6V1tgto0clw`; reemplazar por el propio):

```bash
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
     -H 'Cookie: SESSION_ID=t4ILNrfKdtO6V1tgto0clw' http://127.0.0.1:8080/seguro/perfil
# 302 http://127.0.0.1:8080/seguro/login
```

   El logout borró la entrada del mapa (`seguro/PerfilSeguroController.logout()` llama a
   `sesiones.invalidar(token)`), así que el token murió para todos y no solo en ese navegador.

### Cierre sugerido

En el módulo vulnerable las tres fallas se encadenan: la enumeración entrega los usuarios, la
falta de límite entrega la clave (`1234`), y la cookie predecible entrega la sesión de `ADMIN`
sin ni siquiera tener que loguearse. Cada corrección es chiquita y local: hasheo + política,
mensaje único + bloqueo + log, token aleatorio + mapa servidor + `HttpOnly`.

---

## 4. Tabla comparativa

| | Módulo vulnerable (`/vulnerable`) | Módulo corregido (`/seguro`) |
|---|---|---|
| Almacenamiento de la clave | texto plano en el `Map` | hash BCrypt con salt automático |
| Credenciales por defecto | `admin/admin`, `simon/1234` | ninguna: 12+ caracteres, no comunes |
| Política de contraseña | no existe | `LONGITUD_MINIMA=12` + lista de comunes; la app no arranca si se viola |
| Comparación | `equals()` sobre la en claro | `encoder.matches(clave, hash)` |
| Intentos fallidos | ilimitados | 5 consecutivos → cuenta bloqueada 60 s |
| Mensaje de error | "usuario no existe" / "contraseña incorrecta" (permite enumerar) | "credenciales inválidas" (único) |
| Registro del ataque | nada | `WARN` en consola por intento y por bloqueo |
| Identificador de sesión | Base64 del nombre de usuario, predecible | 16 bytes de `SecureRandom` (128 bits), impredecible |
| Estado en el servidor | ninguno: se confía en el contenido de la cookie | `Map token → usuario` en memoria |
| Cookie | sin `HttpOnly` (la lee cualquier script) | con `HttpOnly` |
| Logout | solo borra la cookie del navegador | elimina la entrada del `Map` y borra la cookie |
| Cookie forjada `SESSION_ID=YWRtaW4=` | entra como `admin` (HTTP 200) | rechazada, vuelve al login (HTTP 302) |

---

## 5. Limitaciones conocidas

Es un laboratorio, no una base para producción. Lo que a propósito **no** está:

- **Robo de una cookie válida.** En el módulo corregido, quien consiga una cookie legítima —por
  ejemplo abriendo DevTools ▸ Application ▸ Cookies en la máquina de la víctima, o leyendo el
  tráfico si alguien la expone— **puede reutilizarla** mientras el servidor la tenga en su mapa.
  `HttpOnly` solo cierra la puerta a los scripts (XSS), no a quien puede leer el almacén de
  cookies del navegador. Mitigarlo de verdad pide **regenerar el identificador al autenticarse**,
  **expiración por inactividad y absoluto**, y **HTTPS** (`Secure` + `SameSite`); nada de eso se
  implementó acá para mantener el código legible.
- **Regeneración, expiración, `SameSite`, `Secure`:** afuera por diseño. La sesión del módulo
  corregido vive hasta el logout o el reinicio de la app.
- **Sin HTTPS:** el laboratorio escucha en `http` solo en `127.0.0.1`, así que las contraseñas
  viajan en claro dentro de la máquina. En una red real eso es una cuarta falla (transporte sin
  cifrar).
- **Logout por `GET` sin token CSRF:** cerrar sesión desde un enlace es una vulnerabilidad menor
  y conocida; no se corrigió porque queda fuera de las tres fallas del laboratorio.
- **Todo en memoria:** reiniciar la app borra usuarios, sesiones y contadores. El bloqueo es por
  nombre de cuenta (no por IP ni global) y el mapa de contadores acepta cualquier nombre que se
  pruebe, así que no resuelve un denegación de servicio distribuida.
- **Cifrado y costo:** BCrypt a su costo por defecto está calibrado para un laboratorio con dos
  usuarios; en producción se mide y se ajusta, y la política de contraseñas se complementa con
  verificación de compromiso (`HaveIBeenPwned`) y MFA.
- **Roles:** `/vulnerable/perfil` y `/seguro/perfil` solo muestran el rol; no hay control de
  autorización por página (otro tema distinto: *Broken Access Control*).

---

## 6. Detalle práctico para la presentación

- Dejar la terminal de `mvn spring-boot:run` visible: los `WARN` del módulo seguro son la
  evidencia del ataque.
- Tener a mano `printf 'admin' | base64` para mostrar en 5 segundos de qué se trata la
  predictibilidad.
- Si el público usa Firefox, la cookie se ve en Herramientas para desarrolladores ▸
  Almacenamiento ▸ Cookies; el comando `document.cookie` de la consola funciona igual en ambos.
- El contador de bloqueos del módulo seguro se reinicia con la app: si en la demo anterior ya se
  bloqueó a `simon`, reiniciar o usar `admin`.
