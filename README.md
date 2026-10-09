# LALIGA Fantasy API Explorer

Aplicación web estática desplegada en Vercel con funciones Node.js para consultar datos públicos de LALIGA Fantasy.

## Despliegue

1. Importa este repositorio en Vercel.
2. No hace falta un comando de build.
3. Despliega y abre la URL que proporciona Vercel.

Arquitectura de datos públicos:

`Navegador → /api/laliga → función Vercel → fantasy-api.llt-services.com/api`

La ruta `/api/laliga` mantiene una lista permitida de endpoints públicos de solo lectura. No acepta rutas arbitrarias ni reenvía cabeceras de autenticación a LALIGA.

## Inicio de sesión con Google

El botón usa el flujo de autorización de LALIGA B2C con Authorization Code + PKCE. No se solicita ni se almacena la contraseña de Google o de LALIGA.

Como la URI de retorno registrada por el cliente nativo es `authredirect://com.lfp.laligafantasy`, el navegador puede no poder abrirla como una página web. El flujo implementado resuelve ese caso así:

1. Pulsa **Continuar con Google** y completa el inicio de sesión en la página oficial de LALIGA.
2. En las herramientas del navegador abre **Red/Network → Todas** y localiza la redirección `authredirect://com.lfp.laligafantasy`. Copia la cabecera completa `Location` de esa respuesta. Si no aparece, copia la URL de la solicitud del esquema personalizado.
3. Pega la URL completa en el formulario. Debe incluir `code` y `state`; una URL abreviada o un código ya utilizado no sirve.
4. El servidor comprueba el estado, utiliza el `code_verifier` guardado para ese intento y canjea el código en `login.laliga.es`.
5. Antes de confirmar el login, valida la sesión consultando `GET /v4/user/me` en la API de Fantasy.

Cada intento PKCE caduca a los 15 minutos y el código de autorización es de un solo uso. Si falla o caduca, vuelve a iniciar el proceso desde el principio. Nunca pegues códigos, tokens ni cookies en incidencias, capturas públicas o chats.

### Cookies y sesiones

Los valores temporales PKCE y los tokens se guardan en cookies `Secure`, `HttpOnly` y con `SameSite` restrictivo. La cookie de sesión tiene el ámbito `/api/auth`; el token no se devuelve en JSON, ni se guarda en `localStorage` o `sessionStorage`, ni queda disponible para el JavaScript de la interfaz. Como Vercel ejecuta funciones sin memoria de sesión persistente compartida, esta versión conserva el token en una cookie HttpOnly del navegador, en lugar de prometer una sesión en memoria del servidor. La ruta de estado intenta renovar la sesión con el refresh token cuando es necesario; la renovación debe considerarse provisional hasta probarla con una cuenta real.

## Alcance actual y seguridad

- La autenticación identifica y verifica la cuenta; no implementa todavía un proxy general para los endpoints privados de ligas, mercado o plantilla.
- El explorador público sigue siendo de solo lectura.
- No hay operaciones de compra, puja, venta, cláusula ni alineación habilitadas.
- No habilites endpoints privados ni operaciones de escritura sin validar por separado el flujo y añadir confirmaciones explícitas por acción.

URL de la aplicación: https://fantasy-xi-eight.vercel.app/
