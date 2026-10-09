# LALIGA Fantasy — Explorador público y panel de cuenta

Aplicación estática desplegada en Vercel con funciones Node.js. Los tokens de LALIGA se conservan en cookies `HttpOnly`; no se entregan al JavaScript del navegador.

## Despliegue

1. Importa este repositorio en Vercel.
2. No hace falta comando de build.
3. Despliega y abre la URL que proporciona Vercel.

## Explorador público

El buscador público consulta endpoints permitidos a través de `/api/laliga`:

`Navegador → /api/laliga → fantasy-api.llt-services.com/api`

Esta ruta es de solo lectura y limita los endpoints públicos permitidos.

## Inicio de sesión con Google

El botón usa Authorization Code + PKCE mediante LALIGA B2C. No pide ni guarda la contraseña de Google o de LALIGA.

1. Pulsa **Continuar con Google** y completa el acceso oficial.
2. En la pestaña de autenticación abre **F12 → Red/Network → Todas**. Localiza la redirección `authredirect://com.lfp.laligafantasy`.
3. Copia la cabecera completa `Location` (o la URL completa de la solicitud al esquema personalizado), pégala en el formulario y pulsa **Completar login**.
4. El servidor valida `state`, canjea el código con el `code_verifier` original y comprueba la cuenta con `GET /v4/user/me`.

La URL de redirección contiene un código de un solo uso. No la publiques ni la envíes en chats. Si el código caduca, vuelve a empezar el login.

## Panel privado: Mis Ligas

Una vez iniciada la sesión, la sección **Mis Ligas** permite:

- Consultar las ligas de la cuenta.
- Abrir la clasificación y acceder a la plantilla de cada equipo/manager.
- Ver la alineación disponible del equipo desde la pantalla de plantilla.
- Consultar el mercado de una liga en modo solo lectura.
- Consultar la actividad de liga desde la ruta paginada inicial.

Las rutas privadas se procesan a través de `/api/auth?path=...`, con una lista permitida explícita y peticiones exclusivamente GET. El token no se pasa al navegador ni al endpoint público `/api/laliga`. El servidor intenta renovar tokens cuando se aproximan a su caducidad, pero la renovación requiere pruebas periódicas contra LALIGA.

### Estado de verificación

El documento técnico de referencia reporta como comprobadas con cuenta real las lecturas de usuario, ligas, clasificación y plantilla. Las rutas de mercado, actividad y alineación proceden del código de referencia de la comunidad y pueden variar o no estar disponibles para todas las cuentas. La interfaz muestra errores si LALIGA rechaza alguna de ellas.

No se habilitan pujas, compras, ventas, ofertas, cláusulas, blindajes ni cambios de alineación. Esas operaciones modifican el estado de una liga y deben verificarse por separado y requerir confirmación explícita por acción.

## Seguridad y arquitectura

- Los tokens de sesión y los refresh tokens se guardan en cookies `Secure`, `HttpOnly` y con `SameSite` restrictivo, con ámbito `/api/auth`.
- El proxy privado permite solo rutas de lectura concretas de la competición 1.
- La interfaz no guarda la respuesta privada en `localStorage`; los datos privados se mantienen en memoria y se borran al cerrar sesión o cuando la sesión deja de ser válida.
- Si LALIGA responde 401, vuelve a iniciar sesión. No reutilices códigos o tokens de otra sesión.

Aplicación: https://fantasy-xi-eight.vercel.app/
