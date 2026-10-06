# LALIGA Fantasy API Explorer

No necesitas un servidor propio.

- GitHub almacena el proyecto.
- Vercel sirve `index.html`.
- Vercel ejecuta `api/laliga/[...path].js` como función serverless.
- La función solo reenvía GET de endpoints públicos permitidos.

## Despliegue

1. Importa este repositorio en Vercel.
2. No hace falta build command.
3. Despliega.
4. Abre la URL de Vercel.

Arquitectura:

Browser -> /api/laliga/... -> Vercel Function -> fantasy-api.llt-services.com

Esto evita que el navegador tenga que resolver el CORS del API de LALIGA Fantasy directamente.

No se aceptan URLs arbitrarias, cookies ni cabeceras Authorization.