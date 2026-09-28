# Guia rápido da API

## Headers

Para rotas protegidas:

```text
Authorization: Bearer <access_token>
Content-Type: application/json
```

## Fluxo

```text
REGISTER
   |
   v
LOGIN -----> MFA habilitado? ---- não ----> ACCESS + REFRESH
   | yes
   v
MFA PENDING TOKEN
   |
   v
TOTP / Google Authenticator
   |
   v
ACCESS + REFRESH
   |
   v
API PROTEGIDA
   |
   +---- ACCESS expira ---> REFRESH ---> novos tokens
```
