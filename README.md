# Central de Autenticação Segura com MFA

Projeto acadêmico de uma API de autenticação desenvolvida com Node.js e Express, aplicando práticas modernas de segurança.

## Tecnologias

- Node.js 20+
- Express
- SQLite
- Argon2id para hash de senhas
- JWT para access token
- Refresh token JWT com rotação e revogação
- TOTP para MFA/2FA
- Google Authenticator
- Helmet
- Rate limiting
- AES-256-GCM para proteger o segredo TOTP armazenado no banco

## Arquitetura de segurança

### 1. Senhas

As senhas nunca são armazenadas em texto puro. O projeto usa **Argon2id**, algoritmo recomendado para armazenamento de senhas.

### 2. Access token

Após a autenticação, é emitido um JWT de acesso com validade curta de **15 minutos**.

### 3. Refresh token

O refresh token é um JWT com validade de **7 dias** e possui um `jti` único. Cada refresh é registrado no SQLite, o token anterior é revogado e um novo refresh token é emitido. Isso implementa rotação de refresh tokens.

### 4. MFA / TOTP

O segundo fator utiliza TOTP, compatível com Google Authenticator. Durante o setup, a API gera uma URI `otpauth://` e um QR Code. O segredo TOTP é armazenado no banco criptografado com AES-256-GCM.

### 5. Proteções adicionais

- Helmet para headers HTTP de segurança.
- Rate limit nas rotas sensíveis.
- Validação básica de e-mail e senha.
- Segredos e chaves ficam no `.env`.
- Banco SQLite e `.env` estão no `.gitignore`.
- Tokens possuem tipos (`access`, `refresh`, `mfa_pending`) para evitar uso indevido.

## Como executar

### 1. Pré-requisitos

Instale Node.js 20 ou superior.

### 2. Instalar dependências

```bash
npm install
```

### 3. Criar variáveis de ambiente

Copie `.env.example` para `.env`.

No Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Gere três valores seguros. Para gerar a chave hexadecimal do AES:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Para as chaves JWT, também é possível usar:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Coloque os valores no `.env`.

### 4. Iniciar

```bash
npm start
```

A API ficará disponível em:

`http://localhost:3000`

## Testando com navegador

Abra:

`http://localhost:3000/health`

O navegador deverá retornar:

```json
{
  "status": "ok",
  "service": "central-auth-mfa"
}
```

Para testar POST, use Postman, Insomnia ou Thunder Client.

## Fluxo de teste completo

### 1. Criar usuário

POST `/auth/register`

```json
{
  "email": "aluno@exemplo.com",
  "password": "SenhaForte123!"
}
```

### 2. Login inicial

POST `/auth/login`

```json
{
  "email": "aluno@exemplo.com",
  "password": "SenhaForte123!"
}
```

Sem MFA habilitado, a resposta possui `accessToken` e `refreshToken`.

### 3. Configurar MFA

Use o `accessToken` como:

`Authorization: Bearer SEU_ACCESS_TOKEN`

POST `/auth/mfa/setup`

A resposta possui `qrCode` em Data URL e `manualSecret`.

Escaneie o QR Code com Google Authenticator.

### 4. Confirmar MFA

POST `/auth/mfa/enable`

```json
{
  "code": "123456"
}
```

Substitua pelo código atual do aplicativo autenticador.

### 5. Testar login com MFA

POST `/auth/login`

```json
{
  "email": "aluno@exemplo.com",
  "password": "SenhaForte123!"
}
```

Agora a API deverá responder com:

```json
{
  "mfaRequired": true,
  "mfaToken": "..."
}
```

Depois:

POST `/auth/mfa/verify`

```json
{
  "mfaToken": "TOKEN_RECEBIDO_NO_LOGIN",
  "code": "123456"
}
```

A resposta final terá o access token e o refresh token.

### 6. Acessar rota protegida

GET `/me`

Header:

`Authorization: Bearer SEU_ACCESS_TOKEN`

### 7. Renovar sessão

POST `/auth/refresh`

```json
{
  "refreshToken": "SEU_REFRESH_TOKEN"
}
```

O refresh antigo será revogado e um novo será emitido.

### 8. Logout

POST `/auth/logout`

Header:

`Authorization: Bearer SEU_ACCESS_TOKEN`

## Endpoints

| Método | Rota | Proteção | Função |
|---|---|---|---|
| GET | `/health` | Pública | Verificar API |
| POST | `/auth/register` | Pública | Cadastro |
| POST | `/auth/login` | Pública | Login |
| POST | `/auth/mfa/setup` | Access JWT | Gerar TOTP/QR |
| POST | `/auth/mfa/enable` | Access JWT | Habilitar MFA |
| POST | `/auth/mfa/verify` | MFA Token | Validar segundo fator |
| POST | `/auth/refresh` | Refresh JWT | Renovar sessão |
| POST | `/auth/logout` | Access JWT | Revogar refresh tokens |
| GET | `/me` | Access JWT | Dados do usuário |

## Estrutura

```text
central-auth-mfa/
├── src/
│   ├── db.js
│   ├── mfa.js
│   ├── middleware.js
│   ├── security.js
│   └── server.js
├── .env.example
├── .gitignore
├── package.json
└── README.md
```

## Observação acadêmica

Este projeto demonstra os principais mecanismos solicitados no trabalho: hash seguro de senha com Argon2id, JWT de curta duração, refresh token com rotação, MFA baseado em TOTP e integração compatível com Google Authenticator.

Para produção, recomenda-se complementar a solução com HTTPS obrigatório, armazenamento de secrets em um Secret Manager, cookies `HttpOnly`/`Secure` quando apropriado, logs e monitoramento de segurança, política de recuperação de conta e testes automatizados.
