# JWT Auth + Token Refresh Demo — FastAPI

A working implementation of the access/refresh token pattern I wrote about in
[JWT Authentication & Token Refresh in FastAPI: A Practical Guide](https://himanitayal.hashnode.dev/).

## What this demonstrates

- **Access/refresh token separation** — short-lived access tokens (15 min),
  longer-lived refresh tokens (7 days)
- **Refresh token rotation** — every refresh issues a brand-new refresh token
  and invalidates the old one, limiting the damage window of a leaked token
- **Secure cookie storage** — the refresh token is set as an `httpOnly`,
  `secure`, `samesite=strict` cookie, never exposed to JavaScript (avoids the
  common `localStorage` XSS pitfall)
- **Token-type enforcement** — a refresh token can't be used to authenticate
  a regular API request, and vice versa
- **Explicit revocation** — `/logout` invalidates the stored refresh token

## Project structure

```
jwt-fastapi-auth-demo/
├── app/
│   ├── auth.py     # token creation, verification, rotation, revocation
│   └── main.py     # FastAPI routes: /login, /refresh, /logout, /me
├── requirements.txt
└── .env.example
```

## Setup

```bash
git clone https://github.com/aihimanitayal/jwt-fastapi-auth-demo.git
cd jwt-fastapi-auth-demo
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # set a real JWT_SECRET_KEY
```

## Run

```bash
uvicorn app.main:app --reload
```

Visit `http://127.0.0.1:8000/docs` for interactive API docs.

## Try it

```bash
# Log in (demo — no real password check)
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"user_id": "demo-user"}' \
  -c cookies.txt

# Access a protected route
curl http://127.0.0.1:8000/me \
  -H "Authorization: Bearer <access_token_from_login_response>"

# Refresh (uses the httpOnly cookie automatically)
curl -X POST http://127.0.0.1:8000/refresh -b cookies.txt -c cookies.txt
```

## Notes on production use

- The refresh token store here is a plain Python dict — **swap for Redis or a
  database table** before shipping anything real; it needs to survive
  restarts and work across multiple server instances.
- `JWT_SECRET_KEY` must come from a secrets manager or environment variable,
  never hardcoded — the `.env.example` default is for local dev only.
- See the blog post for the token-blacklist pattern for immediate
  access-token revocation on security-sensitive actions.

## License

MIT
