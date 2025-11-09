# Studio NN Backend (FastAPI)

## Quick start (local)

1. Create and fill `.env` (use `.env.example` as a template).
2. Create venv and install deps:

```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Run:

```bash
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000/docs

## Deploy notes (Render)

- Ensure the service Root Directory points to `my-fastapi-backend/` (if monorepo).
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Python version is pinned via `runtime.txt` (3.11.9).

### bcrypt / passlib compatibility

Passlib 1.7.x reads `bcrypt.__about__.__version__`. Starting with `bcrypt` 4.1 this attribute was removed,
which causes `AttributeError: module 'bcrypt' has no attribute '__about__'` during import. To avoid this,
`requirements.txt` pins `bcrypt<4.1` alongside `passlib[bcrypt]==1.7.4`.

If your platform installs dependencies from a different location (repo root), make sure it installs the
backend requirements file, or point a root `requirements.txt` to this one:

```
-r my-fastapi-backend/requirements.txt
```

## Environment variables

- `DATABASE_URL` — SQLAlchemy URL for Postgres
- `SECRET_KEY` — JWT secret

## Notes
- Tables auto-create for RSS on startup via `Base.metadata.create_all()`.
- CORS for frontend is configured in `main.py`. For production, set exact origins and HTTPS cookies.
- Email verification flow has been removed; login works via username/password.
