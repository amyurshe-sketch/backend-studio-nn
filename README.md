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

## Environment variables

- `DATABASE_URL` — SQLAlchemy URL for Postgres
- `SECRET_KEY` — JWT secret
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM_NAME`, `SMTP_USE_TLS` — SMTP settings for email verification

## Notes
- Tables auto-create for RSS on startup via `Base.metadata.create_all()`.
- CORS for frontend is configured in `main.py`. For production, set exact origins and HTTPS cookies.

