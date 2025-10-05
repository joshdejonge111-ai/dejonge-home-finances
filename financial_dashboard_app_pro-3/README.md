# FinDash — Multi-user, Auto Ingest, One‑Click Deploy

A premium-looking, password-protected financial dashboard with:
- ✅ Multi-user accounts (Flask‑Login + SQLite)
- ✅ Upload paystubs (CSV/QFX) and auto‑recalculate projections
- ✅ Nightly auto‑apply from per‑user folder (`uploads/<user_id>/auto`) via APScheduler
- ✅ One‑click deploy configs (Render, Heroku/Procfile, Fly.io + Docker)

## Local Setup
1) Create `.env` from `.env.example` and set:
   - `FLASK_SECRET_KEY`: long random string
   - `ADMIN_EMAIL`: your email
   - `ADMIN_PASSWORD_HASH`: generate with:
     ```bash
     python -c "from werkzeug.security import generate_password_hash as g; print(g('YourStrongPassword'))"
     ```
2) Install & run
   ```bash
   pip install -r requirements.txt
   python app_multi.py
   ```
   Visit http://localhost:5000 — sign in with the admin account (first login creates it from env).

## Uploading Paystubs
- CSV headers (case‑insensitive): `date, gross, taxes, deductions, net`
- QFX/OFX supported
- Nightly auto‑apply looks in `uploads/<user_id>/auto` and applies any new files.

## Deploy
### Render
- Use `render.yaml` in a new Render Web Service. Set env vars same as `.env`.
### Heroku
- Push this repo; Heroku detects `Procfile` and starts `gunicorn`.
### Fly.io
- `fly launch` (uses `fly.toml` + `Dockerfile`).

## Optional: IMAP Fetch
For true auto‑fetch, run a small IMAP script on a schedule (GitHub Actions/cron) that saves attachments into `uploads/<user_id>/auto` on the server. (Per‑user credentials recommended.)

---
Built to look clean on macOS (M1). Enjoy!
