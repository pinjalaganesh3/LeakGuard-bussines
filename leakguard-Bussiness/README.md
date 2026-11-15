# LeakGuard Business – Security Monitoring & Incident Management

**BTech Second-Year Academic Project Prototype**

Cloud-ready version with **Supabase (PostgreSQL)** database and **Vercel** deployment support.

> **Honest project positioning:** This is an early-stage academic prototype demonstrating event collection, rule-based detection, incident generation, and dashboard management using simulated data. It is **not** an enterprise-grade security solution.

---

## Architecture

| Layer | Technology |
|-------|------------|
| Frontend | HTML5, CSS3, JavaScript (vanilla), Chart.js |
| Backend | Python Flask |
| Database | Supabase (PostgreSQL) — or SQLite for local fallback |
| Deployment | Vercel (serverless) or local localhost |
| Auth | Environment-variable based (no real auth in prototype) |

---

## Quick Start — Local Development (Recommended for Faculty Demo)

### 1. Clone / Copy the Project
Copy this folder to your Windows 11 laptop.

### 2. Create Virtual Environment
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Configure Environment
```powershell
copy .env.example .env
```
Edit `.env` and add your Supabase credentials (or leave blank to use local SQLite fallback).

### 5. Initialize Database
```powershell
python app.py
```
The app auto-creates tables on first run.

### 6. Open Browser
Visit: **http://127.0.0.1:5000**

---

## Demo Scenario (Faculty Review)

1. Open `http://127.0.0.1:5000` — dashboard shows zero active incidents.
2. Go to **Event Simulator** tab.
3. Username: `demo_user`, Result: **Failed Login**.
4. Click **Simulate Login Attempt** 5 times rapidly.
5. Detection engine auto-creates a **High severity** incident.
6. Open incident → review evidence → set status to **Investigating** → **Closed**.
7. Click **Reset Demo** to repeat.

---

## Deploy to Vercel

### 1. Create GitHub Repository
```powershell
git init
git add .
git commit -m "Initial LeakGuard Business prototype"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/leakguard-Bussiness.git
git push -u origin main
```

### 2. Create Supabase Project
- Go to [supabase.com](https://supabase.com) and create a free project
- Copy **Project URL**, **service_role key**, and **Database connection string**

### 3. Import to Vercel
- Go to [vercel.com](https://vercel.com)
- Click **Add New Project** → Import your GitHub repo
- Add environment variables in Vercel dashboard:
  - `SUPABASE_URL`
  - `SUPABASE_KEY`
  - `SUPABASE_DB_URL`
  - `SECRET_KEY`
- Deploy

---

## Database Schema (Supabase PostgreSQL)

```sql
CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR UNIQUE, role VARCHAR, created_at TIMESTAMP);
CREATE TABLE security_events (id SERIAL PRIMARY KEY, username VARCHAR, event_type VARCHAR, timestamp TIMESTAMP, source_ip VARCHAR, details TEXT);
CREATE TABLE incidents (id SERIAL PRIMARY KEY, incident_id VARCHAR UNIQUE, title VARCHAR, username VARCHAR, severity VARCHAR, status VARCHAR, detection_timestamp TIMESTAMP, evidence TEXT, event_count INTEGER, created_at TIMESTAMP, updated_at TIMESTAMP);
CREATE TABLE incident_status_history (id SERIAL PRIMARY KEY, incident_id VARCHAR, old_status VARCHAR, new_status VARCHAR, changed_at TIMESTAMP, changed_by VARCHAR);
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `psycopg2` install fails on Windows | Use `pip install psycopg2-binary` |
| Supabase connection refused | Check `SUPABASE_DB_URL` and ensure your IP is allowed in Supabase |
| Vercel build fails | Ensure `api/index.py` imports correctly and `vercel.json` routes match |
| Local app won't start | Run `python app.py` directly; check `.env` has no typos |

---

## License

Academic project — educational purposes only.
