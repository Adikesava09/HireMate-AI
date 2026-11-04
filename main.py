import re
import io
import os
import hashlib
import secrets
from pathlib import Path

import requests
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pypdf import PdfReader
from docx import Document

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
MAX_FILE_SIZE = 5 * 1024 * 1024

load_dotenv(BASE_DIR / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")
ADZUNA_APP_ID = os.getenv("ADZUNA_APP_ID")
ADZUNA_APP_KEY = os.getenv("ADZUNA_APP_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing. Add it to your .env file.")

print("Adzuna App ID loaded:", bool(ADZUNA_APP_ID))
print("Adzuna App Key loaded:", bool(ADZUNA_APP_KEY))
print("Database URL loaded:", bool(DATABASE_URL))

app = FastAPI(title="HireMate AI", version="3.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "https://hiremate-ai-frontend-6qdo.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def connect_db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db():
    # Tables were created in Supabase SQL Editor.
    required_tables = {"users", "sessions", "user_resumes"}
    with connect_db() as con:
        rows = con.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name = ANY(%s)
        """, (list(required_tables),)).fetchall()
        found = {row["table_name"] for row in rows}
        missing = required_tables - found
        if missing:
            raise RuntimeError(
                "Missing Supabase tables: " + ", ".join(sorted(missing))
                + ". Run the table-creation SQL in Supabase first."
            )


init_db()


# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200000,
    ).hex()


def get_user_from_token(token):
    if not token:
        return None

    with connect_db() as con:
        row = con.execute("""
            SELECT users.id, users.name, users.email
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = %s
        """, (token,)).fetchone()

    return dict(row) if row else None


@app.get("/")
def home():
    return {"app": "HireMate AI", "status": "running"}


@app.get("/api/health")
def health():
    try:
        with connect_db() as con:
            con.execute("SELECT 1")
        return {"status": "ok", "database": "connected"}
    except Exception:
        raise HTTPException(503, "Database connection failed.")


@app.post("/api/signup")
def signup(data: dict):
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not name or not email or not password:
        raise HTTPException(400, "Please fill in all fields.")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Enter a valid email address.")

    if len(password) < 8:
        raise HTTPException(400, "Password must contain at least 8 characters.")

    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)

    try:
        with connect_db() as con:
            con.execute("""
                INSERT INTO users (name, email, password_hash, salt)
                VALUES (%s, %s, %s, %s)
            """, (name, email, password_hash, salt))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "An account with this email already exists.")

    return {"message": "Account created successfully. Please log in."}


@app.post("/api/login")
def login(data: dict):
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    with connect_db() as con:
        user = con.execute(
            "SELECT * FROM users WHERE email = %s",
            (email,)
        ).fetchone()

    if not user:
        raise HTTPException(401, "Invalid email or password.")

    calculated = hash_password(password, user["salt"])
    if not secrets.compare_digest(calculated, user["password_hash"]):
        raise HTTPException(401, "Invalid email or password.")

    token = secrets.token_urlsafe(32)
    with connect_db() as con:
        con.execute(
            "INSERT INTO sessions (token, user_id) VALUES (%s, %s)",
            (token, user["id"])
        )

    return {
        "message": "Login successful.",
        "token": token,
        "user": {"id": user["id"], "name": user["name"], "email": user["email"]},
    }

def create_login_session(user):
    if user.get("status", "active") != "active":
        raise HTTPException(403, "This account is blocked.")

    token = secrets.token_urlsafe(32)

    with connect_db() as con:
        con.execute(
            "INSERT INTO sessions (token, user_id) VALUES (%s, %s)",
            (token, user["id"])
        )
        con.execute(
            "UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=%s",
            (user["id"],)
        )

    return {
        "message": "Login successful.",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "status": user.get("status", "active")
        }
    }


@app.post("/api/auth/google")
def google_login(data: dict):
    credential = str(data.get("credential", "")).strip()

    if not credential or not GOOGLE_CLIENT_ID:
        raise HTTPException(503, "Google sign-in is not configured.")

    try:
        response = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": credential},
            timeout=10
        )
        claims = response.json()

        if (
            response.status_code != 200
            or claims.get("aud") != GOOGLE_CLIENT_ID
            or claims.get("email_verified") not in (True, "true")
        ):
            raise ValueError("Invalid Google token")

        google_sub = claims["sub"]
        email = claims["email"].strip().lower()
        name = claims.get("name") or email.split("@")[0]

    except Exception:
        raise HTTPException(
            401,
            "Google sign-in verification failed."
        )

    with connect_db() as con:
        linked = con.execute(
            "SELECT user_id FROM google_identities WHERE google_sub=%s",
            (google_sub,)
        ).fetchone()

        if linked:
            user = con.execute(
                "SELECT * FROM users WHERE id=%s",
                (linked["user_id"],)
            ).fetchone()
        else:
            user = con.execute(
                "SELECT * FROM users WHERE LOWER(email)=%s",
                (email,)
            ).fetchone()

            if not user:
                salt = secrets.token_hex(16)
                fake_password = secrets.token_urlsafe(48)

                user_id = con.execute(
                    """INSERT INTO users
                    (name,email,password_hash,salt,role)
                    VALUES(%s,%s,%s,%s,'user')
                    RETURNING id""",
                    (name, email, hash_password(fake_password, salt))
                ).fetchone()["id"]

                user = con.execute(
                    "SELECT * FROM users WHERE id=%s",
                    (user_id,)
                ).fetchone()

            con.execute(
                """INSERT INTO google_identities (google_sub,user_id)
                VALUES(%s,%s)
                ON CONFLICT(google_sub) DO NOTHING""",
                (google_sub, user["id"])
            )

    return create_login_session(user)
@app.get("/api/me")
def me(token: str = ""):
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(401, "Please log in again.")
    return {"user": user}


@app.post("/api/logout")
def logout(data: dict):
    token = str(data.get("token", ""))
    with connect_db() as con:
        con.execute("DELETE FROM sessions WHERE token = %s", (token,))
    return {"message": "Logged out successfully."}


# --------------------------------------------------
# RESUME EXTRACTION AND VALIDATION
# --------------------------------------------------

def extract_resume_text(filename, content):
    suffix = Path(filename).suffix.lower()

    if suffix == ".pdf":
        reader = PdfReader(io.BytesIO(content))
        return "\n".join(page.extract_text() or "" for page in reader.pages)

    if suffix == ".docx":
        doc = Document(io.BytesIO(content))
        parts = [p.text for p in doc.paragraphs]
        for table in doc.tables:
            for row in table.rows:
                parts.extend(cell.text for cell in row.cells)
        return "\n".join(parts)

    raise HTTPException(400, "Only PDF and DOCX files are supported.")


SKILLS = [
    "Python", "SQL", "Excel", "Power BI", "Tableau",
    "Machine Learning", "Data Analysis", "HTML", "CSS",
    "JavaScript", "FastAPI", "Git", "Linux", "Networking",
    "Splunk", "SIEM", "Incident Response", "Threat Analysis",
    "Cybersecurity", "Cloud Computing", "AWS", "Communication",
    "Problem Solving", "Pandas", "NumPy", "Scikit-learn",
    "Active Directory", "Windows", "Linux Administration",
    "TCP/IP", "Firewalls", "SOC", "EDR", "Python Programming",
]


def find_skills(text):
    text = text.lower()
    return [
        skill for skill in SKILLS
        if re.search(
            r"(?<![a-z0-9])" + re.escape(skill.lower()) + r"(?![a-z0-9])",
            text,
        )
    ]


def analyze_text(text, job_title="", job_description=""):
    words = text.split()
    detected = find_skills(text)
    job_text = f"{job_title} {job_description}".strip()
    required = find_skills(job_text) if job_text else detected[:]
    matched = [skill for skill in required if skill in detected]
    missing = [skill for skill in required if skill not in detected]
    keyword_score = round(len(matched) / len(required) * 100) if required else 0
    lower = text.lower()

    section_checks = {
        "Contact details": any(x in lower for x in ["@", "phone", "mobile", "linkedin"]),
        "Education": any(x in lower for x in ["education", "bachelor", "degree", "university", "college"]),
        "Skills": any(x in lower for x in ["skills", "technologies"]),
        "Projects": "project" in lower,
        "Experience": any(x in lower for x in ["experience", "internship", "employment"]),
        "Professional summary": any(x in lower for x in ["professional summary", "career objective", "profile summary", "summary"]),
    }

    present_sections = [name for name, present in section_checks.items() if present]
    missing_sections = [name for name, present in section_checks.items() if not present]
    structure_score = round(len(present_sections) / len(section_checks) * 100)
    word_count = len(words)
    readability_score = 100 if word_count >= 200 else 75 if word_count >= 100 else 50 if word_count >= 50 else 25
    ats_score = round(structure_score * 0.5 + readability_score * 0.2 + keyword_score * 0.3)

    suggestions = [f"Consider adding a {section} section if relevant." for section in missing_sections]
    if missing:
        suggestions.append("Add missing job-related skills only if you genuinely know them.")
    if word_count < 100:
        suggestions.append("Consider adding relevant education, projects, skills and experience.")
    if not suggestions:
        suggestions.append("Review spelling, formatting, dates and job-specific requirements.")

    return {
        "ats_score": ats_score,
        "structure_score": structure_score,
        "keyword_score": keyword_score,
        "score": keyword_score,
        "matched_skills": matched,
        "missing_skills": missing,
        "detected_skills": detected,
        "present_sections": present_sections,
        "missing_sections": missing_sections,
        "suggestions": suggestions,
        "word_count": word_count,
        "note": "Rule-based estimate only. This is not an official ATS score.",
    }


def validate_resume_file(filename, content):
    suffix = Path(filename).suffix.lower()
    if suffix not in {".pdf", ".docx"}:
        raise HTTPException(400, "Upload a PDF or DOCX resume.")
    if not content:
        raise HTTPException(400, "The uploaded file is empty.")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, "File size must be 5 MB or less.")

    try:
        text = extract_resume_text(filename, content)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "Could not read this file. Check that it is a valid PDF or DOCX.")

    if not text.strip():
        raise HTTPException(400, "No readable text found. Scanned PDFs may need OCR first.")
    return text


# --------------------------------------------------
# SAVE AND RETRIEVE USER RESUME
# --------------------------------------------------

@app.post("/api/resume")
async def save_user_resume(token: str = Form(...), file: UploadFile = File(...)):
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(401, "Please log in again.")

    filename = Path(file.filename or "").name
    content = await file.read()
    validate_resume_file(filename, content)

    with connect_db() as con:
        con.execute("""
            INSERT INTO user_resumes (user_id, filename, content)
            VALUES (%s, %s, %s)
            ON CONFLICT(user_id) DO UPDATE SET
                filename = EXCLUDED.filename,
                content = EXCLUDED.content,
                updated_at = CURRENT_TIMESTAMP
        """, (user["id"], filename, content))

    return {"message": "Resume saved successfully.", "filename": filename}


@app.get("/api/resume")
def get_user_resume(token: str = ""):
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(401, "Please log in again.")

    with connect_db() as con:
        row = con.execute("""
            SELECT filename, content, updated_at
            FROM user_resumes WHERE user_id = %s
        """, (user["id"],)).fetchone()

    if not row:
        return {"exists": False, "message": "Upload your resume once."}

    return {"exists": True, "filename": row["filename"], "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None}


# --------------------------------------------------
# ATS RESUME CHECKER
# --------------------------------------------------

@app.post("/api/analyze-resume")
async def analyze_resume(file: UploadFile = File(...), job_title: str = Form(""), job_description: str = Form("")):
    content = await file.read()
    text = validate_resume_file(Path(file.filename or "").name, content)
    return analyze_text(text, job_title, job_description)


# --------------------------------------------------
# JOB DESCRIPTION MATCHER
# --------------------------------------------------

@app.post("/api/job-match")
async def job_match(token: str = Form(...), job_title: str = Form(""), job_description: str = Form(...), file: UploadFile | None = File(None)):
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Please log in again.")

    if file and file.filename:
        filename = Path(file.filename).name
        content = await file.read()
        validate_resume_file(filename, content)
    else:
        with connect_db() as con:
            row = con.execute("""
                SELECT filename, content FROM user_resumes WHERE user_id = %s
            """, (user["id"],)).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="Please upload your resume first.")
        filename, content = row["filename"], row["content"]

    resume_text = extract_resume_text(filename, content)
    return analyze_text(resume_text, job_title, job_description)


# --------------------------------------------------
# ADZUNA REAL JOBS SERVICE
# --------------------------------------------------

def fetch_real_jobs(title="cybersecurity", location="India", page=1):
    if not ADZUNA_APP_ID or not ADZUNA_APP_KEY:
        raise HTTPException(500, "Adzuna API credentials are missing. Check your environment variables.")

    page = max(1, min(page, 10))
    try:
        response = requests.get(
            f"https://api.adzuna.com/v1/api/jobs/in/search/{page}",
            params={
                "app_id": ADZUNA_APP_ID,
                "app_key": ADZUNA_APP_KEY,
                "results_per_page": 20,
                "what": title,
                "where": location,
                "content-type": "application/json",
            },
            timeout=20,
        )
        if response.status_code == 401:
            raise HTTPException(502, "Adzuna rejected the API credentials. Check your APP_ID and APP_KEY.")
        response.raise_for_status()
        data = response.json()
    except HTTPException:
        raise
    except requests.HTTPError as e:
        status = e.response.status_code if e.response is not None else "Unknown"
        details = e.response.text[:500] if e.response is not None else str(e)
        print(f"ADZUNA HTTP ERROR: {status} - {details}")
        raise HTTPException(502, f"Adzuna HTTP Error: {status}. Check server logs for details.")
    except requests.RequestException as e:
        print(f"ADZUNA CONNECTION ERROR: {e}")
        raise HTTPException(502, "Adzuna connection failed. Check server logs.")
    except ValueError as e:
        print(f"ADZUNA JSON ERROR: {e}")
        raise HTTPException(502, "Adzuna returned an invalid response.")

    jobs = []
    for item in data.get("results", []):
        description = item.get("description") or ""
        job_title = item.get("title") or "Job title unavailable"
        jobs.append({
            "role": job_title,
            "company": (item.get("company") or {}).get("display_name") or "Not specified",
            "location": (item.get("location") or {}).get("display_name") or location,
            "description": description,
            "url": item.get("redirect_url", ""),
            "skills": find_skills(job_title + " " + description),
            "source": "Adzuna",
        })

    return {"jobs": jobs, "total": data.get("count", len(jobs)), "page": page, "source": "Adzuna"}


# --------------------------------------------------
# REAL JOBS API
# --------------------------------------------------

@app.get("/api/jobs")
def get_jobs(title: str = "cybersecurity", location: str = "India", page: int = 1):
    return fetch_real_jobs(title, location, page)


# --------------------------------------------------
# AUTOMATIC RESUME MATCH SCORES FOR REAL JOBS
# --------------------------------------------------

@app.post("/api/jobs/match")
async def match_resume_to_jobs(token: str = Form(...), title: str = Form("cybersecurity"), location: str = Form("India"), page: int = Form(1)):
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Please log in again.")

    with connect_db() as con:
        row = con.execute("""
            SELECT filename, content FROM user_resumes WHERE user_id = %s
        """, (user["id"],)).fetchone()

    if not row:
        raise HTTPException(status_code=400, detail="Please upload your resume first.")

    resume_text = extract_resume_text(row["filename"], bytes(row["content"]))
    resume_skills = find_skills(resume_text)
    result = fetch_real_jobs(title=title, location=location, page=page)

    for job in result.get("jobs", []):
        job_skills = find_skills(job.get("role", "") + " " + job.get("description", ""))
        job_skill_set = {item.lower() for item in job_skills}
        resume_skill_set = {item.lower() for item in resume_skills}
        matched = [skill for skill in resume_skills if skill.lower() in job_skill_set]
        missing = [skill for skill in job_skills if skill.lower() not in resume_skill_set]
        score = round(len(matched) / len(job_skills) * 100) if job_skills else 0
        job["match_score"] = score
        job["matched_skills"] = matched
        job["missing_skills"] = missing

    result["jobs"].sort(key=lambda job: job.get("match_score", 0), reverse=True)
    result["resume_filename"] = row["filename"]
    return result
