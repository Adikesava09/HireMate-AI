import re
import io
import os
import hashlib
import secrets
import time
from pathlib import Path

import requests
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pypdf import PdfReader
from docx import Document

# ==================================================
# CONFIG
# ==================================================

BASE_DIR = Path(__file__).resolve().parent
MAX_FILE_SIZE = 5 * 1024 * 1024

load_dotenv(BASE_DIR / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
ADZUNA_APP_ID = os.getenv("ADZUNA_APP_ID")
ADZUNA_APP_KEY = os.getenv("ADZUNA_APP_KEY")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "hirematee.ai@gmail.com").strip().lower()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing.")

app = FastAPI(title="HireMate AI", version="4.0.0")

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


# ==================================================
# DATABASE
# ==================================================

def connect_db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db():
    required = {
        "users", "sessions", "user_resumes",
        "ats_history", "google_identities",
        "password_reset_otps", "saved_jobs",
        "application_tracker", "job_listings",
        "activity_logs"
    }

    with connect_db() as con:
        rows = con.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema='public'
        """).fetchall()

        found = {r["table_name"] for r in rows}
        missing = required - found

        if missing:
            raise RuntimeError(
                "Missing tables: " + ", ".join(sorted(missing))
            )


init_db()


# ==================================================
# SECURITY / AUTH
# ==================================================

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        200000
    ).hex()


def get_user_from_token(token):
    if not token:
        return None

    with connect_db() as con:
        user = con.execute("""
            SELECT u.id, u.name, u.email, u.role, u.status
            FROM sessions s
            JOIN users u ON u.id=s.user_id
            WHERE s.token=%s
        """, (token,)).fetchone()

    if not user:
        return None

    if user.get("status") != "active":
        return None

    return dict(user)


def require_user(token):
    user = get_user_from_token(token)

    if not user:
        raise HTTPException(401, "Please log in again.")

    return user


def require_admin(token):
    user = require_user(token)

    # Server-side email allowlist. Client cannot grant itself admin.
    if user["email"].lower() != ADMIN_EMAIL:
        raise HTTPException(403, "Admin access denied.")

    return user


def log_activity(user_id, event_type, details=None):
    try:
        with connect_db() as con:
            con.execute("""
                INSERT INTO activity_logs(user_id,event_type,details)
                VALUES(%s,%s,%s)
            """, (
                user_id,
                event_type,
                psycopg.types.json.Jsonb(details or {})
            ))
    except Exception as exc:
        print("ACTIVITY LOG ERROR:", str(exc))


def create_login_session(user):
    if user.get("status", "active") != "active":
        raise HTTPException(403, "This account is blocked.")

    token = secrets.token_urlsafe(32)

    with connect_db() as con:
        con.execute(
            "INSERT INTO sessions(token,user_id) VALUES(%s,%s)",
            (token, user["id"])
        )

        con.execute("""
            UPDATE users
            SET last_login_at=CURRENT_TIMESTAMP
            WHERE id=%s
        """, (user["id"],))

    log_activity(user["id"], "login")

    return {
        "message": "Login successful.",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": (
                "admin" if user["email"].lower() == ADMIN_EMAIL
                else "user"
            ),
            "status": user.get("status", "active")
        }
    }


# ==================================================
# BASIC ROUTES
# ==================================================

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


# ==================================================
# SIGNUP / LOGIN
# ==================================================

@app.post("/api/signup")
def signup(data: dict):
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not name or not email or not password:
        raise HTTPException(400, "Fill all fields.")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Invalid email.")

    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")

    salt = secrets.token_hex(16)

    try:
        with connect_db() as con:
            con.execute("""
                INSERT INTO users(name,email,password_hash,salt,role,status)
                VALUES(%s,%s,%s,%s,'user','active')
            """, (
                name, email, hash_password(password, salt), salt
            ))
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "Email already registered.")

    return {"message": "Account created successfully."}


@app.post("/api/login")
def login(data: dict):
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    with connect_db() as con:
        user = con.execute(
            "SELECT * FROM users WHERE LOWER(email)=%s",
            (email,)
        ).fetchone()

    if not user:
        raise HTTPException(401, "Invalid email or password.")

    calculated = hash_password(password, user["salt"])

    if not secrets.compare_digest(calculated, user["password_hash"]):
        raise HTTPException(401, "Invalid email or password.")

    return create_login_session(user)


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
        raise HTTPException(401, "Google verification failed.")

    with connect_db() as con:
        linked = con.execute("""
            SELECT user_id FROM google_identities
            WHERE google_sub=%s
        """, (google_sub,)).fetchone()

        if linked:
            user = con.execute(
                "SELECT * FROM users WHERE id=%s",
                (linked["user_id"],)
            ).fetchone()
        else:
            user = con.execute("""
                SELECT * FROM users WHERE LOWER(email)=%s
            """, (email,)).fetchone()

            if not user:
                salt = secrets.token_hex(16)
                fake_password = secrets.token_urlsafe(48)

                user_id = con.execute("""
                    INSERT INTO users
                    (name,email,password_hash,salt,role,status)
                    VALUES(%s,%s,%s,%s,'user','active')
                    RETURNING id
                """, (
                    name, email,
                    hash_password(fake_password, salt), salt
                )).fetchone()["id"]

                user = con.execute(
                    "SELECT * FROM users WHERE id=%s",
                    (user_id,)
                ).fetchone()

            con.execute("""
                INSERT INTO google_identities(google_sub,user_id)
                VALUES(%s,%s)
                ON CONFLICT(google_sub) DO NOTHING
            """, (google_sub, user["id"]))

    return create_login_session(user)


@app.get("/api/me")
def me(token: str = ""):
    user = require_user(token)

    return {
        "user": {
            **user,
            "role": (
                "admin" if user["email"].lower() == ADMIN_EMAIL
                else "user"
            )
        }
    }


@app.post("/api/logout")
def logout(data: dict):
    token = str(data.get("token", ""))

    with connect_db() as con:
        con.execute(
            "DELETE FROM sessions WHERE token=%s",
            (token,)
        )

    return {"message": "Logged out."}


# ==================================================
# BREVO FORGOT PASSWORD OTP
# ==================================================

def send_reset_otp(email, otp):
    api_key = os.getenv("BREVO_API_KEY", "").strip()

    if not api_key:
        raise HTTPException(503, "Brevo API key is missing.")

    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": api_key,
                "Content-Type": "application/json"
            },
            json={
                "sender": {
                    "name": "HireMate AI",
                    "email": "hirematee.ai@gmail.com"
                },
                "to": [{"email": email}],
                "subject": "HireMate AI Password Reset Code",
                "textContent": (
                    f"Your OTP is {otp}. It expires in 10 minutes."
                )
            },
            timeout=20
        )

        if response.status_code not in (200, 201, 202):
            print("BREVO ERROR:", response.text)
            raise HTTPException(502, "Could not send reset email.")

    except requests.RequestException:
        raise HTTPException(502, "Email service connection failed.")


@app.post("/api/forgot-password")
def forgot_password(data: dict):
    email = str(data.get("email", "")).strip().lower()

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Invalid email.")

    with connect_db() as con:
        user = con.execute(
            "SELECT id FROM users WHERE LOWER(email)=%s",
            (email,)
        ).fetchone()

        if not user:
            return {"message": "If the account exists, a code was sent."}

        previous = con.execute("""
            SELECT last_sent_at FROM password_reset_otps
            WHERE email=%s
        """, (email,)).fetchone()

        if previous and (
            time.time() - previous["last_sent_at"].timestamp()
        ) < 60:
            raise HTTPException(429, "Wait 60 seconds before retrying.")

        otp = f"{secrets.randbelow(1000000):06d}"

        otp_hash = hashlib.sha256(
            (otp + os.getenv("OTP_PEPPER", "hiremate-reset-v1")).encode()
        ).hexdigest()

        con.execute("""
            INSERT INTO password_reset_otps
            (email,otp_hash,expires_at,attempts,last_sent_at)
            VALUES(
                %s,%s,
                CURRENT_TIMESTAMP + INTERVAL '10 minutes',
                0,CURRENT_TIMESTAMP
            )
            ON CONFLICT(email) DO UPDATE SET
                otp_hash=EXCLUDED.otp_hash,
                expires_at=EXCLUDED.expires_at,
                attempts=0,
                last_sent_at=CURRENT_TIMESTAMP
        """, (email, otp_hash))

    send_reset_otp(email, otp)

    return {"message": "If the account exists, a code was sent."}


@app.post("/api/reset-password")
def reset_password(data: dict):
    email = str(data.get("email", "")).strip().lower()
    otp = str(data.get("otp", "")).strip()
    password = str(data.get("new_password", ""))

    if not re.fullmatch(r"\d{6}", otp):
        raise HTTPException(400, "Enter a valid 6-digit OTP.")

    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")

    otp_hash = hashlib.sha256(
        (otp + os.getenv("OTP_PEPPER", "hiremate-reset-v1")).encode()
    ).hexdigest()

    with connect_db() as con:
        row = con.execute(
            "SELECT * FROM password_reset_otps WHERE email=%s",
            (email,)
        ).fetchone()

        if (
            not row
            or row["expires_at"].timestamp() < time.time()
            or row["attempts"] >= 5
            or not secrets.compare_digest(otp_hash, row["otp_hash"])
        ):
            if row:
                con.execute("""
                    UPDATE password_reset_otps
                    SET attempts=attempts+1 WHERE email=%s
                """, (email,))

            raise HTTPException(400, "Invalid or expired OTP.")

        salt = secrets.token_hex(16)

        con.execute("""
            UPDATE users SET password_hash=%s,salt=%s
            WHERE LOWER(email)=%s
        """, (hash_password(password, salt), salt, email))

        con.execute("""
            DELETE FROM sessions
            WHERE user_id=(
                SELECT id FROM users WHERE LOWER(email)=%s
            )
        """, (email,))

        con.execute(
            "DELETE FROM password_reset_otps WHERE email=%s",
            (email,)
        )

    return {"message": "Password reset successfully."}


# ==================================================
# RESUME EXTRACTION
# ==================================================

SKILLS = [
    "Python", "SQL", "Excel", "Power BI", "Tableau",
    "Machine Learning", "Data Analysis", "HTML", "CSS",
    "JavaScript", "FastAPI", "Git", "Linux", "Networking",
    "Splunk", "SIEM", "Incident Response", "Threat Analysis",
    "Cybersecurity", "Cloud Computing", "AWS", "Communication",
    "Problem Solving", "Pandas", "NumPy", "Scikit-learn",
    "Active Directory", "Windows", "Linux Administration",
    "TCP/IP", "Firewalls", "SOC", "EDR"
]


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


def validate_resume_file(filename, content):
    if Path(filename).suffix.lower() not in {".pdf", ".docx"}:
        raise HTTPException(400, "Upload PDF or DOCX.")

    if not content:
        raise HTTPException(400, "Empty file.")

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, "Maximum file size is 5 MB.")

    try:
        text = extract_resume_text(filename, content)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "Could not read the resume.")

    if not text.strip():
        raise HTTPException(400, "No readable text found.")

    return text


def find_skills(text):
    text = text.lower()

    return [
        skill for skill in SKILLS
        if re.search(
            r"(?<![a-z0-9])" + re.escape(skill.lower()) + r"(?![a-z0-9])",
            text
        )
    ]


def analyze_text(text, job_title="", job_description=""):
    detected = find_skills(text)
    job_text = f"{job_title} {job_description}".strip()
    required = find_skills(job_text) if job_text else detected

    matched = [s for s in required if s in detected]
    missing = [s for s in required if s not in detected]

    keyword_score = (
        round(len(matched) / len(required) * 100)
        if required else 0
    )

    lower = text.lower()

    sections = {
        "Contact details": any(x in lower for x in ["@", "phone", "mobile"]),
        "Education": any(x in lower for x in ["education", "degree", "college"]),
        "Skills": "skills" in lower,
        "Projects": "project" in lower,
        "Experience": any(x in lower for x in ["experience", "internship"]),
        "Summary": any(x in lower for x in ["summary", "objective"])
    }

    present = [k for k, v in sections.items() if v]
    missing_sections = [k for k, v in sections.items() if not v]

    structure = round(len(present) / len(sections) * 100)
    words = len(text.split())
    readability = 100 if words >= 200 else 75 if words >= 100 else 50 if words >= 50 else 25

    ats_score = round(
        structure * 0.5 + readability * 0.2 + keyword_score * 0.3
    )

    suggestions = [
        f"Consider adding {s} section if relevant."
        for s in missing_sections
    ]

    if missing:
        suggestions.append(
            "Add missing skills only if you genuinely know them."
        )

    if words < 100:
        suggestions.append("Add relevant education, projects and experience.")

    if not suggestions:
        suggestions.append("Review spelling, dates and formatting.")

    return {
        "ats_score": ats_score,
        "structure_score": structure,
        "keyword_score": keyword_score,
        "score": keyword_score,
        "matched_skills": matched,
        "missing_skills": missing,
        "detected_skills": detected,
        "present_sections": present,
        "missing_sections": missing_sections,
        "suggestions": suggestions,
        "word_count": words,
        "note": "Rule-based estimate, not an official ATS score."
    }


# ==================================================
# USER RESUME
# ==================================================

@app.post("/api/resume")
async def save_resume(
    token: str = Form(...),
    file: UploadFile = File(...)
):
    user = require_user(token)

    filename = Path(file.filename or "").name
    content = await file.read()
    validate_resume_file(filename, content)

    with connect_db() as con:
        con.execute("""
            INSERT INTO user_resumes(user_id,filename,content)
            VALUES(%s,%s,%s)
            ON CONFLICT(user_id) DO UPDATE SET
                filename=EXCLUDED.filename,
                content=EXCLUDED.content,
                updated_at=CURRENT_TIMESTAMP
        """, (user["id"], filename, content))

    log_activity(user["id"], "resume_uploaded")

    return {"message": "Resume saved.", "filename": filename}


@app.get("/api/resume")
def get_resume(token: str = ""):
    user = require_user(token)

    with connect_db() as con:
        row = con.execute("""
            SELECT filename,updated_at
            FROM user_resumes WHERE user_id=%s
        """, (user["id"],)).fetchone()

    if not row:
        return {"exists": False}

    return {
        "exists": True,
        "filename": row["filename"],
        "updated_at": row["updated_at"].isoformat()
        if row["updated_at"] else None
    }


@app.post("/api/analyze-resume")
async def analyze_resume(
    file: UploadFile = File(...),
    job_title: str = Form(""),
    job_description: str = Form("")
):
    content = await file.read()
    text = validate_resume_file(file.filename or "", content)
    return analyze_text(text, job_title, job_description)


@app.post("/api/job-match")
async def job_match(
    token: str = Form(...),
    job_title: str = Form(""),
    job_description: str = Form(...),
    file: UploadFile | None = File(None)
):
    user = require_user(token)

    if file and file.filename:
        content = await file.read()
        text = validate_resume_file(file.filename, content)
    else:
        with connect_db() as con:
            row = con.execute("""
                SELECT filename,content FROM user_resumes
                WHERE user_id=%s
            """, (user["id"],)).fetchone()

        if not row:
            raise HTTPException(400, "Upload your resume first.")

        text = extract_resume_text(row["filename"], bytes(row["content"]))

    result = analyze_text(text, job_title, job_description)
    log_activity(user["id"], "job_description_checked")
    return result


# ==================================================
# ADZUNA JOBS
# ==================================================

def fetch_real_jobs(title="cybersecurity", location="India", page=1):
    if not ADZUNA_APP_ID or not ADZUNA_APP_KEY:
        raise HTTPException(500, "Adzuna credentials missing.")

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
                "content-type": "application/json"
            },
            timeout=20
        )
        response.raise_for_status()
        data = response.json()

    except requests.RequestException:
        raise HTTPException(502, "Adzuna service unavailable.")

    jobs = []

    for item in data.get("results", []):
        description = item.get("description") or ""
        role = item.get("title") or "Job title unavailable"

        jobs.append({
            "role": role,
            "company": (item.get("company") or {}).get("display_name", "Not specified"),
            "location": (item.get("location") or {}).get("display_name", location),
            "description": description,
            "url": item.get("redirect_url", ""),
            "skills": find_skills(role + " " + description),
            "source": "Adzuna"
        })

    return {
        "jobs": jobs,
        "total": data.get("count", len(jobs)),
        "page": page,
        "source": "Adzuna"
    }


@app.get("/api/jobs")
def get_jobs(
    title: str = "cybersecurity",
    location: str = "India",
    page: int = 1
):
    return fetch_real_jobs(title, location, page)


@app.post("/api/jobs/match")
async def match_jobs(
    token: str = Form(...),
    title: str = Form("cybersecurity"),
    location: str = Form("India"),
    page: int = Form(1)
):
    user = require_user(token)

    with connect_db() as con:
        row = con.execute("""
            SELECT filename,content FROM user_resumes
            WHERE user_id=%s
        """, (user["id"],)).fetchone()

    if not row:
        raise HTTPException(400, "Upload your resume first.")

    resume_text = extract_resume_text(
        row["filename"], bytes(row["content"])
    )
    resume_skills = find_skills(resume_text)

    result = fetch_real_jobs(title, location, page)

    for job in result["jobs"]:
        job_skills = find_skills(
            job["role"] + " " + job["description"]
        )

        matched = [
            s for s in resume_skills
            if s.lower() in {x.lower() for x in job_skills}
        ]

        missing = [
            s for s in job_skills
            if s.lower() not in {x.lower() for x in resume_skills}
        ]

        job["match_score"] = (
            round(len(matched) / len(job_skills) * 100)
            if job_skills else 0
        )
        job["matched_skills"] = matched
        job["missing_skills"] = missing

    result["jobs"].sort(
        key=lambda j: j["match_score"],
        reverse=True
    )

    return result


# ==================================================
# SKILL GAP ANALYSIS
# ==================================================

@app.post("/api/skill-gap")
def skill_gap(data: dict):
    user = require_user(str(data.get("token", "")))
    job_title = str(data.get("job_title", ""))
    job_description = str(data.get("job_description", ""))

    with connect_db() as con:
        row = con.execute("""
            SELECT filename,content FROM user_resumes
            WHERE user_id=%s
        """, (user["id"],)).fetchone()

    if not row:
        raise HTTPException(400, "Upload your resume first.")

    resume_text = extract_resume_text(
        row["filename"], bytes(row["content"])
    )

    resume_skills = find_skills(resume_text)
    required = find_skills(job_title + " " + job_description)

    return {
        "current_skills": resume_skills,
        "required_skills": required,
        "matched_skills": [s for s in required if s in resume_skills],
        "missing_skills": [s for s in required if s not in resume_skills],
        "message": "Build a learning plan for the missing skills."
    }


# ==================================================
# COVER LETTER GENERATOR
# ==================================================

@app.post("/api/cover-letter")
def cover_letter(data: dict):
    user = require_user(str(data.get("token", "")))

    role = str(data.get("job_title", "the position")).strip()
    company = str(data.get("company", "your company")).strip()

    with connect_db() as con:
        row = con.execute("""
            SELECT filename,content FROM user_resumes
            WHERE user_id=%s
        """, (user["id"],)).fetchone()

    if not row:
        raise HTTPException(400, "Upload your resume first.")

    text = extract_resume_text(row["filename"], bytes(row["content"]))
    skills = find_skills(text)

    letter = f"""Dear Hiring Manager,

I am writing to express my interest in the {role} position at {company}.

I am interested in developing my career in this field. My resume highlights my educational background, projects and skills including {", ".join(skills[:8]) if skills else "relevant technical skills"}.

I am eager to learn, contribute to your team and improve my professional skills. I would appreciate the opportunity to discuss my application.

Thank you for your time and consideration.

Sincerely,
{user["name"]}
"""

    log_activity(user["id"], "cover_letter_generated")

    return {
        "cover_letter": letter,
        "note": "Template-generated draft. Review and personalize before sending."
    }


# ==================================================
# INTERVIEW PREPARATION
# ==================================================

@app.post("/api/interview-prep")
def interview_prep(data: dict):
    user = require_user(str(data.get("token", "")))

    role = str(data.get("job_title", "General fresher role"))
    questions = [
        "Tell me about yourself.",
        f"Why are you interested in the {role} role?",
        "Explain one project from your resume.",
        "What are your strengths and areas to improve?",
        "How do you troubleshoot an unfamiliar technical issue?",
        "Describe a situation where you learned something quickly.",
        "Why should we hire you?",
        "Where do you see yourself in three years?"
    ]

    log_activity(user["id"], "interview_prep_opened")

    return {
        "role": role,
        "questions": questions,
        "note": "Practice questions. These are not AI-generated interview predictions."
    }


# ==================================================
# SAVED JOBS
# ==================================================

@app.get("/api/saved-jobs")
def get_saved_jobs(token: str = ""):
    user = require_user(token)

    with connect_db() as con:
        rows = con.execute("""
            SELECT * FROM saved_jobs
            WHERE user_id=%s ORDER BY created_at DESC
        """, (user["id"],)).fetchall()

    return {"jobs": [dict(r) for r in rows]}


@app.post("/api/saved-jobs")
def save_job(data: dict):
    user = require_user(str(data.get("token", "")))

    title = str(data.get("job_title", "")).strip()

    if not title:
        raise HTTPException(400, "Job title is required.")

    with connect_db() as con:
        row = con.execute("""
            INSERT INTO saved_jobs
            (user_id,job_title,company,location,job_url,description,source)
            VALUES(%s,%s,%s,%s,%s,%s,%s)
            RETURNING id
        """, (
            user["id"],
            title,
            data.get("company"),
            data.get("location"),
            data.get("job_url"),
            data.get("description"),
            data.get("source")
        )).fetchone()

    log_activity(user["id"], "job_saved", {"job_title": title})

    return {"message": "Job saved.", "id": row["id"]}


@app.delete("/api/saved-jobs/{job_id}")
def delete_saved_job(job_id: int, token: str = ""):
    user = require_user(token)

    with connect_db() as con:
        result = con.execute("""
            DELETE FROM saved_jobs
            WHERE id=%s AND user_id=%s
        """, (job_id, user["id"]))

    if result.rowcount == 0:
        raise HTTPException(404, "Saved job not found.")

    return {"message": "Saved job deleted."}


# ==================================================
# APPLICATION TRACKER
# ==================================================

@app.get("/api/applications")
def get_applications(token: str = ""):
    user = require_user(token)

    with connect_db() as con:
        rows = con.execute("""
            SELECT * FROM application_tracker
            WHERE user_id=%s ORDER BY created_at DESC
        """, (user["id"],)).fetchall()

    return {"applications": [dict(r) for r in rows]}


@app.post("/api/applications")
def add_application(data: dict):
    user = require_user(str(data.get("token", "")))

    title = str(data.get("job_title", "")).strip()

    if not title:
        raise HTTPException(400, "Job title is required.")

    allowed = {
        "Applied", "Shortlisted", "Interview",
        "Selected", "Rejected", "Withdrawn"
    }

    status = str(data.get("application_status", "Applied"))

    if status not in allowed:
        raise HTTPException(400, "Invalid application status.")

    with connect_db() as con:
        row = con.execute("""
            INSERT INTO application_tracker
            (user_id,job_title,company,location,job_url,
             application_status,notes)
            VALUES(%s,%s,%s,%s,%s,%s,%s)
            RETURNING id
        """, (
            user["id"],
            title,
            data.get("company"),
            data.get("location"),
            data.get("job_url"),
            status,
            data.get("notes")
        )).fetchone()

    log_activity(user["id"], "application_added")

    return {"message": "Application added.", "id": row["id"]}


@app.put("/api/applications/{application_id}")
def update_application(application_id: int, data: dict):
    user = require_user(str(data.get("token", "")))

    allowed = {
        "Applied", "Shortlisted", "Interview",
        "Selected", "Rejected", "Withdrawn"
    }

    status = str(data.get("application_status", ""))

    if status not in allowed:
        raise HTTPException(400, "Invalid status.")

    with connect_db() as con:
        result = con.execute("""
            UPDATE application_tracker
            SET application_status=%s,
                notes=%s,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=%s AND user_id=%s
        """, (
            status,
            data.get("notes"),
            application_id,
            user["id"]
        ))

    if result.rowcount == 0:
        raise HTTPException(404, "Application not found.")

    return {"message": "Application updated."}


@app.delete("/api/applications/{application_id}")
def delete_application(application_id: int, token: str = ""):
    user = require_user(token)

    with connect_db() as con:
        result = con.execute("""
            DELETE FROM application_tracker
            WHERE id=%s AND user_id=%s
        """, (application_id, user["id"]))

    if result.rowcount == 0:
        raise HTTPException(404, "Application not found.")

    return {"message": "Application deleted."}


# ==================================================
# ADMIN DASHBOARD
# ==================================================

@app.get("/api/admin/stats")
def admin_stats(token: str = ""):
    require_admin(token)

    with connect_db() as con:
        total_users = con.execute(
            "SELECT COUNT(*) AS n FROM users"
        ).fetchone()["n"]

        active_users = con.execute("""
            SELECT COUNT(*) AS n FROM users WHERE status='active'
        """).fetchone()["n"]

        total_resumes = con.execute(
            "SELECT COUNT(*) AS n FROM user_resumes"
        ).fetchone()["n"]

        total_saved_jobs = con.execute(
            "SELECT COUNT(*) AS n FROM saved_jobs"
        ).fetchone()["n"]

        total_applications = con.execute(
            "SELECT COUNT(*) AS n FROM application_tracker"
        ).fetchone()["n"]

        total_ats = con.execute(
            "SELECT COUNT(*) AS n FROM ats_history"
        ).fetchone()["n"]

        total_jobs = con.execute(
            "SELECT COUNT(*) AS n FROM job_listings"
        ).fetchone()["n"]

    return {
        "total_users": total_users,
        "active_users": active_users,
        "total_resumes": total_resumes,
        "total_saved_jobs": total_saved_jobs,
        "total_applications": total_applications,
        "total_ats_checks": total_ats,
        "managed_jobs": total_jobs
    }


@app.get("/api/admin/users")
def admin_users(token: str = ""):
    require_admin(token)

    with connect_db() as con:
        rows = con.execute("""
            SELECT id,name,email,role,status,last_login_at
            FROM users ORDER BY id DESC
        """).fetchall()

    return {"users": [dict(r) for r in rows]}


@app.put("/api/admin/users/{user_id}/status")
def admin_update_user(user_id: int, data: dict):
    admin = require_admin(str(data.get("token", "")))
    status = str(data.get("status", ""))

    if status not in {"active", "blocked"}:
        raise HTTPException(400, "Invalid status.")

    with connect_db() as con:
        target = con.execute(
            "SELECT email FROM users WHERE id=%s",
            (user_id,)
        ).fetchone()

        if not target:
            raise HTTPException(404, "User not found.")

        if target["email"].lower() == ADMIN_EMAIL:
            raise HTTPException(403, "Admin account cannot be blocked here.")

        con.execute(
            "UPDATE users SET status=%s WHERE id=%s",
            (status, user_id)
        )

        if status == "blocked":
            con.execute(
                "DELETE FROM sessions WHERE user_id=%s",
                (user_id,)
            )

    log_activity(admin["id"], "admin_user_status_changed", {
        "target_user_id": user_id,
        "status": status
    })

    return {"message": "User status updated."}


# ==================================================
# ADMIN JOB MANAGEMENT
# ==================================================

@app.get("/api/admin/jobs")
def admin_get_jobs(token: str = ""):
    require_admin(token)

    with connect_db() as con:
        rows = con.execute("""
            SELECT * FROM job_listings ORDER BY created_at DESC
        """).fetchall()

    return {"jobs": [dict(r) for r in rows]}


@app.post("/api/admin/jobs")
def admin_add_job(data: dict):
    admin = require_admin(str(data.get("token", "")))

    title = str(data.get("job_title", "")).strip()

    if not title:
        raise HTTPException(400, "Job title is required.")

    with connect_db() as con:
        row = con.execute("""
            INSERT INTO job_listings
            (job_title,company,location,description,requirements,job_url)
            VALUES(%s,%s,%s,%s,%s,%s)
            RETURNING id
        """, (
            title,
            data.get("company"),
            data.get("location"),
            data.get("description"),
            data.get("requirements"),
            data.get("job_url")
        )).fetchone()

    log_activity(admin["id"], "admin_job_created")

    return {"message": "Job created.", "id": row["id"]}


@app.delete("/api/admin/jobs/{job_id}")
def admin_delete_job(job_id: int, token: str = ""):
    admin = require_admin(token)

    with connect_db() as con:
        result = con.execute(
            "DELETE FROM job_listings WHERE id=%s",
            (job_id,)
        )

    if result.rowcount == 0:
        raise HTTPException(404, "Job not found.")

    log_activity(admin["id"], "admin_job_deleted")

    return {"message": "Job deleted."}


# ==================================================
# ADMIN ACTIVITY LOGS
# ==================================================

@app.get("/api/admin/activity")
def admin_activity(token: str = "", limit: int = 100):
    require_admin(token)

    limit = max(1, min(limit, 500))

    with connect_db() as con:
        rows = con.execute("""
            SELECT
                a.id,a.user_id,u.email,
                a.event_type,a.details,a.created_at
            FROM activity_logs a
            LEFT JOIN users u ON u.id=a.user_id
            ORDER BY a.created_at DESC
            LIMIT %s
        """, (limit,)).fetchall()

    return {"activities": [dict(r) for r in rows]}


@app.get("/api/admin/otp-monitor")
def admin_otp_monitor(token: str = ""):
    require_admin(token)

    with connect_db() as con:
        rows = con.execute("""
            SELECT email,expires_at,attempts,last_sent_at
            FROM password_reset_otps
            ORDER BY last_sent_at DESC
            LIMIT 100
        """).fetchall()

    return {"otp_requests": [dict(r) for r in rows]}


# ==================================================
# ADMIN APPLICATION STATISTICS
# ==================================================

@app.get("/api/admin/application-stats")
def admin_application_stats(token: str = ""):
    require_admin(token)

    with connect_db() as con:
        rows = con.execute("""
            SELECT application_status,COUNT(*) AS total
            FROM application_tracker
            GROUP BY application_status
            ORDER BY total DESC
        """).fetchall()

    return {"statistics": [dict(r) for r in rows]}


# ==================================================
# END
# ==================================================
