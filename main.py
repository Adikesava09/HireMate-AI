import re
import io
import os
import sqlite3
import hashlib
import secrets
from pathlib import Path
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pypdf import PdfReader
from docx import Document

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "hiremate.db"
MAX_FILE_SIZE = 5 * 1024 * 1024

load_dotenv(BASE_DIR / ".env")

ADZUNA_APP_ID = os.getenv("ADZUNA_APP_ID")
ADZUNA_APP_KEY = os.getenv("ADZUNA_APP_KEY")
print("Adzuna App ID loaded:", bool(ADZUNA_APP_ID))
print("Adzuna App Key loaded:", bool(ADZUNA_APP_KEY))

app = FastAPI(title="HireMate AI", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def connect_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with connect_db() as con:
        columns = [
            row["name"]
            for row in con.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        ]

        if columns and "salt" not in columns:
            con.execute("ALTER TABLE users RENAME TO users_legacy")

        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        """)

        con.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
    con.execute("""
            CREATE TABLE IF NOT EXISTS user_resumes (
                user_id INTEGER PRIMARY KEY,
                filename TEXT NOT NULL,
                content BLOB NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

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
            WHERE sessions.token = ?
        """, (token,)).fetchone()

    return dict(row) if row else None


@app.get("/")
def home():
    return {"app": "HireMate AI", "status": "running"}


@app.get("/api/health")
def health():
    return {"status": "ok"}


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
        raise HTTPException(
            400,
            "Password must contain at least 8 characters."
        )

    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)

    try:
        with connect_db() as con:
            con.execute("""
                INSERT INTO users (name, email, password_hash, salt)
                VALUES (?, ?, ?, ?)
            """, (name, email, password_hash, salt))
    except sqlite3.IntegrityError:
        raise HTTPException(
            409,
            "An account with this email already exists."
        )

    return {
        "message": "Account created successfully. Please log in."
    }


@app.post("/api/login")
def login(data: dict):
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    with connect_db() as con:
        user = con.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if not user:
        raise HTTPException(401, "Invalid email or password.")

    calculated = hash_password(password, user["salt"])

    if not secrets.compare_digest(
        calculated,
        user["password_hash"]
    ):
        raise HTTPException(401, "Invalid email or password.")

    token = secrets.token_urlsafe(32)

    with connect_db() as con:
        con.execute(
            "INSERT INTO sessions (token, user_id) VALUES (?, ?)",
            (token, user["id"])
        )

    return {
        "message": "Login successful.",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
        },
    }


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
        con.execute(
            "DELETE FROM sessions WHERE token = ?",
            (token,)
        )

    return {"message": "Logged out successfully."}


# --------------------------------------------------
# RESUME EXTRACTION AND VALIDATION
# --------------------------------------------------

def extract_resume_text(filename, content):
    suffix = Path(filename).suffix.lower()

    if suffix == ".pdf":
        reader = PdfReader(io.BytesIO(content))
        return "\n".join(
            page.extract_text() or ""
            for page in reader.pages
        )

    if suffix == ".docx":
        doc = Document(io.BytesIO(content))
        parts = [p.text for p in doc.paragraphs]

        for table in doc.tables:
            for row in table.rows:
                parts.extend(cell.text for cell in row.cells)

        return "\n".join(parts)

    raise HTTPException(
        400,
        "Only PDF and DOCX files are supported."
    )


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
            r"(?<![a-z0-9])"
            + re.escape(skill.lower())
            + r"(?![a-z0-9])",
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

    keyword_score = (
        round(len(matched) / len(required) * 100)
        if required else 0
    )

    lower = text.lower()

    section_checks = {
        "Contact details": any(
            x in lower for x in ["@", "phone", "mobile", "linkedin"]
        ),
        "Education": any(
            x in lower
            for x in ["education", "bachelor", "degree", "university", "college"]
        ),
        "Skills": any(
            x in lower for x in ["skills", "technologies"]
        ),
        "Projects": "project" in lower,
        "Experience": any(
            x in lower for x in ["experience", "internship", "employment"]
        ),
        "Professional summary": any(
            x in lower
            for x in [
                "professional summary",
                "career objective",
                "profile summary",
                "summary",
            ]
        ),
    }

    present_sections = [
        name for name, present in section_checks.items() if present
    ]
    missing_sections = [
        name for name, present in section_checks.items() if not present
    ]

    structure_score = round(
        len(present_sections) / len(section_checks) * 100
    )

    word_count = len(words)

    readability_score = (
        100 if word_count >= 200
        else 75 if word_count >= 100
        else 50 if word_count >= 50
        else 25
    )

    ats_score = round(
        structure_score * 0.5
        + readability_score * 0.2
        + keyword_score * 0.3
    )

    suggestions = []

    for section in missing_sections:
        suggestions.append(
            f"Consider adding a {section} section if relevant."
        )

    if missing:
        suggestions.append(
            "Add missing job-related skills only if you genuinely know them."
        )

    if word_count < 100:
        suggestions.append(
            "Consider adding relevant education, projects, skills and experience."
        )

    if not suggestions:
        suggestions.append(
            "Review spelling, formatting, dates and job-specific requirements."
        )

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
        raise HTTPException(
            400,
            "Could not read this file. Check that it is a valid PDF or DOCX."
        )

    if not text.strip():
        raise HTTPException(
            400,
            "No readable text found. Scanned PDFs may need OCR first."
        )

    return text

# --------------------------------------------------
# SAVE AND RETRIEVE USER RESUME
# --------------------------------------------------

@app.post("/api/resume")
async def save_user_resume(
    token: str = Form(...),
    file: UploadFile = File(...)
):
    user = get_user_from_token(token)

    if not user:
        raise HTTPException(401, "Please log in again.")

    filename = Path(file.filename or "").name
    content = await file.read()

    validate_resume_file(filename, content)

    with connect_db() as con:
        con.execute("""
            INSERT INTO user_resumes (user_id, filename, content)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                filename = excluded.filename,
                content = excluded.content,
                updated_at = CURRENT_TIMESTAMP
        """, (user["id"], filename, content))

    return {
        "message": "Resume saved successfully.",
        "filename": filename
    }


@app.get("/api/resume")
def get_user_resume(token: str = ""):
    user = get_user_from_token(token)

    if not user:
        raise HTTPException(401, "Please log in again.")

    with connect_db() as con:
        row = con.execute("""
            SELECT filename, content, updated_at
            FROM user_resumes
            WHERE user_id = ?
        """, (user["id"],)).fetchone()

    if not row:
        return {"exists": False, "message": "Upload your resume once."}

    return {
        "exists": True,
        "filename": row["filename"],
        "updated_at": row["updated_at"]
    }

# --------------------------------------------------
# ATS RESUME CHECKER
# --------------------------------------------------

@app.post("/api/analyze-resume")
async def analyze_resume(
    file: UploadFile = File(...),
    job_title: str = Form(""),
    job_description: str = Form(""),
):
    content = await file.read()
    text = validate_resume_file(
        Path(file.filename or "").name,
        content
    )

    return analyze_text(text, job_title, job_description)


# --------------------------------------------------
# JOB DESCRIPTION MATCHER
# --------------------------------------------------

@app.post("/api/job-match")
async def job_match(
    token: str = Form(...),
    job_title: str = Form(""),
    job_description: str = Form(...),
    file: UploadFile | None = File(None)
):
    user = get_user_from_token(token)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Please log in again."
        )

    # Use newly uploaded resume if provided
    if file and file.filename:
        filename = Path(file.filename).name
        content = await file.read()
        validate_resume_file(filename, content)

    else:
        # Otherwise, use the user's saved resume
        with connect_db() as con:
            row = con.execute(
                """
                SELECT filename, content
                FROM user_resumes
                WHERE user_id = ?
                """,
                (user["id"],)
            ).fetchone()

        if not row:
            raise HTTPException(
                status_code=400,
                detail="Please upload your resume first."
            )

        filename = row["filename"]
        content = row["content"]

    resume_text = extract_resume_text(filename, content)

    result = analyze_text(
        resume_text,
        job_title,
        job_description
    )

    return result


# --------------------------------------------------
# ADZUNA REAL JOBS SERVICE
# --------------------------------------------------

def fetch_real_jobs(title="cybersecurity", location="India", page=1):
    if not ADZUNA_APP_ID or not ADZUNA_APP_KEY:
        raise HTTPException(
            500,
            "Adzuna API credentials are missing. Check your .env file."
        )

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
            raise HTTPException(
                502,
                "Adzuna rejected the API credentials. Check your APP_ID and APP_KEY."
            )

        response.raise_for_status()
        data = response.json()

    except HTTPException:
        raise

    except requests.HTTPError as e:
        status = e.response.status_code if e.response is not None else "Unknown"
        details = e.response.text[:500] if e.response is not None else str(e)

        print(f"ADZUNA HTTP ERROR: {status}")
        print(f"ADZUNA DETAILS: {details}")

        raise HTTPException(
            502,
            f"Adzuna HTTP Error: {status}. Check terminal for details."
        )

    except requests.RequestException as e:
        print(f"ADZUNA CONNECTION ERROR: {e}")

        raise HTTPException(
            502,
            "Adzuna connection failed. Check terminal."
        )

    except ValueError as e:
        print(f"ADZUNA JSON ERROR: {e}")

        raise HTTPException(
            502,
            "Adzuna returned an invalid response."
        )

    jobs = []

    for item in data.get("results", []):
        description = item.get("description") or ""
        job_title = item.get("title") or "Job title unavailable"

        jobs.append({
            "role": job_title,
            "company": (
                (item.get("company") or {}).get("display_name")
                or "Not specified"
            ),
            "location": (
                (item.get("location") or {}).get("display_name")
                or location
            ),
            "description": description,
            "url": item.get("redirect_url", ""),
            "skills": find_skills(job_title + " " + description),
            "source": "Adzuna",
        })

    return {
        "jobs": jobs,
        "total": data.get("count", len(jobs)),
        "page": page,
        "source": "Adzuna",
    }


# --------------------------------------------------
# REAL JOBS API
# --------------------------------------------------

@app.get("/api/jobs")
def get_jobs(
    title: str = "cybersecurity",
    location: str = "India",
    page: int = 1,
):
    return fetch_real_jobs(title, location, page)


# --------------------------------------------------
# AUTOMATIC RESUME MATCH SCORES FOR REAL JOBS
# --------------------------------------------------

@app.post("/api/jobs/match")
async def match_resume_to_jobs(
    token: str = Form(...),
    title: str = Form("cybersecurity"),
    location: str = Form("India"),
    page: int = Form(1)
):
    user = get_user_from_token(token)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Please log in again."
        )

    # Retrieve the saved resume
    with connect_db() as con:
        row = con.execute(
            """
            SELECT filename, content
            FROM user_resumes
            WHERE user_id = ?
            """,
            (user["id"],)
        ).fetchone()

    if not row:
        raise HTTPException(
            status_code=400,
            detail="Please upload your resume first."
        )

    resume_text = extract_resume_text(
        row["filename"],
        row["content"]
    )

    resume_skills = find_skills(resume_text)

    result = fetch_real_jobs(
        title=title,
        location=location,
        page=page
    )

    jobs = result.get("jobs", [])

    for job in jobs:
        job_text = (
            job.get("role", "")
            + " "
            + job.get("description", "")
        )

        job_skills = find_skills(job_text)

        matched = [
            skill for skill in resume_skills
            if skill.lower() in {
                item.lower() for item in job_skills
            }
        ]

        missing = [
            skill for skill in job_skills
            if skill.lower() not in {
                item.lower() for item in resume_skills
            }
        ]

        if job_skills:
            score = round(
                len(matched) / len(job_skills) * 100
            )
        else:
            score = 0

        job["match_score"] = score
        job["matched_skills"] = matched
        job["missing_skills"] = missing

    jobs.sort(
        key=lambda job: job.get("match_score", 0),
        reverse=True
    )

    result["jobs"] = jobs
    result["resume_filename"] = row["filename"]

    return result