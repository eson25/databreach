from fastapi import FastAPI, HTTPException
import requests
import hashlib
import sqlite3
import os

app = FastAPI()

HIBP_API_KEY = os.getenv("HIBP_API_KEY")  # Use an environment variable for security
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range/"

# Connect to database
conn = sqlite3.connect("breaches.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS breaches (company TEXT, count INTEGER)")
conn.commit()

@app.get("/check_email/{email}")
def check_email(email: str):
    headers = {"hibp-api-key": HIBP_API_KEY}
    response = requests.get(HIBP_BREACH_URL + email, headers=headers)

    if response.status_code == 404:
        return {"email": email, "breaches": []}
    elif response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Error contacting HIBP")

    breaches = response.json()
    breached_companies = [b["Name"] for b in breaches]

    for company in breached_companies:
        cursor.execute("SELECT count FROM breaches WHERE company=?", (company,))
        result = cursor.fetchone()
        if result:
            cursor.execute("UPDATE breaches SET count = count + 1 WHERE company=?", (company,))
        else:
            cursor.execute("INSERT INTO breaches (company, count) VALUES (?, ?)", (company, 1))
        conn.commit()

    return {"email": email, "breaches": breached_companies}

@app.get("/check_password/{password}")
def check_password(password: str):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    response = requests.get(HIBP_PASSWORD_URL + prefix)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Error contacting HIBP")

    leaked_passwords = {line.split(":")[0] for line in response.text.splitlines()}
    return {"password_leaked": suffix in leaked_passwords}

@app.get("/leaderboard")
def leaderboard():
    cursor.execute("SELECT * FROM breaches ORDER BY count DESC LIMIT 10")
    return {"most_breached_companies": cursor.fetchall()}
