import os, json, time, secrets, hashlib, sqlite3, cv2
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Header, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from detector import Detector, draw

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DAP_DATA", os.path.join(BASE, "data")); os.makedirs(DATA + "/files", exist_ok=True)
def find_model():
    import glob
    c = [os.environ.get("DAP_MODEL"), os.path.join(BASE, "model/exp.tflite"), os.path.join(BASE, "exp.tflite")] + glob.glob(BASE + "/**/*.tflite", recursive=True)
    for p in c:
        if p and os.path.isfile(p) and os.path.getsize(p) > 1_000_000: return p
    raise FileNotFoundError("exp.tflite introuvable ou vide dans " + BASE + " (fichiers .tflite: " + str([(p, os.path.getsize(p)) for p in glob.glob(BASE + "/**/*.tflite", recursive=True)]) + ")")
app = FastAPI(title="DAP - Diagnostic Automatique des Parasites"); _det = None
app.add_middleware(CORSMiddleware, allow_origins=os.environ.get('DAP_ORIGINS', '*').split(','), allow_methods=['*'], allow_headers=['*'])

def det():
    global _det
    if _det is None: _det = Detector(find_model())
    return _det

def q(sql, a=(), one=False):
    c = sqlite3.connect(DATA + "/dap.db"); c.row_factory = sqlite3.Row
    cur = c.execute(sql, a); r = cur.fetchall(); c.commit(); lid = cur.lastrowid; c.close()
    if sql.lstrip().upper().startswith("INSERT"): return lid
    r = [dict(x) for x in r]; return (r[0] if r else None) if one else r

for s in ["""CREATE TABLE IF NOT EXISTS labs(id INTEGER PRIMARY KEY, name, type, wilaya, address, phone, has_expert INT, created REAL)""",
 """CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, lab_id INT, name, email UNIQUE, salt, pw, role)""",
 """CREATE TABLE IF NOT EXISTS sessions(token PRIMARY KEY, user_id INT)""",
 """CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, lab_id INT, patient_ref, age, sex, sample_type, notes, status, created REAL)""",
 """CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, case_id INT, name, kind, path, parent INT)""",
 """CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, case_id INT, file_id INT, parasite, conf REAL, box, status, confirmed_by INT, confirmed_at REAL)""",
 """CREATE TABLE IF NOT EXISTS referrals(id INTEGER PRIMARY KEY, case_id INT, from_lab INT, to_lab INT, sent_by INT, message, status, verdict, report, expert_id INT, sent_at REAL, reviewed_at REAL)"""]:
    q(s)

def hp(pw, salt): return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120000).hex()

def user(authorization: str = Header(None), t: str = Query(None)):
    tok = (authorization or "").replace("Bearer ", "") or t
    u = q("SELECT u.*,l.name lab_name,l.has_expert FROM sessions s JOIN users u ON u.id=s.user_id JOIN labs l ON l.id=u.lab_id WHERE s.token=?", (tok,), True)
    if not u: raise HTTPException(401, "Non authentifié")
    return u

def access(cid, u):
    c = q("SELECT * FROM cases WHERE id=?", (cid,), True)
    if not c: raise HTTPException(404)
    if c["lab_id"] != u["lab_id"] and not q("SELECT 1 FROM referrals WHERE case_id=? AND to_lab=?", (cid, u["lab_id"]), True): raise HTTPException(403)
    return c

class Reg(BaseModel):
    lab_name: str; type: str = "Laboratoire"; wilaya: str = ""; address: str = ""; phone: str = ""; has_expert: bool = False
    name: str; email: str; password: str
class Login(BaseModel): email: str; password: str
class NewUser(BaseModel): name: str; email: str; password: str; role: str = "tech"
class NewCase(BaseModel): patient_ref: str; age: str = ""; sex: str = ""; sample_type: str = "Selles"; notes: str = ""
class Refer(BaseModel): to_lab: int; message: str = ""
class Report(BaseModel): verdict: str; report: str; findings: List[dict] = []  # [{id, status: confirmed|rejected}]

def session(uid):
    t = secrets.token_hex(24); q("INSERT INTO sessions VALUES(?,?)", (t, uid)); return t

@app.get("/api/health")
def health():
    try: d = det(); return {"model": "ok", "path": find_model(), "size": os.path.getsize(find_model()), "input": [int(x) for x in d.inp["shape"]], "classes": len(__import__("detector").LABELS)}
    except Exception as e: raise HTTPException(500, f"{type(e).__name__}: {e}")

@app.post("/api/register")
def register(r: Reg):
    if q("SELECT 1 FROM users WHERE email=?", (r.email,), True): raise HTTPException(409, "E-mail déjà utilisé")
    lid = q("INSERT INTO labs(name,type,wilaya,address,phone,has_expert,created) VALUES(?,?,?,?,?,?,?)", (r.lab_name, r.type, r.wilaya, r.address, r.phone, int(r.has_expert), time.time()))
    salt = secrets.token_hex(8)
    uid = q("INSERT INTO users(lab_id,name,email,salt,pw,role) VALUES(?,?,?,?,?,?)", (lid, r.name, r.email, salt, hp(r.password, salt), "admin"))
    return {"token": session(uid)}

@app.post("/api/login")
def login(l: Login):
    u = q("SELECT * FROM users WHERE email=?", (l.email,), True)
    if not u or hp(l.password, u["salt"]) != u["pw"]: raise HTTPException(401, "Identifiants invalides")
    return {"token": session(u["id"])}

@app.get("/api/me")
def me(u=Depends(user)): return {k: u[k] for k in ("id", "name", "email", "role", "lab_id", "lab_name", "has_expert")}

@app.post("/api/users")
def add_user(n: NewUser, u=Depends(user)):
    if u["role"] != "admin": raise HTTPException(403)
    if n.role not in ("tech", "expert"): raise HTTPException(400)
    salt = secrets.token_hex(8)
    q("INSERT INTO users(lab_id,name,email,salt,pw,role) VALUES(?,?,?,?,?,?)", (u["lab_id"], n.name, n.email, salt, hp(n.password, salt), n.role)); return {"ok": True}

@app.get("/api/labs")
def labs(u=Depends(user)):
    return q("SELECT id,name,type,wilaya,has_expert FROM labs WHERE has_expert=1 AND id!=?", (u["lab_id"],))

@app.post("/api/cases")
def new_case(c: NewCase, u=Depends(user)):
    return {"id": q("INSERT INTO cases(lab_id,patient_ref,age,sex,sample_type,notes,status,created) VALUES(?,?,?,?,?,?,?,?)", (u["lab_id"], c.patient_ref, c.age, c.sex, c.sample_type, c.notes, "nouveau", time.time()))}

@app.get("/api/cases")
def cases(u=Depends(user)):
    return q("""SELECT c.*,(SELECT COUNT(*) FROM findings f WHERE f.case_id=c.id) n_findings,
      (SELECT GROUP_CONCAT(DISTINCT parasite) FROM findings f WHERE f.case_id=c.id AND f.status!='rejected') parasites,
      (c.lab_id!=?) received FROM cases c WHERE c.lab_id=? OR c.id IN (SELECT case_id FROM referrals WHERE to_lab=?) ORDER BY c.id DESC""", (u["lab_id"],) * 3)

@app.get("/api/cases/{cid}")
def case(cid: int, u=Depends(user)):
    c = access(cid, u); own = c["lab_id"] == u["lab_id"]
    refs = q("SELECT r.*,a.name from_name,b.name to_name FROM referrals r JOIN labs a ON a.id=r.from_lab JOIN labs b ON b.id=r.to_lab WHERE case_id=? ORDER BY r.id DESC", (cid,))
    can_review = any(r["to_lab"] == u["lab_id"] and r["status"] == "en_attente" for r in refs) and u["role"] in ("expert", "admin")
    return {"case": c, "own": own, "files": q("SELECT id,name,kind,parent FROM files WHERE case_id=?", (cid,)),
            "findings": q("SELECT id,file_id,parasite,conf,status FROM findings WHERE case_id=?", (cid,)), "referrals": refs, "can_review": can_review}

@app.post("/api/cases/{cid}/files")
async def upload(cid: int, files: List[UploadFile] = File(...), u=Depends(user)):
    c = access(cid, u)
    if c["lab_id"] != u["lab_id"]: raise HTTPException(403)
    out = []
    for f in files:
        ext = os.path.splitext(f.filename)[1].lower(); kind = "image" if ext in (".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff") else "video" if ext in (".mp4", ".avi", ".mov", ".mkv", ".webm") else "doc"
        fid = q("INSERT INTO files(case_id,name,kind,path) VALUES(?,?,?,?)", (cid, f.filename, kind, ""))
        p = f"{DATA}/files/{fid}{ext}"; open(p, "wb").write(await f.read()); q("UPDATE files SET path=? WHERE id=?", (p, fid))
        if kind == "image":
            img = cv2.imread(p)
            if img is not None: out.append(analyse(cid, fid, img, f.filename))
        elif kind == "video":
            cap = cv2.VideoCapture(p); n = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
            for i in range(0, max(n, 1), max(n // 12, 1)):  # ~12 frames per video
                cap.set(cv2.CAP_PROP_POS_FRAMES, i); ok, fr = cap.read()
                if ok: out.append(analyse(cid, fid, fr, f"{f.filename} #{i}", True))
            cap.release()
    q("UPDATE cases SET status=? WHERE id=? AND status IN ('nouveau','analysé')", ("analysé", cid))
    return {"results": out}

def analyse(cid, parent, img, name, frame=False):
    try: d = det()(img)
    except Exception as e: raise HTTPException(500, f"Échec du modèle IA : {type(e).__name__}: {e}")
    if frame and not d: return {"name": name, "n": 0}
    fid = q("INSERT INTO files(case_id,name,kind,path,parent) VALUES(?,?,?,?,?)", (cid, name, "annotée", "", parent))
    p = f"{DATA}/files/{fid}_ann.jpg"; cv2.imwrite(p, draw(img, d)); q("UPDATE files SET path=? WHERE id=?", (p, fid))
    for x in d: q("INSERT INTO findings(case_id,file_id,parasite,conf,box,status) VALUES(?,?,?,?,?,?)", (cid, fid, x["parasite"], x["conf"], json.dumps(x["box"]), "auto"))
    return {"name": name, "n": len(d)}

@app.get("/api/files/{fid}")
def get_file(fid: int, u=Depends(user)):
    f = q("SELECT * FROM files WHERE id=?", (fid,), True)
    if not f: raise HTTPException(404)
    access(f["case_id"], u); return FileResponse(f["path"], filename=f["name"] if f["kind"] == "doc" else None)

@app.post("/api/cases/{cid}/refer")
def refer(cid: int, r: Refer, u=Depends(user)):
    c = access(cid, u)
    if c["lab_id"] != u["lab_id"]: raise HTTPException(403)
    if not q("SELECT 1 FROM labs WHERE id=? AND has_expert=1", (r.to_lab,), True): raise HTTPException(400, "Établissement sans expert")
    q("INSERT INTO referrals(case_id,from_lab,to_lab,sent_by,message,status,sent_at) VALUES(?,?,?,?,?,?,?)", (cid, u["lab_id"], r.to_lab, u["id"], r.message, "en_attente", time.time()))
    q("UPDATE cases SET status='envoyé pour expertise' WHERE id=?", (cid,)); return {"ok": True}

@app.post("/api/referrals/{rid}/report")
def report(rid: int, r: Report, u=Depends(user)):
    ref = q("SELECT * FROM referrals WHERE id=?", (rid,), True)
    if not ref or ref["to_lab"] != u["lab_id"] or u["role"] not in ("expert", "admin") or ref["status"] != "en_attente": raise HTTPException(403)
    for f in r.findings:
        if f.get("status") in ("confirmed", "rejected"):
            q("UPDATE findings SET status=?,confirmed_by=?,confirmed_at=? WHERE id=? AND case_id=?", (f["status"], u["id"], time.time(), f["id"], ref["case_id"]))
    q("UPDATE referrals SET status='expertisé',verdict=?,report=?,expert_id=?,reviewed_at=? WHERE id=?", (r.verdict, r.report, u["id"], time.time(), rid))
    q("UPDATE cases SET status='expertisé' WHERE id=?", (ref["case_id"],)); return {"ok": True}

@app.get("/api/database")
def database(status: str = "confirmed", parasite: str = "", u=Depends(user)):
    """Base des parasites : confirmés de tout le réseau (sans identité patient) + propres résultats du labo."""
    rows = q("""SELECT f.id,f.parasite,f.conf,f.status,f.file_id,f.confirmed_at,c.id case_id,l.name lab,c.age,c.sex,c.created,
      CASE WHEN c.lab_id=? THEN c.patient_ref ELSE NULL END patient_ref, e.name expert
      FROM findings f JOIN cases c ON c.id=f.case_id JOIN labs l ON l.id=c.lab_id LEFT JOIN users e ON e.id=f.confirmed_by
      WHERE (?='all' OR f.status=?) AND (?='' OR f.parasite=?) AND (f.status='confirmed' OR c.lab_id=?) ORDER BY f.id DESC LIMIT 500""",
      (u["lab_id"], status, status, parasite, parasite, u["lab_id"]))
    return rows

@app.get("/api/stats")
def stats(u=Depends(user)):
    l = u["lab_id"]
    return {"cases": q("SELECT COUNT(*) n FROM cases WHERE lab_id=?", (l,), True)["n"],
            "pending_out": q("SELECT COUNT(*) n FROM referrals WHERE from_lab=? AND status='en_attente'", (l,), True)["n"],
            "inbox": q("SELECT COUNT(*) n FROM referrals WHERE to_lab=? AND status='en_attente'", (l,), True)["n"],
            "confirmed": q("SELECT COUNT(*) n FROM findings f JOIN cases c ON c.id=f.case_id WHERE c.lab_id=? AND f.status='confirmed'", (l,), True)["n"],
            "by_parasite": q("SELECT parasite,COUNT(*) n FROM findings WHERE status='confirmed' GROUP BY parasite ORDER BY n DESC")}

if os.path.isdir(BASE + "/static"): app.mount("/", StaticFiles(directory=BASE + "/static", html=True))
