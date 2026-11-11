import os, math, json, time, secrets, hashlib, sqlite3, cv2
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Header, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from detector import Detector, draw, LABELS
import io, shutil
from fastapi.responses import Response

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

q("CREATE TABLE IF NOT EXISTS annotations(id INTEGER PRIMARY KEY, case_id INT, file_id INT, label, x0 REAL, y0 REAL, x1 REAL, y1 REAL, expert_id INT, created REAL)")
for m in ["ALTER TABLE labs ADD COLUMN status", "ALTER TABLE sessions ADD COLUMN created REAL", "ALTER TABLE annotations ADD COLUMN review", "ALTER TABLE annotations ADD COLUMN reviewed_by INT", "ALTER TABLE annotations ADD COLUMN reviewed_at REAL"]:
    try: q(m)
    except Exception: pass
q("CREATE TABLE IF NOT EXISTS ai_files(file_id INTEGER PRIMARY KEY, n INT, ts REAL)")   # image analysée par l'IA (même si 0 détection)
q("CREATE TABLE IF NOT EXISTS ai_preds(id INTEGER PRIMARY KEY, file_id INT, parasite, conf REAL, x0 REAL, y0 REAL, x1 REAL, y1 REAL)")   # prédictions ORIGINALES du modèle (coordonnées normalisées)
q("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INT, lab_id INT, action, target, ts REAL)")
q("UPDATE labs SET status='approved' WHERE status IS NULL")
q("UPDATE annotations SET review='pending' WHERE review IS NULL")

try: q("ALTER TABLE files ADD COLUMN raw")
except Exception: pass
NEG = "__NEG__"   # marqueur interne : image validée par l'expert « sans parasite » (échantillon négatif)
DS = DATA + "/dataset"; os.makedirs(DS + "/images", exist_ok=True); os.makedirs(DS + "/labels", exist_ok=True)   # dataset APPROUVÉ (seul exportable)
PD = DATA + "/dataset_pending"; os.makedirs(PD + "/images", exist_ok=True); os.makedirs(PD + "/labels", exist_ok=True)  # en attente de validation centrale
# LISTE MAÎTRESSE (ajout en fin de liste uniquement : les index 0-18 = modèle actuel ; ne jamais réordonner)
EXTRA = ["Schistosoma mansoni", "Schistosoma haematobium", "Schistosoma japonicum", "Clonorchis sinensis", "Fasciola hepatica", "Dicrocoelium dendriticum",
         "Diphyllobothrium latum", "Dipylidium caninum", "Trichostrongylus spp.", "Heterophyes heterophyes", "Metagonimus yokogawai", "Toxocara spp.",
         "Cryptosporidium spp.", "Cyclospora cayetanensis", "Cystoisospora belli", "Balantidium coli", "Dientamoeba fragilis", "Entamoeba hartmanni",
         "Entamoeba polecki", "Trichomonas hominis", "Enteromonas hominis", "Retortamonas intestinalis", "Sarcocystis spp.", "Microsporidia",
         "Ascaris (oeuf non fécondé)", "Larve rhabditiforme", "Larve strongyloïde"]
OTHER = ["Artéfact / non parasite", "Levure", "Débris végétal", "Grain d'amidon / pollen"]
CLASSES = LABELS + EXTRA + OTHER

def hp(pw, salt): return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120000).hex()

DEMO = os.environ.get("DAP_DEMO", "0") == "1"  # 1 = accès direct sans connexion (déconseillé) ; 0 = connexion obligatoire
SESSION_H = float(os.environ.get("DAP_SESSION_HOURS", 12))
_UQ = "SELECT u.*,l.name lab_name,l.has_expert,l.status lab_status FROM users u JOIN labs l ON l.id=u.lab_id "

def mk_user(lab_id, name, email, pw, role):
    salt = secrets.token_hex(8)
    return q("INSERT INTO users(lab_id,name,email,salt,pw,role) VALUES(?,?,?,?,?,?)", (lab_id, name, email, salt, hp(pw, salt), role))

def seed():
    ce = os.environ.get("DAP_CENTRAL_EMAIL", "central@dap.local"); cp = os.environ.get("DAP_CENTRAL_PASSWORD")
    if not q("SELECT 1 FROM users WHERE role='central'", (), True):
        if not cp: cp = secrets.token_urlsafe(9); print(f"[DAP] Compte central créé : {ce} / {cp}  (définissez DAP_CENTRAL_PASSWORD pour le fixer)", flush=True)
        lid = q("INSERT INTO labs(name,type,wilaya,has_expert,created,status) VALUES(?,?,?,?,?,?)", ("Administration centrale DAP", "Central", "", 0, time.time(), "approved"))
        mk_user(lid, "Administrateur central", ce, cp, "central")
    if os.environ.get("DAP_SEED_DEMO", "0") == "1" and not q("SELECT 1 FROM users WHERE email='labo@dap.local'", (), True):
        dp = os.environ.get("DAP_DEMO_PASSWORD", "demo1234")
        for name, ex, email, role, uname in [("Laboratoire Démo", 0, "labo@dap.local", "admin", "Technicien Démo"), ("Hôpital Expert Démo", 1, "expert@dap.local", "expert", "Dr Expert Démo")]:
            lid = q("INSERT INTO labs(name,type,wilaya,has_expert,created,status) VALUES(?,?,?,?,?,?)", (name, "Hôpital" if ex else "Laboratoire", "Relizane", ex, time.time(), "approved"))
            mk_user(lid, uname, email, dp, role)
        print(f"[DAP] Comptes démo : labo@dap.local et expert@dap.local / {dp}", flush=True)
seed()

def audit(u, action, target=""):
    try: q("INSERT INTO audit(user_id,lab_id,action,target,ts) VALUES(?,?,?,?,?)", (u["id"], u["lab_id"], action, str(target), time.time()))
    except Exception: pass

def user(authorization: str = Header(None), t: str = Query(None)):
    tok = (authorization or "").replace("Bearer ", "") or t
    u = q(_UQ.replace("FROM users u", "FROM sessions s JOIN users u ON u.id=s.user_id") + "WHERE s.token=?", (tok,), True) if tok else None
    if u:
        ss = q("SELECT created FROM sessions WHERE token=?", (tok,), True)
        if ss and ss["created"] and time.time() - ss["created"] > SESSION_H * 3600:
            q("DELETE FROM sessions WHERE token=?", (tok,)); u = None
    if not u and DEMO: u = q(_UQ + "WHERE u.email='labo@dap.local'", (), True)
    if not u: raise HTTPException(401, "Session expirée ou non authentifié")
    if u["lab_status"] != "approved": raise HTTPException(403, "Établissement non approuvé")
    return u

def central(u=Depends(user)):
    if u["role"] != "central": raise HTTPException(403, "Réservé à l'administration centrale")
    return u

def access(cid, u):
    c = q("SELECT * FROM cases WHERE id=?", (cid,), True)
    if not c: raise HTTPException(404)
    if u["role"] == "central": raise HTTPException(403, "L'administration centrale n'accède pas aux dossiers patients")
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
    t = secrets.token_hex(24); q("INSERT INTO sessions(token,user_id,created) VALUES(?,?,?)", (t, uid, time.time())); return t

@app.get("/api/health")
def health():
    try: d = det(); return {"model": "ok", "path": find_model(), "size": os.path.getsize(find_model()), "input": [int(x) for x in d.inp["shape"]], "classes": len(__import__("detector").LABELS)}
    except Exception as e: raise HTTPException(500, f"{type(e).__name__}: {e}")

@app.post("/api/register")
def register(r: Reg):
    if len(r.password) < 8: raise HTTPException(400, "Mot de passe : 8 caractères minimum")
    if q("SELECT 1 FROM users WHERE email=?", (r.email.strip().lower(),), True): raise HTTPException(409, "E-mail déjà utilisé")
    lid = q("INSERT INTO labs(name,type,wilaya,address,phone,has_expert,created,status) VALUES(?,?,?,?,?,?,?,?)", (r.lab_name, r.type, r.wilaya, r.address, r.phone, int(r.has_expert), time.time(), "pending"))
    mk_user(lid, r.name, r.email.strip().lower(), r.password, "admin")
    return {"pending": True, "message": "Demande enregistrée. Votre établissement sera activé après validation par l'administration centrale."}

@app.post("/api/login")
def login(l: Login):
    u = q(_UQ + "WHERE u.email=?", (l.email.strip().lower(),), True)
    if not u or hp(l.password, u["salt"]) != u["pw"]: raise HTTPException(401, "Identifiants invalides")
    if u["lab_status"] == "pending": raise HTTPException(403, "Établissement en attente de validation par l'administration centrale")
    if u["lab_status"] != "approved": raise HTTPException(403, "Établissement non approuvé")
    audit(u, "login"); return {"token": session(u["id"])}

@app.post("/api/logout")
def logout(authorization: str = Header(None)):
    q("DELETE FROM sessions WHERE token=?", ((authorization or "").replace("Bearer ", ""),)); return {"ok": True}

@app.get("/api/me")
def me(u=Depends(user)): return {k: u[k] for k in ("id", "name", "email", "role", "lab_id", "lab_name", "has_expert")}

@app.get("/api/team")
def team(u=Depends(user)):
    if u["role"] != "admin": raise HTTPException(403)
    return q("SELECT id,name,email,role FROM users WHERE lab_id=? ORDER BY id", (u["lab_id"],))

@app.post("/api/users")
def add_user(n: NewUser, u=Depends(user)):
    if u["role"] != "admin": raise HTTPException(403)
    if n.role not in ("tech", "expert"): raise HTTPException(400)
    if len(n.password) < 8: raise HTTPException(400, "Mot de passe : 8 caractères minimum")
    if q("SELECT 1 FROM users WHERE email=?", (n.email.strip().lower(),), True): raise HTTPException(409, "E-mail déjà utilisé")
    if n.role == "expert" and not u["has_expert"]: raise HTTPException(400, "Établissement non déclaré comme disposant d'un expert")
    mk_user(u["lab_id"], n.name, n.email.strip().lower(), n.password, n.role); audit(u, "add_user", n.email); return {"ok": True}

@app.get("/api/labs")
def labs(u=Depends(user)):
    return q("SELECT id,name,type,wilaya,has_expert FROM labs WHERE has_expert=1 AND status='approved' AND id!=?", (u["lab_id"],))

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
    c = access(cid, u); own = c["lab_id"] == u["lab_id"]; audit(u, "view_case", cid)
    refs = q("SELECT r.*,a.name from_name,b.name to_name,(SELECT name FROM users WHERE id=r.expert_id) expert_name FROM referrals r JOIN labs a ON a.id=r.from_lab JOIN labs b ON b.id=r.to_lab WHERE case_id=? ORDER BY r.id DESC", (cid,))
    can_review = any(r["to_lab"] == u["lab_id"] and r["status"] == "en_attente" for r in refs) and u["role"] in ("expert", "admin")
    return {"case": c, "own": own, "files": q("SELECT id,name,kind,parent FROM files WHERE case_id=?", (cid,)),
            "findings": q("SELECT id,file_id,parasite,conf,status,box FROM findings WHERE case_id=?", (cid,)), "referrals": refs, "can_review": can_review}

@app.post("/api/cases/{cid}/files")
async def upload(cid: int, files: List[UploadFile] = File(default=[]), u=Depends(user)):
    c = access(cid, u)
    if not files: raise HTTPException(400, "Aucun fichier reçu : choisissez une image avant de cliquer sur Téléverser")
    if c["lab_id"] != u["lab_id"]: raise HTTPException(403)
    out = []
    for f in files:
        ext = os.path.splitext(f.filename)[1].lower(); kind = "image" if ext in (".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tif", ".tiff") else "video" if ext in (".mp4", ".avi", ".mov", ".mkv", ".webm") else "doc"
        fid = q("INSERT INTO files(case_id,name,kind,path) VALUES(?,?,?,?)", (cid, f.filename, kind, ""))
        p = f"{DATA}/files/{fid}{ext}"; open(p, "wb").write(await f.read()); q("UPDATE files SET path=? WHERE id=?", (p, fid))
        if kind == "image":
            img = cv2.imread(p)
            if img is not None: out.append(analyse(cid, fid, img, f.filename, False, p))
        elif kind == "video":
            cap = cv2.VideoCapture(p); n = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
            for i in range(0, max(n, 1), max(n // 12, 1)):  # ~12 frames per video
                cap.set(cv2.CAP_PROP_POS_FRAMES, i); ok, fr = cap.read()
                if ok: out.append(analyse(cid, fid, fr, f"{f.filename} #{i}", True))
            cap.release()
    q("UPDATE cases SET status=? WHERE id=? AND status IN ('nouveau','analysé')", ("analysé", cid))
    return {"results": out}

def _snap_ai(fid, dets, IW, IH):
    """Mémorise les prédictions d'origine du modèle (pour mesurer plus tard la concordance IA / expert)."""
    if q("SELECT 1 FROM ai_files WHERE file_id=?", (fid,), True): return
    q("INSERT INTO ai_files(file_id,n,ts) VALUES(?,?,?)", (fid, len(dets), time.time()))
    for lab, conf, b in dets: q("INSERT INTO ai_preds(file_id,parasite,conf,x0,y0,x1,y1) VALUES(?,?,?,?,?,?,?)", (fid, lab, conf, b[0] / IW, b[1] / IH, b[2] / IW, b[3] / IH))

def analyse(cid, parent, img, name, frame=False, raw=None):
    try: d = det()(img)
    except Exception as e: raise HTTPException(500, f"Échec du modèle IA : {type(e).__name__}: {e}")
    if frame and not d: return {"name": name, "n": 0}
    fid = q("INSERT INTO files(case_id,name,kind,path,parent) VALUES(?,?,?,?,?)", (cid, name, "annotée", "", parent))
    p = f"{DATA}/files/{fid}_ann.jpg"; cv2.imwrite(p, draw(img, d))
    rp = raw or f"{DATA}/files/{fid}_raw.jpg"
    if not raw: cv2.imwrite(rp, img)
    q("UPDATE files SET path=?,raw=? WHERE id=?", (p, rp, fid))
    for x in d: q("INSERT INTO findings(case_id,file_id,parasite,conf,box,status) VALUES(?,?,?,?,?,?)", (cid, fid, x["parasite"], x["conf"], json.dumps(x["box"]), "auto"))
    _snap_ai(fid, [(x["parasite"], x["conf"], x["box"]) for x in d], img.shape[1], img.shape[0])
    return {"name": name, "n": len(d)}

@app.get("/api/files/{fid}")
def get_file(fid: int, raw: int = Query(0), u=Depends(user)):
    f = q("SELECT * FROM files WHERE id=?", (fid,), True)
    if not f: raise HTTPException(404)
    if u["role"] == "central":
        if not q("SELECT 1 FROM annotations WHERE file_id=?", (fid,), True): raise HTTPException(403)
    else: access(f["case_id"], u)
    return FileResponse((f["raw"] if raw and f["raw"] else f["path"]), filename=f["name"] if f["kind"] == "doc" else None, headers={"Cache-Control": "no-cache"})

@app.post("/api/cases/{cid}/refer")
def refer(cid: int, r: Refer, u=Depends(user)):
    c = access(cid, u)
    if c["lab_id"] != u["lab_id"]: raise HTTPException(403)
    if not q("SELECT 1 FROM labs WHERE id=? AND has_expert=1", (r.to_lab,), True): raise HTTPException(400, "Établissement sans expert")
    q("INSERT INTO referrals(case_id,from_lab,to_lab,sent_by,message,status,sent_at) VALUES(?,?,?,?,?,?,?)", (cid, u["lab_id"], r.to_lab, u["id"], r.message, "en_attente", time.time()))
    q("UPDATE cases SET status='envoyé pour expertise' WHERE id=?", (cid,)); audit(u, "refer", f"case {cid} -> lab {r.to_lab}"); return {"ok": True}

@app.post("/api/referrals/{rid}/report")
def report(rid: int, r: Report, u=Depends(user)):
    ref = q("SELECT * FROM referrals WHERE id=?", (rid,), True)
    if not ref or ref["to_lab"] != u["lab_id"] or u["role"] not in ("expert", "admin") or ref["status"] != "en_attente": raise HTTPException(403)
    if not (r.verdict or "").strip(): raise HTTPException(400, "Conclusion obligatoire avant l'envoi du rapport")
    for f in r.findings:
        if f.get("status") in ("confirmed", "rejected"):
            q("UPDATE findings SET status=?,confirmed_by=?,confirmed_at=? WHERE id=? AND case_id=?", (f["status"], u["id"], time.time(), f["id"], ref["case_id"]))
    q("UPDATE referrals SET status='expertisé',verdict=?,report=?,expert_id=?,reviewed_at=? WHERE id=?", (r.verdict, r.report, u["id"], time.time(), rid))
    q("UPDATE cases SET status='expertisé' WHERE id=?", (ref["case_id"],)); audit(u, "expert_report", f"case {ref['case_id']}"); return {"ok": True}

@app.get("/api/classes")
def classes(u=Depends(user)): return {"model": LABELS, "extra": EXTRA, "other": OTHER}

class AnnBox(BaseModel): label: str; box: List[float]  # [x0,y0,x1,y1] normalisés 0-1
class AnnIn(BaseModel): boxes: List[AnnBox]

def _file(fid, u):
    f = q("SELECT * FROM files WHERE id=?", (fid,), True)
    if not f: raise HTTPException(404)
    access(f["case_id"], u); return f

@app.get("/api/files/{fid}/annotations")
def get_ann(fid: int, u=Depends(user)):
    if u["role"] != "central": _file(fid, u)
    return q("SELECT label,x0,y0,x1,y1,review FROM annotations WHERE file_id=? AND label!=?", (fid, NEG))

def _rm(p):
    try: os.remove(p)
    except FileNotFoundError: pass

@app.post("/api/files/{fid}/annotations")
def save_ann(fid: int, a: AnnIn, u=Depends(user)):
    """Enregistre l'annotation de l'expert : elle reste EN ATTENTE (dossier dataset_pending) jusqu'à validation par l'administration centrale."""
    if u["role"] not in ("expert", "admin") or not u["has_expert"]: raise HTTPException(403, "Réservé à l'expert")
    f = _file(fid, u); img = cv2.imread(f["raw"] or f["path"])
    if img is None: raise HTTPException(400, "Image illisible")
    if not q("SELECT 1 FROM ai_files WHERE file_id=?", (fid,), True) and not q("SELECT 1 FROM annotations WHERE file_id=?", (fid,), True):
        h0, w0 = img.shape[:2]   # image analysée avant la mise en place du suivi : on retient les détections actuelles comme prédictions de l'IA
        _snap_ai(fid, [(r["parasite"], r["conf"], json.loads(r["box"])) for r in q("SELECT parasite,conf,box FROM findings WHERE file_id=?", (fid,))], w0, h0)
    q("DELETE FROM annotations WHERE file_id=?", (fid,)); lines = []; dets = []
    q("DELETE FROM findings WHERE file_id=?", (fid,))   # le résultat de l'expert remplace les détections de l'IA pour cette image
    IH, IW = img.shape[:2]
    for b in a.boxes:
        if b.label not in CLASSES: raise HTTPException(400, "Classe inconnue : " + b.label)
        x0, y0, x1, y1 = [min(max(v, 0.0), 1.0) for v in b.box]; x0, x1 = sorted((x0, x1)); y0, y1 = sorted((y0, y1))
        if x1 - x0 < .005 or y1 - y0 < .005: continue
        dets.append({"parasite": b.label, "class_id": CLASSES.index(b.label), "conf": None, "box": [x0 * IW, y0 * IH, x1 * IW, y1 * IH]})
        if b.label not in OTHER:   # artéfacts / levures / débris : gardés pour l'entraînement, pas comptés comme parasites
            q("INSERT INTO findings(case_id,file_id,parasite,conf,box,status,confirmed_by,confirmed_at) VALUES(?,?,?,?,?,?,?,?)", (f["case_id"], fid, b.label, None, json.dumps([x0 * IW, y0 * IH, x1 * IW, y1 * IH]), "confirmed", u["id"], time.time()))
        lines.append(f"{CLASSES.index(b.label)} {(x0+x1)/2:.6f} {(y0+y1)/2:.6f} {x1-x0:.6f} {y1-y0:.6f}")
        q("INSERT INTO annotations(case_id,file_id,label,x0,y0,x1,y1,expert_id,created,review) VALUES(?,?,?,?,?,?,?,?,?,?)", (f["case_id"], fid, b.label, x0, y0, x1, y1, u["id"], time.time(), "pending"))
    if not lines: q("INSERT INTO annotations(case_id,file_id,label,x0,y0,x1,y1,expert_id,created,review) VALUES(?,?,?,?,?,?,?,?,?,?)", (f["case_id"], fid, NEG, 0, 0, 0, 0, u["id"], time.time(), "pending"))   # échantillon négatif : image sans parasite
    _rm(f"{DS}/images/dap_{fid}.jpg"); _rm(f"{DS}/labels/dap_{fid}.txt")   # toute modification annule une validation antérieure
    cv2.imwrite(f"{PD}/images/dap_{fid}.jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 95])
    open(f"{PD}/labels/dap_{fid}.txt", "w").write("\n".join(lines))
    if f["kind"] == "annotée" and f["path"]: cv2.imwrite(f["path"], draw(img, dets))   # l'image vue par le laboratoire montre les boîtes de l'expert
    audit(u, "annotate", f"file {fid}"); return {"saved": len(lines), "negative": not lines, "review": "pending"}

# ---------- Administration centrale ----------
@app.get("/api/central/overview")
def c_overview(u=Depends(central)):
    n = lambda sql: q(sql, (), True)["n"]
    return {"labs_pending": n("SELECT COUNT(*) n FROM labs WHERE status='pending'"), "labs_approved": n("SELECT COUNT(*) n FROM labs WHERE status='approved' AND type!='Central'"),
            "ann_pending": n("SELECT COUNT(DISTINCT file_id) n FROM annotations WHERE review='pending'"), "ann_approved": n("SELECT COUNT(DISTINCT file_id) n FROM annotations WHERE review='approved'"),
            "cases": n("SELECT COUNT(*) n FROM cases"), "confirmed": n("SELECT COUNT(*) n FROM findings WHERE status='confirmed'"),
            "by_parasite": q("SELECT parasite,COUNT(*) n FROM findings WHERE status='confirmed' GROUP BY parasite ORDER BY n DESC")}

@app.get("/api/central/labs")
def c_labs(u=Depends(central)):
    return q("SELECT l.id,l.name,l.type,l.wilaya,l.address,l.phone,l.has_expert,l.status,l.created,(SELECT email FROM users WHERE lab_id=l.id AND role='admin' LIMIT 1) admin_email FROM labs l WHERE l.type!='Central' ORDER BY (l.status='pending') DESC, l.id DESC")

class Review(BaseModel): action: str

@app.post("/api/central/labs/{lid}/review")
def c_lab_review(lid: int, r: Review, u=Depends(central)):
    st = {"approve": "approved", "reject": "rejected", "suspend": "rejected"}.get(r.action)
    if not st: raise HTTPException(400)
    q("UPDATE labs SET status=? WHERE id=? AND type!='Central'", (st, lid)); audit(u, "lab_" + r.action, lid); return {"ok": True}

class ExpertFlag(BaseModel): value: bool

@app.post("/api/central/labs/{lid}/expert")
def c_lab_expert(lid: int, r: ExpertFlag, u=Depends(central)):
    q("UPDATE labs SET has_expert=? WHERE id=? AND type!='Central'", (int(r.value), lid)); audit(u, "lab_expert_" + str(r.value), lid); return {"ok": True}

@app.get("/api/central/annotations")
def c_ann(review: str = "pending", u=Depends(central)):
    return q("""SELECT a.file_id,a.review,SUM(a.label!='__NEG__') boxes,GROUP_CONCAT(DISTINCT a.label) labels,l.name lab,e.name expert,MAX(a.created) created
      FROM annotations a JOIN cases c ON c.id=a.case_id JOIN labs l ON l.id=c.lab_id LEFT JOIN users e ON e.id=a.expert_id
      WHERE a.review=? GROUP BY a.file_id ORDER BY created DESC LIMIT 300""", (review,))

@app.post("/api/central/files/{fid}/review")
def c_file_review(fid: int, r: Review, u=Depends(central)):
    if r.action not in ("approve", "reject"): raise HTTPException(400)
    new = "approved" if r.action == "approve" else "rejected"
    if not q("SELECT 1 FROM annotations WHERE file_id=?", (fid,), True): raise HTTPException(404)
    q("UPDATE annotations SET review=?,reviewed_by=?,reviewed_at=? WHERE file_id=?", (new, u["id"], time.time(), fid))
    pi, pl = f"{PD}/images/dap_{fid}.jpg", f"{PD}/labels/dap_{fid}.txt"
    if new == "approved" and os.path.exists(pi):
        shutil.copy(pi, f"{DS}/images/dap_{fid}.jpg"); shutil.copy(pl, f"{DS}/labels/dap_{fid}.txt")
    else: _rm(f"{DS}/images/dap_{fid}.jpg"); _rm(f"{DS}/labels/dap_{fid}.txt")
    audit(u, "annotation_" + r.action, f"file {fid}"); return {"ok": True}

def _iou(a, b):
    ix = max(0.0, min(a[2], b[2]) - max(a[0], b[0])); iy = max(0.0, min(a[3], b[3]) - max(a[1], b[1])); i = ix * iy
    u = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - i
    return i / u if u > 0 else 0.0

@app.get("/api/central/concordance")
def c_concordance(u=Depends(central)):
    """Concordance IA / expert : on compare les prédictions d'origine du modèle aux boîtes de l'expert (appariement IoU >= 0,5)."""
    fids = [r["file_id"] for r in q("SELECT DISTINCT a.file_id FROM annotations a JOIN ai_files f ON f.file_id=a.file_id WHERE a.review!='rejected'")]
    tp, fp, fn, conf = {}, {}, {}, {}; n_ai = n_gt = missed_unknown = neg_imgs = neg_fa = 0
    inc = lambda d, k: d.__setitem__(k, d.get(k, 0) + 1)
    for fid in fids:
        ai = [(r["parasite"], (r["x0"], r["y0"], r["x1"], r["y1"])) for r in q("SELECT parasite,x0,y0,x1,y1 FROM ai_preds WHERE file_id=?", (fid,))]
        gt_all = q("SELECT label,x0,y0,x1,y1 FROM annotations WHERE file_id=?", (fid,))
        if any(g["label"] == NEG for g in gt_all):
            neg_imgs += 1; neg_fa += 1 if ai else 0
        gt = [(g["label"], (g["x0"], g["y0"], g["x1"], g["y1"])) for g in gt_all if g["label"] != NEG]
        n_ai += len(ai); n_gt += len(gt)
        pairs = sorted(((_iou(a[1], g[1]), i, j) for i, a in enumerate(ai) for j, g in enumerate(gt)), reverse=True)
        ua, ug = set(), set()
        for v, i, j in pairs:
            if v < 0.5: break
            if i in ua or j in ug: continue
            ua.add(i); ug.add(j)
            if ai[i][0] == gt[j][0]: inc(tp, ai[i][0])
            else: inc(fp, ai[i][0]); inc(conf, (ai[i][0], gt[j][0])); (inc(fn, gt[j][0]) if gt[j][0] in LABELS else None)
        for i, a in enumerate(ai):
            if i not in ua: inc(fp, a[0])
        for j, g in enumerate(gt):
            if j not in ug: (inc(fn, g[0]) if g[0] in LABELS else None); missed_unknown += 0 if g[0] in LABELS else 1
    ratio = lambda a, b: round(a / b, 3) if b else None
    rows = []
    for c in LABELS:
        t_, f_, n_ = tp.get(c, 0), fp.get(c, 0), fn.get(c, 0)
        if t_ + f_ + n_: rows.append({"label": c, "tp": t_, "fp": f_, "fn": n_, "precision": ratio(t_, t_ + f_), "recall": ratio(t_, t_ + n_)})
    T_, F_, N_ = sum(tp.values()), sum(fp.values()), sum(fn.values())
    p, r = ratio(T_, T_ + F_), ratio(T_, T_ + N_)
    return {"images": len(fids), "ai_boxes": n_ai, "expert_boxes": n_gt, "tp": T_, "fp": F_, "fn": N_, "precision": p, "recall": r,
            "f1": round(2 * p * r / (p + r), 3) if p and r else None, "by_class": rows, "missed_unknown": missed_unknown,
            "negatives": {"images": neg_imgs, "with_ai_detection": neg_fa},
            "confusions": [{"ai": a, "expert": b, "n": n} for (a, b), n in sorted(conf.items(), key=lambda kv: -kv[1])[:10]]}

@app.get("/api/central/audit")
def c_audit(u=Depends(central)):
    return q("SELECT a.ts,a.action,a.target,u.name,u.email,l.name lab FROM audit a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN labs l ON l.id=a.lab_id ORDER BY a.id DESC LIMIT 300")

@app.get("/api/dataset/stats")
def ds_stats(u=Depends(central)):
    return {"images": q("SELECT COUNT(DISTINCT file_id) n FROM annotations WHERE review='approved'", (), True)["n"], "boxes": q("SELECT COUNT(*) n FROM annotations WHERE review='approved' AND label!='__NEG__'", (), True)["n"], "negatives": q("SELECT COUNT(*) n FROM annotations WHERE review='approved' AND label='__NEG__'", (), True)["n"],
            "pending": q("SELECT COUNT(DISTINCT file_id) n FROM annotations WHERE review='pending'", (), True)["n"],
            "by_class": q("SELECT label,COUNT(*) n FROM annotations WHERE review='approved' AND label!='__NEG__' GROUP BY label ORDER BY n DESC")}

def _ds_rows(review="all", parasite=""):
    """Une ligne par IMAGE annotée (train + label YOLO), avec établissement source et nom de l'expert."""
    rows = q("""SELECT a.file_id,a.review,a.label,a.x0,a.y0,a.x1,a.y1,a.created,l.name lab,e.name expert,c.id case_id
      FROM annotations a JOIN cases c ON c.id=a.case_id JOIN labs l ON l.id=c.lab_id LEFT JOIN users e ON e.id=a.expert_id
      WHERE (?='all' OR a.review=?) ORDER BY a.file_id DESC, a.id""", (review, review))
    out = {}
    for r in rows:
        o = out.setdefault(r["file_id"], {"file_id": r["file_id"], "case_id": r["case_id"], "review": r["review"], "lab": r["lab"], "expert": r["expert"], "created": r["created"], "labels": {}, "yolo": [], "negative": False})
        o["created"] = max(o["created"] or 0, r["created"] or 0)
        if r["label"] == NEG: o["negative"] = True; continue   # image sans parasite : fichier label YOLO vide
        o["labels"][r["label"]] = o["labels"].get(r["label"], 0) + 1
        o["yolo"].append(f"{CLASSES.index(r['label'])} {(r['x0']+r['x1'])/2:.6f} {(r['y0']+r['y1'])/2:.6f} {r['x1']-r['x0']:.6f} {r['y1']-r['y0']:.6f}")
    res = [dict(o, yolo="\n".join(o["yolo"])) for o in out.values() if not parasite or parasite.lower() in " ".join(o["labels"]).lower()]
    return sorted(res, key=lambda o: o["created"] or 0, reverse=True)

@app.get("/api/central/dataset")
def c_dataset(review: str = "all", parasite: str = "", u=Depends(central)):
    if review not in ("all", "pending", "approved", "rejected"): raise HTTPException(400)
    return _ds_rows(review, parasite)[:300]

@app.get("/api/dataset.zip")
def ds_zip(u=Depends(central)):
    """Export YOLO : train/images, train/labels, val/images, val/labels, data.yaml, sources.csv (établissement source + expert)."""
    import csv, tempfile
    tmp = tempfile.mkdtemp(); rows = [o for o in _ds_rows("approved") if os.path.exists(f"{DS}/images/dap_{o['file_id']}.jpg")]
    for sp in ("train", "val"): os.makedirs(f"{tmp}/{sp}/images"); os.makedirs(f"{tmp}/{sp}/labels")
    with open(tmp + "/sources.csv", "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh); w.writerow(["split", "image", "label", "etablissement_source", "expert", "parasites"])
        for o in rows:
            fid = o["file_id"]; sp = "val" if fid % 7 == 0 else "train"
            shutil.copy(f"{DS}/images/dap_{fid}.jpg", f"{tmp}/{sp}/images/dap_{fid}.jpg"); shutil.copy(f"{DS}/labels/dap_{fid}.txt", f"{tmp}/{sp}/labels/dap_{fid}.txt")
            w.writerow([sp, f"{sp}/images/dap_{fid}.jpg", f"{sp}/labels/dap_{fid}.txt", o["lab"], o["expert"] or "", "; ".join(f"{k} x{n}" for k, n in o["labels"].items()) or "(sans parasite)"])
    has_val = any(os.listdir(f"{tmp}/val/images"))
    open(tmp + "/data.yaml", "w").write("path: .\ntrain: train/images\nval: " + ("val/images" if has_val else "train/images") + "\nnames:\n" + "".join(f"  {i}: {n}\n" for i, n in enumerate(CLASSES)))
    arc = shutil.make_archive(DATA + "/dap_dataset", "zip", tmp); shutil.rmtree(tmp, ignore_errors=True)
    audit(u, "dataset_export"); return FileResponse(arc, filename="dap_dataset_yolo.zip")

_F = {}
def _fonts():
    """Polices du PDF : DejaVu (arabe + latin) ; repli sur Helvetica (sans arabe) si les fichiers de police sont introuvables."""
    if _F: return
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    for d in (BASE + "/fonts", "/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu"):
        try:
            pdfmetrics.registerFont(TTFont("DJ", d + "/DejaVuSans.ttf")); pdfmetrics.registerFont(TTFont("DJB", d + "/DejaVuSans-Bold.ttf"))
            _F.update(n="DJ", b="DJB", ar=True); return
        except Exception: continue
    _F.update(n="Helvetica", b="Helvetica-Bold", ar=False)

def T(t):
    """Texte pour PDF : met en forme l'arabe (lettres liées + sens droite-gauche), échappe le XML."""
    from xml.sax.saxutils import escape as X
    t = str(t or "")
    if _F.get("ar") and any("\u0600" <= ch <= "\u06ff" for ch in t):
        try:
            import arabic_reshaper
            from bidi.algorithm import get_display
            t = "\n".join(get_display(arabic_reshaper.reshape(l)) for l in t.split("\n"))
        except ImportError: pass
    elif not _F.get("ar"): t = t.encode("latin-1", "replace").decode("latin-1")   # polices de repli : caractères non latins remplacés
    return X(t).replace("\n", "<br/>")

@app.get("/api/cases/{cid}/report.pdf")
def report_pdf(cid: int, lang: str = "fr", u=Depends(user)):
    try: return _report_pdf(cid, u, lang)
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, f"Erreur de génération du PDF : {type(e).__name__}: {e}")

def _report_pdf(cid, u, lang="fr"):
    L = lambda fr, en: en if lang == "en" else fr
    """Compte rendu d'examen parasitologique des selles, mise en page type compte rendu de laboratoire algérien (bilingue FR/AR)."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RI, KeepTogether
    _fonts(); c = access(cid, u); audit(u, "report_pdf", cid)
    lab = q("SELECT * FROM labs WHERE id=?", (c["lab_id"],), True)
    P = lambda size=9, bold=False, **k: ParagraphStyle("p", fontName=_F["b"] if bold else _F["n"], fontSize=size, leading=size * 1.4, **k)
    N, B = P(9), P(9, True)
    exp = q("SELECT r.*,b.name to_name,b.wilaya to_wilaya,e.name expert_name FROM referrals r JOIN labs b ON b.id=r.to_lab LEFT JOIN users e ON e.id=r.expert_id WHERE r.case_id=? AND r.status='expertisé' ORDER BY r.id DESC LIMIT 1", (cid,), True)
    fs = q("SELECT parasite,conf,status FROM findings WHERE case_id=? AND status!='rejected' ORDER BY status,conf DESC", (cid,))
    fmt = lambda t: time.strftime("%d/%m/%Y", time.localtime(t))
    S = []
    head = Table([[Paragraph("" + L("République Algérienne Démocratique et Populaire<br/>Ministère de la Santé", "People's Democratic Republic of Algeria<br/>Ministry of Health") + "", P(8.5, True, alignment=0)),
                   Paragraph(T("الجمهورية الجزائرية الديمقراطية الشعبية") + "<br/>" + T("وزارة الصحة"), P(9.5, True, alignment=TA_RIGHT))]], colWidths=[9*cm, 8*cm])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")])); S += [head, Spacer(1, 6)]
    S += [Paragraph(T(lab["name"]) + (" - " + T(lab["wilaya"]) if lab["wilaya"] else ""), P(12, True, alignment=TA_CENTER)),
          Paragraph(T(lab["address"] or "") + (("" + L(" - Tél : ", " - Tel: ") + "" + T(lab["phone"])) if lab["phone"] else ""), P(8, alignment=TA_CENTER)), Spacer(1, 10)]
    tt = Table([[Paragraph("" + L("COMPTE RENDU D'EXAMEN PARASITOLOGIQUE DES SELLES<br/>", "STOOL PARASITOLOGY EXAMINATION REPORT<br/>") + "" + T("نتيجة الفحص الطفيلي للبراز"), P(11, True, alignment=TA_CENTER, textColor=colors.white))]], colWidths=[17*cm])
    tt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f766e")), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)])); S += [tt, Spacer(1, 8)]
    pat = Table([[Paragraph("<b>" + L("Nom et prénom / ", "Patient name / ") + "" + T("الاسم واللقب") + " :</b> " + T(c["patient_ref"]), N), Paragraph("<b>" + L("N° dossier :", "Case no.:") + "</b> %s-%05d" % (lab["id"], cid), N)],
                 [Paragraph("<b>" + L("Âge / ", "Age / ") + "" + T("السن") + " :</b> " + T(c["age"] or "-") + " &nbsp;&nbsp; <b>" + L("Sexe / ", "Sex / ") + "" + T("الجنس") + " :</b> " + T(c["sex"] or "-"), N), Paragraph("<b>" + L("Date de réception :", "Date received:") + "</b> " + fmt(c["created"]), N)],
                 [Paragraph("<b>" + L("Nature du prélèvement :", "Sample type:") + "</b> " + T(c["sample_type"]), N), Paragraph("<b>" + L("Date du résultat :", "Result date:") + "</b> " + fmt(exp["reviewed_at"] if exp else time.time()), N)]], colWidths=[10.5*cm, 6.5*cm])
    pat.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), .6, colors.grey), ("INNERGRID", (0, 0), (-1, -1), .25, colors.lightgrey), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)])); S += [pat, Spacer(1, 8)]
    if c["notes"]: S += [Paragraph("<b>" + L("Renseignements cliniques :", "Clinical information:") + "</b> " + T(c["notes"]), N), Spacer(1, 6)]
    lbl = {"auto": "" + L("Détection IA (à valider)", "AI detection (to be validated)") + "", "confirmed": "" + L("Confirmé / identifié par l'expert", "Confirmed / identified by the expert") + ""}
    S += [Paragraph("" + L("EXAMEN MICROSCOPIQUE DIRECT / ", "DIRECT MICROSCOPIC EXAMINATION / ") + "" + T("الفحص المجهري المباشر"), P(10, True)), Spacer(1, 3)]
    rows = [["" + L("Élément parasitaire retrouvé", "Parasitic element found") + "", "" + L("Confiance IA", "AI confidence") + "", L("Statut", "Status")]] + [[Paragraph(T(x["parasite"]), N), ("-" if x["conf"] is None else "%d %%" % round(x["conf"] * 100)), lbl.get(x["status"], x["status"])] for x in fs]
    if not fs: rows.append([Paragraph("" + L("Absence d'élément parasitaire détecté sur les images analysées / ", "No parasitic element detected on the analysed images / ") + "" + T("لم يتم الكشف عن أي طفيلي"), N), "", ""])
    tb = Table(rows, colWidths=[9*cm, 3*cm, 5*cm], repeatRows=1)
    tb.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), _F["n"]), ("FONTNAME", (0, 0), (-1, 0), _F["b"]), ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2f3f1")), ("GRID", (0, 0), (-1, -1), .4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")])); S += [tb, Spacer(1, 8)]
    conf_names = {}
    for x in fs:
        if x["status"] == "confirmed": conf_names[x["parasite"]] = conf_names.get(x["parasite"], 0) + 1
    if conf_names: S += [Paragraph("<b>" + L("Éléments parasitaires confirmés par l'expert :", "Parasitic elements confirmed by the expert:") + "</b> " + T(", ".join(f"{k} (x{v})" for k, v in conf_names.items())), N), Spacer(1, 6)]
    S += [Paragraph("CONCLUSION / " + T("الخلاصة"), P(10, True)), Spacer(1, 3)]
    if exp: S += [Paragraph(T(exp["verdict"] or ""), B), Paragraph(T(exp["report"] or ""), N)]
    else: S += [Paragraph("" + L("Résultat PRÉLIMINAIRE établi par intelligence artificielle, non encore validé par un médecin expert. Ne pas utiliser seul pour une décision thérapeutique.", "PRELIMINARY result produced by artificial intelligence, not yet validated by an expert physician. Do not use alone for a therapeutic decision.") + "", B)]
    S.append(Spacer(1, 8))
    imgs = [f["path"] for f in q("SELECT path FROM files WHERE case_id=? AND kind='annotée' LIMIT 4", (cid,)) if f["path"] and os.path.exists(f["path"])]
    cells = []
    for p in imgs:
        im = cv2.imread(p)
        if im is not None: h, w = im.shape[:2]; k = min(8*cm / w, 6*cm / h); cells.append(RI(p, width=w * k, height=h * k))
    if cells:
        S.append(Paragraph("" + L("Images analysées / ", "Analysed images / ") + "" + T("الصور المحللة"), P(9, True))); S.append(Spacer(1, 3))
        g = Table([cells[i:i + 2] + [""] * (2 - len(cells[i:i + 2])) for i in range(0, len(cells), 2)], colWidths=[8.5*cm, 8.5*cm]); S += [g, Spacer(1, 8)]
    sig = Table([[Paragraph("" + L("Le technicien / Le biologiste<br/>", "Technician / Biologist<br/>") + "" + T("التقني / البيولوجي"), P(8.5, True, alignment=TA_CENTER)),
                  Paragraph("" + L("Le médecin expert<br/>", "Expert physician<br/>") + "" + T("الطبيب الخبير") + ((" : " + T(exp["expert_name"] or "") + "<br/>" + T(exp["to_name"])) if exp else ""), P(8.5, True, alignment=TA_CENTER)),
                  Paragraph("" + L("Cachet<br/>", "Stamp<br/>") + "" + T("الختم"), P(8.5, True, alignment=TA_CENTER))], ["", "", ""]], colWidths=[5.6*cm] * 3, rowHeights=[1.9*cm, 2.2*cm])
    sig.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), .5, colors.grey), ("INNERGRID", (0, 0), (-1, -1), .25, colors.lightgrey), ("VALIGN", (0, 0), (-1, 0), "MIDDLE")]))
    S += [KeepTogether([sig, Spacer(1, 6), Paragraph("" + L("Document généré par la plateforme DAP. Les détections par IA constituent une aide au diagnostic et doivent être validées par un professionnel de santé qualifié.", "Document generated by the DAP platform. AI detections are a diagnostic aid and must be validated by a qualified healthcare professional.") + "", P(7, alignment=TA_CENTER, textColor=colors.grey))])]
    buf = io.BytesIO(); SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=1.5*cm, bottomMargin=1.5*cm, title=f"Compte rendu {lab['id']}-{cid}").build(S)
    return Response(buf.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f'inline; filename="compte_rendu_{cid}.pdf"'})

@app.get("/api/database")
def database(status: str = "all", parasite: str = "", u=Depends(user)):
    """Base des parasites. Établissements : uniquement leurs propres résultats. Administration centrale : toutes les détections confirmées, sans identité patient."""
    if u["role"] == "central":
        return q("""SELECT f.id,f.parasite,f.conf,f.status,f.file_id,f.confirmed_at,c.id case_id,l.name lab,c.age,c.sex,c.created,NULL patient_ref,e.name expert
          FROM findings f JOIN cases c ON c.id=f.case_id JOIN labs l ON l.id=c.lab_id LEFT JOIN users e ON e.id=f.confirmed_by
          WHERE f.status='confirmed' AND (?='' OR f.parasite=?) ORDER BY f.id DESC LIMIT 500""", (parasite, parasite))
    return q("""SELECT f.id,f.parasite,f.conf,f.status,f.file_id,f.confirmed_at,c.id case_id,l.name lab,c.age,c.sex,c.created,c.patient_ref,e.name expert
      FROM findings f JOIN cases c ON c.id=f.case_id JOIN labs l ON l.id=c.lab_id LEFT JOIN users e ON e.id=f.confirmed_by
      WHERE c.lab_id=? AND (?='all' OR f.status=?) AND (?='' OR f.parasite=?) ORDER BY f.id DESC LIMIT 500""", (u["lab_id"], status, status, parasite, parasite))

@app.get("/api/stats")
def stats(u=Depends(user)):
    l = u["lab_id"]
    return {"cases": q("SELECT COUNT(*) n FROM cases WHERE lab_id=?", (l,), True)["n"],
            "pending_out": q("SELECT COUNT(*) n FROM referrals WHERE from_lab=? AND status='en_attente'", (l,), True)["n"],
            "inbox": q("SELECT COUNT(*) n FROM referrals WHERE to_lab=? AND status='en_attente'", (l,), True)["n"],
            "confirmed": q("SELECT COUNT(*) n FROM findings f JOIN cases c ON c.id=f.case_id WHERE c.lab_id=? AND f.status='confirmed'", (l,), True)["n"],
            "by_parasite": q("SELECT f.parasite,COUNT(*) n FROM findings f JOIN cases c ON c.id=f.case_id WHERE c.lab_id=? AND f.status!='rejected' GROUP BY f.parasite ORDER BY n DESC", (l,))}

if os.path.isdir(BASE + "/static"): app.mount("/", StaticFiles(directory=BASE + "/static", html=True))
