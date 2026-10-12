import os
import re
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta

import requests
from flask import (Flask, jsonify, render_template, request,
                   send_from_directory)
from flask_jwt_extended import (JWTManager, create_access_token, decode_token,
                                get_jwt_identity, jwt_required)
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(BASE, "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_secret(name):
    """Use env var if set, otherwise create a persistent random secret file."""
    value = os.environ.get(name)
    if value:
        return value
    path = os.path.join(BASE, "." + name.lower())
    if os.path.exists(path):
        return open(path).read().strip()
    value = uuid.uuid4().hex + uuid.uuid4().hex
    with open(path, "w") as f:
        f.write(value)
    return value


db_url = os.environ.get("DATABASE_URL", "sqlite:///chat.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app = Flask(__name__)
app.config["SECRET_KEY"] = get_secret("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = get_secret("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB uploads

db = SQLAlchemy(app)
jwt = JWTManager(app)
# threading mode works on Termux and with gunicorn --threads
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

FIREBASE_API_KEY = os.environ.get("FIREBASE_API_KEY")
IMAGE_RE = re.compile(r"^/uploads/[0-9a-f]{32}\.(png|jpg|gif|webp)$")


# ---------------------------------------------------------------- models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))              # null for OTP-only users
    phone = db.Column(db.String(20), unique=True)          # set for OTP users


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    __table_args__ = (db.UniqueConstraint("group_id", "user_id"),)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"))   # direct chat
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))     # group chat
    text = db.Column(db.Text, default="")
    image = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship("User", foreign_keys=[sender_id])

    def to_dict(self):
        return {"id": self.id, "from": self.sender_id,
                "from_name": self.sender.username, "to": self.receiver_id,
                "group": self.group_id, "text": self.text or "",
                "image": self.image, "time": self.created_at.isoformat() + "Z"}


with app.app_context():
    from sqlalchemy import inspect
    insp = inspect(db.engine)
    if insp.has_table("message") and \
            "group_id" not in [c["name"] for c in insp.get_columns("message")]:
        print("Old v1 database found - resetting it for the new version.")
        db.drop_all()
    db.create_all()

online = {}       # user_id -> open connection count
sid_user = {}     # socket id -> user_id
user_sids = defaultdict(set)


# ---------------------------------------------------------------- helpers
hits = defaultdict(deque)


def rate_limited(bucket, limit=10, per=60):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    q = hits[(bucket, ip.split(",")[0].strip())]
    now = time.time()
    while q and now - q[0] > per:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def valid_username(name):
    return 3 <= len(name) <= 30 and name.replace("_", "").isalnum()


def session_for(user):
    return jsonify(token=create_access_token(identity=str(user.id)),
                   user={"id": user.id, "username": user.username})


def is_member(gid, uid):
    return Member.query.filter_by(group_id=gid, user_id=uid).first() is not None


@app.after_request
def secure(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.errorhandler(413)
def too_big(_):
    return jsonify(error="File too large (max 5 MB)"), 413


# ---------------------------------------------------------------- pages
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/sw.js")
def service_worker():
    return send_from_directory(os.path.join(BASE, "static"), "sw.js",
                               mimetype="application/javascript")


@app.route("/uploads/<name>")
def uploads(name):
    if not IMAGE_RE.match("/uploads/" + name):
        return "", 404
    return send_from_directory(UPLOAD_DIR, name)


# ---------------------------------------------------------------- auth
@app.get("/api/config")
def config():
    cfg = None
    if FIREBASE_API_KEY:
        cfg = {"apiKey": FIREBASE_API_KEY,
               "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN", ""),
               "projectId": os.environ.get("FIREBASE_PROJECT_ID", ""),
               "appId": os.environ.get("FIREBASE_APP_ID", "")}
    return jsonify(firebase=cfg)


def creds():
    data = request.get_json(silent=True) or {}
    return (data.get("username") or "").strip().lower(), data.get("password") or ""


@app.post("/api/register")
def register():
    if rate_limited("register"):
        return jsonify(error="Too many attempts, wait a minute"), 429
    username, password = creds()
    if not valid_username(username):
        return jsonify(error="Username: 3-30 letters/numbers/underscore"), 400
    if len(password) < 6:
        return jsonify(error="Password must be at least 6 characters"), 400
    if User.query.filter_by(username=username).first():
        return jsonify(error="Username already taken"), 409
    user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    return session_for(user), 201


@app.post("/api/login")
def login():
    if rate_limited("login"):
        return jsonify(error="Too many attempts, wait a minute"), 429
    username, password = creds()
    user = User.query.filter_by(username=username).first()
    if not user or not user.password_hash or \
            not check_password_hash(user.password_hash, password):
        return jsonify(error="Wrong username or password"), 401
    return session_for(user)


@app.post("/api/otp-login")
def otp_login():
    """Verify a Firebase phone-auth ID token and log the user in."""
    if not FIREBASE_API_KEY:
        return jsonify(error="Phone login is not configured"), 501
    if rate_limited("otp", limit=20):
        return jsonify(error="Too many attempts, wait a minute"), 429
    id_token = (request.get_json(silent=True) or {}).get("idToken")
    if not id_token:
        return jsonify(error="Missing token"), 400
    try:
        r = requests.post(
            "https://identitytoolkit.googleapis.com/v1/accounts:lookup",
            params={"key": FIREBASE_API_KEY}, json={"idToken": id_token},
            timeout=10)
    except requests.RequestException:
        return jsonify(error="Could not reach Firebase"), 502
    users = r.json().get("users") if r.status_code == 200 else None
    phone = users[0].get("phoneNumber") if users else None
    if not phone:
        return jsonify(error="Phone verification failed"), 401
    user = User.query.filter_by(phone=phone).first()
    if not user:
        base = "user" + phone[-6:]
        name = base
        while User.query.filter_by(username=name).first():
            name = base + str(uuid.uuid4().int % 1000)
        user = User(username=name, phone=phone)
        db.session.add(user)
        db.session.commit()
    return session_for(user)


@app.patch("/api/me")
@jwt_required()
def rename():
    me = db.session.get(User, int(get_jwt_identity()))
    name = ((request.get_json(silent=True) or {}).get("username") or "").strip().lower()
    if not valid_username(name):
        return jsonify(error="Username: 3-30 letters/numbers/underscore"), 400
    taken = User.query.filter(User.username == name, User.id != me.id).first()
    if taken:
        return jsonify(error="Username already taken"), 409
    me.username = name
    db.session.commit()
    return jsonify(user={"id": me.id, "username": me.username})


# ---------------------------------------------------------------- data
@app.get("/api/users")
@jwt_required()
def users():
    me = int(get_jwt_identity())
    rows = User.query.filter(User.id != me).order_by(User.username).all()
    return jsonify([{"id": u.id, "username": u.username,
                     "online": online.get(u.id, 0) > 0} for u in rows])


@app.get("/api/messages/<int:other_id>")
@jwt_required()
def history(other_id):
    me = int(get_jwt_identity())
    msgs = (Message.query.filter(Message.group_id.is_(None))
            .filter(((Message.sender_id == me) & (Message.receiver_id == other_id)) |
                    ((Message.sender_id == other_id) & (Message.receiver_id == me)))
            .order_by(Message.id.desc()).limit(200).all())
    return jsonify([m.to_dict() for m in reversed(msgs)])


@app.get("/api/groups")
@jwt_required()
def my_groups():
    me = int(get_jwt_identity())
    rows = (Group.query.join(Member, Member.group_id == Group.id)
            .filter(Member.user_id == me).order_by(Group.name).all())
    return jsonify([{"id": g.id, "name": g.name} for g in rows])


@app.post("/api/groups")
@jwt_required()
def create_group():
    me = int(get_jwt_identity())
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()[:50]
    ids = {int(i) for i in data.get("members", []) if str(i).isdigit()}
    ids = {u.id for u in User.query.filter(User.id.in_(ids)).all()} - {me}
    if not name or not ids:
        return jsonify(error="Give the group a name and pick at least one member"), 400
    group = Group(name=name, owner_id=me)
    db.session.add(group)
    db.session.flush()
    for uid in ids | {me}:
        db.session.add(Member(group_id=group.id, user_id=uid))
    db.session.commit()
    for uid in ids | {me}:           # live-join connected members
        for sid in list(user_sids.get(uid, [])):
            join_room(f"group_{group.id}", sid=sid, namespace="/")
        socketio.emit("group_added", {"id": group.id}, room=f"user_{uid}")
    return jsonify(id=group.id, name=group.name), 201


@app.get("/api/groups/<int:gid>/messages")
@jwt_required()
def group_history(gid):
    if not is_member(gid, int(get_jwt_identity())):
        return jsonify(error="Not a member"), 403
    msgs = (Message.query.filter_by(group_id=gid)
            .order_by(Message.id.desc()).limit(200).all())
    return jsonify([m.to_dict() for m in reversed(msgs)])


@app.post("/api/upload")
@jwt_required()
def upload():
    f = request.files.get("file")
    if not f:
        return jsonify(error="No file"), 400
    head = f.read(12)
    f.seek(0)
    if head.startswith(b"\x89PNG"):
        ext = "png"
    elif head.startswith(b"\xff\xd8\xff"):
        ext = "jpg"
    elif head.startswith(b"GIF8"):
        ext = "gif"
    elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        ext = "webp"
    else:
        return jsonify(error="Only PNG, JPG, GIF or WEBP images"), 400
    name = f"{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(UPLOAD_DIR, name))
    return jsonify(url="/uploads/" + name)


# ---------------------------------------------------------------- realtime
@socketio.on("connect")
def on_connect(auth):
    try:
        uid = int(decode_token((auth or {}).get("token", ""))["sub"])
    except Exception:
        return False  # reject unauthenticated sockets
    sid_user[request.sid] = uid
    user_sids[uid].add(request.sid)
    join_room(f"user_{uid}")
    for m in Member.query.filter_by(user_id=uid).all():
        join_room(f"group_{m.group_id}")
    online[uid] = online.get(uid, 0) + 1
    emit("presence", {"id": uid, "online": True}, broadcast=True)


@socketio.on("disconnect")
def on_disconnect():
    uid = sid_user.pop(request.sid, None)
    if uid is None:
        return
    user_sids[uid].discard(request.sid)
    online[uid] = max(0, online.get(uid, 1) - 1)
    if online[uid] == 0:
        emit("presence", {"id": uid, "online": False}, broadcast=True)


@socketio.on("send_message")
def on_message(data):
    uid = sid_user.get(request.sid)
    data = data or {}
    text = (data.get("text") or "").strip()[:2000]
    image = data.get("image")
    if uid is None or not (text or image):
        return
    if image:
        if not IMAGE_RE.match(image) or \
                not os.path.exists(os.path.join(UPLOAD_DIR, image.split("/")[-1])):
            return
    gid, to = data.get("group"), data.get("to")
    if gid is not None and not isinstance(gid, int):
        return
    if gid is None and (not isinstance(to, int) or to == uid):
        return
    if gid:
        if not is_member(gid, uid):
            return
        msg = Message(sender_id=uid, group_id=gid, text=text, image=image)
        rooms = [f"group_{gid}"]
    else:
        if not db.session.get(User, to):
            return
        msg = Message(sender_id=uid, receiver_id=to, text=text, image=image)
        rooms = [f"user_{to}", f"user_{uid}"]
    db.session.add(msg)
    db.session.commit()
    payload = msg.to_dict()
    for room in rooms:
        emit("new_message", payload, room=room)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)),
                 allow_unsafe_werkzeug=True)
