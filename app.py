from __future__ import annotations

import html
import hashlib
import secrets
import sqlite3
from http import cookies
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote
from wsgiref.simple_server import make_server

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "app.db"
STYLE_PATH = BASE_DIR / "static" / "style.css"

SESSIONS: dict[str, int] = {}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, password_data: str) -> bool:
    try:
        salt_hex, digest_hex = password_data.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)
    except ValueError:
        return False

    calculated = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return secrets.compare_digest(calculated, expected_digest)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS notices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(author_id) REFERENCES users(id)
            );
            """
        )


def parse_post_data(environ: dict) -> dict[str, str]:
    try:
        size = int(environ.get("CONTENT_LENGTH", "0"))
    except ValueError:
        size = 0
    body = environ["wsgi.input"].read(size).decode("utf-8")
    parsed = parse_qs(body)
    return {k: v[0] for k, v in parsed.items()}


def get_flash_message(environ: dict) -> str:
    query = environ.get("QUERY_STRING", "")
    message = parse_qs(query).get("message", [""])[0]
    return unquote(message)


def get_session_id(environ: dict) -> str | None:
    cookie = cookies.SimpleCookie(environ.get("HTTP_COOKIE", ""))
    morsel = cookie.get("session_id")
    return morsel.value if morsel else None


def get_current_user(environ: dict) -> sqlite3.Row | None:
    session_id = get_session_id(environ)
    if not session_id or session_id not in SESSIONS:
        return None

    user_id = SESSIONS[session_id]
    with get_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def html_response(start_response, content: str, status: str = "200 OK", headers=None):
    base_headers = [("Content-Type", "text/html; charset=utf-8")]
    if headers:
        base_headers.extend(headers)
    start_response(status, base_headers)
    return [content.encode("utf-8")]


def redirect_response(start_response, location: str, headers=None):
    base_headers = [("Location", location)]
    if headers:
        base_headers.extend(headers)
    start_response("302 Found", base_headers)
    return [b""]


def page(title: str, body: str, user: sqlite3.Row | None = None, message: str = "") -> str:
    nav = (
        f'<span class="welcome">{html.escape(user["username"])}님</span>'
        '<a href="/notice/new">공지 작성</a>'
        '<a href="/logout">로그아웃</a>'
        if user
        else '<a href="/login">로그인</a><a href="/register">회원가입</a>'
    )
    flash = f"<ul class='flash-list'><li>{html.escape(message)}</li></ul>" if message else ""
    return f"""<!doctype html>
<html lang='ko'>
  <head>
    <meta charset='UTF-8' />
    <meta name='viewport' content='width=device-width, initial-scale=1.0' />
    <title>{html.escape(title)}</title>
    <link rel='stylesheet' href='/static/style.css' />
  </head>
  <body>
    <header class='header'>
      <h1><a href='/'>📢 공지 웹서비스</a></h1>
      <nav>{nav}</nav>
    </header>
    <main class='container'>
      {flash}
      {body}
    </main>
  </body>
</html>
"""


def register(environ, start_response):
    user = get_current_user(environ)
    message = get_flash_message(environ)
    if environ["REQUEST_METHOD"] == "POST":
        form = parse_post_data(environ)
        username = form.get("username", "").strip()
        password = form.get("password", "").strip()
        if not username or not password:
            message = "아이디와 비밀번호를 모두 입력해주세요."
        elif len(username) < 3:
            message = "아이디는 3자 이상이어야 합니다."
        elif len(password) < 4:
            message = "비밀번호는 4자 이상이어야 합니다."
        else:
            try:
                with get_connection() as conn:
                    conn.execute(
                        "INSERT INTO users (username, password) VALUES (?, ?)",
                        (username, hash_password(password)),
                    )
                return redirect_response(
                    start_response,
                    "/login?message=" + quote("회원가입이 완료되었습니다. 로그인해주세요."),
                )
            except sqlite3.IntegrityError:
                message = "이미 존재하는 아이디입니다."

    body = """
    <section class='form-card'>
      <h2>회원가입</h2>
      <form method='post'>
        <label for='username'>아이디</label>
        <input type='text' id='username' name='username' required />
        <label for='password'>비밀번호</label>
        <input type='password' id='password' name='password' required />
        <button type='submit'>회원가입</button>
      </form>
    </section>
    """
    return html_response(start_response, page("회원가입", body, user, message))


def login(environ, start_response):
    user = get_current_user(environ)
    message = get_flash_message(environ)
    if environ["REQUEST_METHOD"] == "POST":
        form = parse_post_data(environ)
        username = form.get("username", "").strip()
        password = form.get("password", "").strip()

        with get_connection() as conn:
            db_user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if db_user and verify_password(password, db_user["password"]):
            session_id = secrets.token_hex(16)
            SESSIONS[session_id] = db_user["id"]
            return redirect_response(
                start_response,
                "/?message=" + quote(f"{db_user['username']}님 환영합니다."),
                headers=[
                    (
                        "Set-Cookie",
                        f"session_id={session_id}; HttpOnly; Path=/; SameSite=Lax",
                    )
                ],
            )
        message = "로그인 정보가 올바르지 않습니다."

    body = """
    <section class='form-card'>
      <h2>로그인</h2>
      <form method='post'>
        <label for='username'>아이디</label>
        <input type='text' id='username' name='username' required />
        <label for='password'>비밀번호</label>
        <input type='password' id='password' name='password' required />
        <button type='submit'>로그인</button>
      </form>
    </section>
    """
    return html_response(start_response, page("로그인", body, user, message))


def logout(environ, start_response):
    session_id = get_session_id(environ)
    if session_id:
        SESSIONS.pop(session_id, None)
    return redirect_response(
        start_response,
        "/?message=" + quote("로그아웃되었습니다."),
        headers=[("Set-Cookie", "session_id=deleted; Max-Age=0; Path=/")],
    )


def create_notice(environ, start_response):
    user = get_current_user(environ)
    if not user:
        return redirect_response(start_response, "/login")

    message = get_flash_message(environ)
    if environ["REQUEST_METHOD"] == "POST":
        form = parse_post_data(environ)
        title = form.get("title", "").strip()
        content = form.get("content", "").strip()
        if not title or not content:
            message = "제목과 내용을 모두 입력해주세요."
        else:
            with get_connection() as conn:
                conn.execute(
                    "INSERT INTO notices (title, content, author_id) VALUES (?, ?, ?)",
                    (title, content, user["id"]),
                )
            return redirect_response(
                start_response,
                "/?message=" + quote("공지사항이 등록되었습니다."),
            )

    body = """
    <section class='form-card'>
      <h2>새 공지사항 작성</h2>
      <form method='post'>
        <label for='title'>제목</label>
        <input type='text' id='title' name='title' required />
        <label for='content'>내용</label>
        <textarea id='content' name='content' rows='6' required></textarea>
        <button type='submit'>등록</button>
      </form>
    </section>
    """
    return html_response(start_response, page("공지 작성", body, user, message))


def serve_static(start_response):
    if not STYLE_PATH.exists():
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Not Found"]
    content = STYLE_PATH.read_text(encoding="utf-8")
    start_response("200 OK", [("Content-Type", "text/css; charset=utf-8")])
    return [content.encode("utf-8")]


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    if path == "/":
        return html_response(
            start_response,
            page("공지 목록", index_body(), get_current_user(environ), get_flash_message(environ)),
        )
    if path == "/register":
        return register(environ, start_response)
    if path == "/login":
        return login(environ, start_response)
    if path == "/logout":
        return logout(environ, start_response)
    if path == "/notice/new":
        return create_notice(environ, start_response)
    if path == "/static/style.css":
        return serve_static(start_response)

    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
    return ["Not Found".encode("utf-8")]


def index_body() -> str:
    with get_connection() as conn:
        notices = conn.execute(
            """
            SELECT n.title, n.content, n.created_at, u.username
            FROM notices n JOIN users u ON n.author_id = u.id
            ORDER BY n.id DESC
            """
        ).fetchall()

    if not notices:
        return "<h2>공지사항 게시판</h2><p>아직 등록된 공지사항이 없습니다.</p>"

    items = "".join(
        f"""
        <li class='notice-item'>
          <h3>{html.escape(n['title'])}</h3>
          <p>{html.escape(n['content'])}</p>
          <small>작성자: {html.escape(n['username'])} | {n['created_at']}</small>
        </li>
        """
        for n in notices
    )
    return f"<h2>공지사항 게시판</h2><ul class='notice-list'>{items}</ul>"


if __name__ == "__main__":
    init_db()
    with make_server("0.0.0.0", 5000, application) as server:
        print("Server running on http://localhost:5000")
        server.serve_forever()
