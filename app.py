import json
import os
import re
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Generator, Tuple, Optional
import io
import csv
import datetime
import sqlite3
import hashlib
import base64
import secrets
import gradio as gr
from openai import OpenAI
from fastapi import FastAPI
from gradio.routes import mount_gradio_app
import uvicorn

API_CFG = os.getenv("api_key")
DEFAULT_MODEL = "glm-4.5-air"
DEFAULT_BASE_URL = "https://open.bigmodel.cn/api/paas/v4/"
DEFAULT_MAX_TOKENS = 5000
DEFAULT_TEMPERATURE = 0.7
DEFAULT_TOP_P = 0.95
ADMIN_ACCESS_CODE = os.getenv("ADMIN_ACCESS_CODE")

# -------------------------
# 全局状态
# -------------------------
LAST_OUTLINE: Dict[str, Any] = {
    "text": "",
    "episodes": [],   
    "genre": "",
    "synopsis": "",
    "api_key": API_CFG,
    "total_eps": 0,
    "scripts": [],     # list of {"ep": int, "script": str, "memory": str}
    "memories": []     
}

# -------------------------
# SQLite 数据库 
# -------------------------
DB_PATH = "app_data.db"

def get_db_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pwd_salt TEXT NOT NULL,
        pwd_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS scripts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        ep INTEGER,
        title TEXT,
        script TEXT,
        memory TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    conn.commit()
    conn.close()

# 密码哈希（PBKDF2）
def hash_password(password: str, salt: Optional[bytes] = None):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return base64.b64encode(salt).decode(), base64.b64encode(dk).decode()

def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    salt = base64.b64decode(salt_b64)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return base64.b64encode(dk).decode() == hash_b64

# 用户/会话/脚本 操作函数
def register_user_db(username: str, password: str) -> Tuple[bool, str]:
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return False, "用户名已存在"
    salt_b64, hash_b64 = hash_password(password)
    now = datetime.datetime.utcnow().isoformat()
    cur.execute("INSERT INTO users(username, pwd_salt, pwd_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, salt_b64, hash_b64, now))
    conn.commit()
    conn.close()
    return True, "注册成功"

def login_user_db(username: str, password: str, session_days: int = 7) -> Tuple[bool, Optional[str]]:
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return False, "用户不存在"
    if not verify_password(password, row["pwd_salt"], row["pwd_hash"]):
        conn.close()
        return False, "密码错误"
    token = secrets.token_urlsafe(32)
    expires = (datetime.datetime.utcnow() + datetime.timedelta(days=session_days)).isoformat()
    cur.execute("INSERT OR REPLACE INTO sessions(token, user_id, expires_at) VALUES (?, ?, ?)",
                (token, row["id"], expires))
    conn.commit()
    conn.close()
    return True, token

def get_user_by_token(token: str) -> Optional[sqlite3.Row]:
    if not token:
        return None
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT s.token, s.expires_at, u.id AS user_id, u.username
        FROM sessions s JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
    """, (token,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    try:
        if datetime.datetime.fromisoformat(row["expires_at"]) < datetime.datetime.utcnow():
            conn = get_db_conn()
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            conn.close()
            return None
    except Exception:
        return None
    return row

def save_script_db(user_id: int, ep: Optional[int], script: str, memory: str, title: Optional[str] = None):
    conn = get_db_conn()
    cur = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO scripts(user_id, ep, title, script, memory, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, ep, title or f"Ep{ep}", script, memory, now)
    )
    conn.commit()
    conn.close()

def list_user_scripts(user_id: int, limit: int = 200):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, ep, title, script, created_at
        FROM scripts
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    """, (user_id, limit))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_script_by_id_for_user(script_id: int, user_id: int):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scripts WHERE id = ? AND user_id = ?", (script_id, user_id))
    row = cur.fetchone()
    conn.close()
    return row

# 后台：联表查看（用户名 + 剧本）
def admin_list_all_scripts(limit: int = 500) -> List[sqlite3.Row]:
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT s.id, s.user_id, u.username, s.ep, s.title, s.script, s.created_at
        FROM scripts s JOIN users u ON s.user_id = u.id
        ORDER BY s.created_at DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

# 初始化 DB
init_db()

# -------------------------
# 工具函数
# -------------------------
def split_nonempty_lines(s: str) -> List[str]:
    return [line.strip() for line in re.split(r'\r?\n', s) if line.strip()]

def get_front_memory() -> str:
    mems = LAST_OUTLINE.get("memories", [])
    if not mems:
        return "无前文记忆。"
    return "\n\n".join(mems)

def write_text_tempfile(content: str, filename: str = "script.txt") -> str:
    suffix = Path(filename).suffix or ".txt"
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="drama_")
    with open(tf.name, "w", encoding="utf-8") as f:
        f.write(content)
    return tf.name

def get_script_by_ep(ep_index: int) -> Optional[str]:
    for s in LAST_OUTLINE.get("scripts", []):
        if s.get("ep") == ep_index:
            return s.get("script", "")
    return None

def combine_all_scripts_text() -> str:
    parts = []
    parts.append(f"类型: {LAST_OUTLINE.get('genre','')}")
    syn = LAST_OUTLINE.get("synopsis", "").strip()
    if syn:
        parts.append("梗概：\n" + syn)
    outline_text = (LAST_OUTLINE.get("text") or "").strip()
    if outline_text:
        parts.append("=" * 40)
        parts.append("【全局大纲】\n" + outline_text)
    parts.append("=" * 40)
    parts.append(f"总集数（已保存）: {len(LAST_OUTLINE.get('scripts', []))}")
    parts.append("=" * 40)
    for s in sorted(LAST_OUTLINE.get("scripts", []), key=lambda x: x["ep"]):
        parts.append(f"=== Episode {s['ep']} ===\n{s.get('script','')}".rstrip())
        parts.append("-" * 40)
    return "\n".join(parts).rstrip() + "\n"

# -------------------------
# ChatLLM
# -------------------------
def ChatLLM(model_name=DEFAULT_MODEL, api_key=API_CFG, base_url=DEFAULT_BASE_URL):
    client = OpenAI(api_key=api_key, base_url=base_url)

    def chat_sync(messages, max_tokens=DEFAULT_MAX_TOKENS, temperature=DEFAULT_TEMPERATURE, top_p=DEFAULT_TOP_P) -> str:
        try:
            r = client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=temperature,
                top_p=top_p,
                max_tokens=max_tokens
            )
            try:
                return getattr(r.choices[0].message, "content", "") or ""
            except Exception:
                return r.choices[0].text or ""
        except Exception as e:
            return f"[LLM_EXCEPTION] {repr(e)}"

    def chat_stream(messages, max_tokens=DEFAULT_MAX_TOKENS, temperature=DEFAULT_TEMPERATURE, top_p=DEFAULT_TOP_P) -> Generator[Dict[str, Any], None, None]:
        try:
            responses = client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=temperature,
                top_p=top_p,
                max_tokens=max_tokens,
                stream=True
            )
            for chunk in responses:
                try:
                    if getattr(chunk, "choices", None):
                        choice = chunk.choices[0]
                        delta = getattr(choice, "delta", None)
                        if delta is not None:
                            piece = delta.get("content", "") if isinstance(delta, dict) else getattr(delta, "content", "")
                        else:
                            piece = getattr(choice, "text", "") or ""
                        finish_reason = getattr(choice, "finish_reason", None)
                        yield {"content": piece or "", "finish_reason": finish_reason}
                    else:
                        yield {"content": "", "finish_reason": None}
                except Exception:
                    yield {"content": "", "finish_reason": None}
        except Exception as e:
            yield {"content": f"[LLM_EXCEPTION] {repr(e)}", "finish_reason": None}

    return chat_sync, chat_stream

# -------------------------
# 自动续写工具
# -------------------------
def _find_overlap_suffix_prefix(a: str, b: str, max_overlap: int = 200) -> int:
    if not a or not b:
        return 0
    m = min(max_overlap, len(a), len(b))
    for k in range(m, 0, -1):
        if a[-k:] == b[:k]:
            return k
    return 0

def auto_resume_streaming_messages(
    chat_stream_fn,
    base_messages: List[Dict[str, str]],
    *,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    top_p: float = DEFAULT_TOP_P,
    resume_instruction: str = "继续从上次中断处续写，严格避免重复已输出内容，保持相同结构与格式。",
    tail_chars: int = 2000,
    max_rounds: int = 3
) -> Generator[str, None, None]:
    global_buf = ""
    round_idx = 0

    while True:
        messages = list(base_messages)
        if round_idx > 0:
            tail = global_buf[-tail_chars:]
            messages.append({"role": "assistant", "content": tail})
            messages.append({"role": "user", "content": resume_instruction})

        pass_buf = ""
        last_len = 0
        finish_reason_final: Optional[str] = None

        for chunk in chat_stream_fn(messages, max_tokens=max_tokens, temperature=temperature, top_p=top_p):
            piece = chunk.get("content", "") or ""
            if piece:
                pass_buf += piece
                addition = pass_buf[last_len:]
                last_len = len(pass_buf)
                ov = _find_overlap_suffix_prefix(global_buf, addition, max_overlap=200)
                to_append = addition[ov:]
                if to_append:
                    global_buf += to_append
                    yield global_buf

            fr = chunk.get("finish_reason", None)
            if fr is not None:
                finish_reason_final = fr

        if finish_reason_final != "length":
            break

        round_idx += 1
        if round_idx >= max_rounds:
            break

def auto_resume_stream_text(
    chat_stream_fn,
    system: str,
    user_prompt: str,
    *,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
    top_p: float = DEFAULT_TOP_P,
    resume_instruction: str = "继续从上次中断处续写，严格避免重复已输出内容，保持相同结构与格式。",
    tail_chars: int = 2000,
    max_rounds: int = 3
) -> Generator[str, None, None]:
    base_messages = []
    if system:
        base_messages.append({"role": "system", "content": system})
    base_messages.append({"role": "user", "content": user_prompt})
    for buf in auto_resume_streaming_messages(
        chat_stream_fn,
        base_messages,
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        resume_instruction=resume_instruction,
        tail_chars=tail_chars,
        max_rounds=max_rounds
    ):
        yield buf

# -------------------------
# Prompts
# -------------------------
SYNOPSIS_PROMPT = """你是资深短剧梗概策划师。请基于"类型"和"用户提供的初始梗概（若有）"，生成5~7句简洁、抓人的中文剧情梗概：
- 要求包含主角目标、主要矛盾、两个以上潜在反转的伏笔、以及结尾的情感或剧情勾子；
- 用自然段输出，无需标题或多余前缀。
输入：
- 类型：{genre}
- 初始梗概（可选）：{user_synopsis}
- 前文记忆（参考，避免冲突）：{front_memory}
输出：直接给出5~7句梗概文本。
"""

SYNOPSIS_EDIT_PROMPT = """你是资深短剧梗概修订师。请在尽量保留原梗概优点和叙事骨架的前提下，依据用户新增/修改要求给出一版改写后的梗概（4~6句，直出正文）：
- 若用户新要求与原梗概冲突，以用户新要求为准；
- 语言凝练、情节清晰，留下2处以上反转伏笔与收尾勾子。
原梗概：
{orig}
用户新增/修改要求：
{req}
前文记忆（参考，避免冲突）：
{front_memory}
输出：给出改写后的梗概正文（5~6句），不要加任何标题或说明。
"""

PLOT_PLANNER_PROMPT = """你是资深短剧大纲策划师。根据"类型"与"梗概"，自动确定适合的总集数（必须9~11集），并给出逐集大纲与场景任务。
输入：
- 类型：{genre}
- 梗概：{synopsis}
要求：
- 绝对服从梗概中明确的世界观、人物关系与设定；不得擅自改写梗概既定信息。
- 自动决定合适的集数（8~10集，每集必须都有主题Theme与4~5个场景任务Scenes）。
- 参考前文记忆，避免冲突（若无则忽略）。
- 每一集至少有2个反转，整体跌宕起伏且合理。
- 每集结尾必须有勾子（Cliff）。
- 结构完整（开端-发展-高潮-结局），不能草草收尾。
- 严格按下方格式输出。
前文记忆（参考）： 
{front_memory}
输出格式严格如下：
=== Episode 1 ===
Theme: ...
Scenes:
- S1: ...
- S2: ...
- S3: ...
- S4: ...
- S5: ...
Cliff: ...
# 本集对记忆的贡献
- ...
=== Episode 2 ===
Theme: ...
Scenes:
- S1: ...
- S2: ...
- S3: ...
- S4: ...
Cliff: ...
# 本集对记忆的贡献
- ...
（按以上格式继续，直至最后一集）
"""

SCENE_WRITER_PROMPT = """你是剧本作家。根据给定的主题与场景任务，创作本集完整剧本（含场景标题、人物台词、舞台指示），只输出剧本文本（不要附加说明/摘要/注释）。
约束：
- 结构：按 SCENE 1、SCENE 2 ... 明确分段。
- 每个场景人物对话10到20轮左右，可以有人物心理独白，人物行动与台词相符合。
- 角色说话标记清晰；舞台指示用括号标注。
- 风格：{tone}
- 只输出本集剧本文字。
- 熟读前文记忆，不要与前文矛盾，并为后文埋下伏笔。
参考前文记忆（避免冲突）：
{front_memory}
本集主题：
{theme}
场景任务：
{scene_plan}
"""

CRITIC_PROMPT = """你是严格的短剧剧本编辑，请针对以下剧本和前文记忆提出可执行的修订建议：
- 至少 8 条，每条格式：问题 -- 建议（具体可修改之处）。
- 涵盖节奏、冲突、人物设定、台词张力、场景转换、情节反转、情感勾子等维度。
- 输出每条一行，格式：修订 -- 改善建议（具体到句/段/场景）。
前文记忆： 
{front_memory}
剧本（待评）： 
{scene_text}
"""

CONTINUITY_PROMPT = """你是短剧剧本一致性检查员。请基于下列"全局状态 + 前文记忆"来核对剧本：
- 找出前后文矛盾、时间线错误、人物设定不一致、重要细节缺失或错误等。
- 每条一行，格式：问题 -- 修正建议（具体到句/段/场景）。
全局状态（JSON）：
{global_state}
前文记忆（文本）：
{front_memory}
剧本（待查）：
{scene_text}
"""

REVISION_PROMPT = """你是剧本总编辑。请严格根据"编辑意见"和"一致性意见"对剧本进行修订：
- 在不改变核心走向的前提下，落实所有必要修改。
- 仅输出"修订后的完整剧本文本"，不要输出任何说明、列表或元信息。
评论家意见：
{critic}
连续性意见：
{continuity}
原剧本：
{original}
"""

MEMORY_PROMPT = """你是一个严格的前文内容总结记忆大师。请从下列剧本文本里提炼记忆摘要，便于跨集延续：
- 尽量简洁，提炼出情节、人物关系、关键道具以及会影响后续走向的信息。
剧本文本：
{episode_text}
"""

# -------------------------
# 解析大纲输出为 episodes + 完整性检测
# -------------------------
def parse_outline_to_episodes(planner_out: str) -> List[Dict[str, Any]]:
    lines = split_nonempty_lines(planner_out)
    episodes = []
    cur = None
    for line in lines:
        m = re.match(r'^\s*===\s*Episode\s*(\d+)\s*===\s*$', line, flags=re.I)
        if m:
            if cur:
                episodes.append(cur)
            cur = {"ep": int(m.group(1)), "theme": "", "scenes": [], "raw": []}
            continue
        if cur is None:
            continue
        cur["raw"].append(line)
        if re.match(r'^\s*Theme\s*:', line, flags=re.I):
            cur["theme"] = line.split(":", 1)[1].strip()
        elif re.match(r'^\s*(?:-\s*)?(?:S)?\d+\s*:', line):
            cur["scenes"].append(re.sub(r'^\s*-\s*', '', line).strip())
        elif re.match(r'^\s*\d+\.\s', line):
            cur["scenes"].append(line.strip())
    if cur:
        episodes.append(cur)
    return episodes

def need_resume_outline(text: str) -> bool:
    eps = parse_outline_to_episodes(text or "")
    if not eps:
        return True
    if len(eps) < 8:
        return True
    last_raw = "\n".join(eps[-1].get("raw", []))
    if "Cliff:" not in last_raw:
        return True
    if not re.search(r'(?:#\s*)?本集对记忆的贡献', last_raw):
        return True
    return False

# -------------------------
# 流式：梗概生成与修订
# -------------------------
def generate_synopsis_stream(genre: str, user_synopsis: str) -> Generator[str, None, None]:
    _, chat_stream = ChatLLM()
    front_memory = get_front_memory()
    prompt = SYNOPSIS_PROMPT.format(genre=genre, user_synopsis=(user_synopsis or "（无）"), front_memory=front_memory)
    for buf in auto_resume_stream_text(
        chat_stream,
        system="梗概生成器",
        user_prompt=prompt,
        max_tokens=1200,
        temperature=0.68,
        top_p=0.95,
        resume_instruction="继续完整输出梗概，不要重复已写内容。若已完成，请停止。",
        tail_chars=1200,
        max_rounds=2
    ):
        yield buf

def refine_synopsis_stream(current_synopsis: str, instructions: str) -> Generator[str, None, None]:
    _, chat_stream = ChatLLM()
    front_memory = get_front_memory()
    prompt = SYNOPSIS_EDIT_PROMPT.format(orig=current_synopsis or "（当前梗概为空）", req=instructions or "（无）", front_memory=front_memory)
    for buf in auto_resume_stream_text(
        chat_stream,
        system="梗概修订器",
        user_prompt=prompt,
        max_tokens=1200,
        temperature=0.6,
        top_p=0.9,
        resume_instruction="若未写完4~6句，请继续；若已完成，请停止。",
        tail_chars=1000,
        max_rounds=2
    ):
        yield buf

# -------------------------
# 流式：仅基于“当前梗概”生成跨集大纲
# -------------------------
def generate_outline_only_stream(genre: str, synopsis_text: str):
    _, chat_stream = ChatLLM()
    LAST_OUTLINE["genre"] = genre
    syn_final = (synopsis_text or "").strip()
    if not syn_final:
        err = "【错误】当前梗概为空，请先在“梗概”页签生成或粘贴梗概，并点击【保存当前梗概】。"
        yield ("", "", err)
        return
    LAST_OUTLINE["synopsis"] = syn_final

    front_memory = get_front_memory()
    planner_prompt = PLOT_PLANNER_PROMPT.format(genre=genre, synopsis=syn_final, front_memory=front_memory)
    outline_buf = ""

    for buf in auto_resume_stream_text(
        chat_stream,
        system="大纲策划师",
        user_prompt=planner_prompt,
        max_tokens=6500,
        temperature=0.2,
        top_p=0.9,
        resume_instruction="继续从中断处按相同格式续写，直至完整收尾（总集数8~10集，每集含Theme/Scenes/Cliff与'# 本集对记忆的贡献'），不要重复任何已输出内容。",
        tail_chars=3000,
        max_rounds=3
    ):
        outline_buf = buf
        LAST_OUTLINE["text"] = outline_buf
        disc_live = "【流程】基于当前梗概 -> 大纲\n"
        disc_live += "【当前梗概】\n" + syn_final + "\n\n"
        disc_live += "【大纲策划师】\n" + outline_buf
        yield (syn_final, outline_buf, disc_live)

    attempts = 0
    while need_resume_outline(outline_buf) and attempts < 3:
        attempts += 1
        tail = outline_buf[-3000:]
        base_messages = [
            {"role": "system", "content": "大纲策划师"},
            {"role": "user", "content": planner_prompt},
            {"role": "assistant", "content": tail},
            {"role": "user", "content": "继续输出剩余集数与缺失段落，严格沿用相同格式，不要重复。"}
        ]

        round_last = ""
        _, chat_stream = ChatLLM()
        for buf in auto_resume_streaming_messages(
            chat_stream,
            base_messages,
            max_tokens=4500,
            temperature=0.2,
            top_p=0.9,
            resume_instruction="继续，不要重复，直到完整收尾。",
            tail_chars=3000,
            max_rounds=2
        ):
            addition = buf[len(round_last):]
            round_last = buf
            if not addition:
                continue
            ov = _find_overlap_suffix_prefix(outline_buf, addition, max_overlap=2000)
            outline_buf += addition[ov:]
            LAST_OUTLINE["text"] = outline_buf
            disc_live = "【流程】基于当前梗概 -> 大纲\n"
            disc_live += "【当前梗概】\n" + syn_final + "\n\n"
            disc_live += "【大纲策划师（补全）】\n" + outline_buf
            yield (syn_final, outline_buf, disc_live)

        if not need_resume_outline(outline_buf):
            break

    eps = parse_outline_to_episodes(outline_buf)
    if not eps or len(eps) < 8:
        disc = "【错误】解析大纲失败或集数不足：请调整输入后重试。"
        last_disc = "【当前梗概】\n" + syn_final + "\n\n" + "【大纲策划师】\n" + outline_buf + "\n\n" + disc
        yield (syn_final, outline_buf, last_disc)
        return

    LAST_OUTLINE["episodes"] = eps
    LAST_OUTLINE["total_eps"] = len(eps)
    LAST_OUTLINE["text"] = outline_buf

    disc = f"【完成】大纲解析成功：共 {len(eps)} 集。"
    disc += " 每集场景任务数：" + ", ".join([str(len(e.get('scenes', []))) for e in eps[:10]]) + ("..." if len(eps) > 10 else "")
    final_disc = "【当前梗概】\n" + syn_final + "\n\n" + "【大纲策划师】\n" + outline_buf + "\n\n" + disc
    yield (syn_final, outline_buf, final_disc)

# -------------------------
# 核心子流程（作家/评论家/连续性/修订/记忆）
# -------------------------
def writer_stream(chat_stream, theme: str, scene_plan: str, front_memory: str, tone: str = "戏剧性") -> Generator[str, None, None]:
    prompt = SCENE_WRITER_PROMPT.format(theme=theme, scene_plan=scene_plan, front_memory=front_memory, tone=tone)
    resume_tip = "继续从中断处续写后续场景/台词，保持 SCENE 分段格式与风格一致，严禁重复已输出内容。"
    for buf in auto_resume_stream_text(
        chat_stream,
        system="剧本作家",
        user_prompt=prompt,
        max_tokens=3500,
        temperature=0.7,
        top_p=0.95,
        resume_instruction=resume_tip,
        tail_chars=3000,
        max_rounds=4
    ):
        yield buf

def critic_stream(chat_stream, script_text: str, front_memory: str) -> Generator[str, None, None]:
    prompt = CRITIC_PROMPT.format(scene_text=script_text, front_memory=front_memory)
    resume_tip = "继续补充剩余修订建议，避免与已输出条目重复；若已完成充分建议，请停止。"
    for buf in auto_resume_stream_text(
        chat_stream,
        system="评论家",
        user_prompt=prompt,
        max_tokens=3500,
        temperature=0.5,
        top_p=0.95,
        resume_instruction=resume_tip,
        tail_chars=2000,
        max_rounds=2
    ):
        yield buf

def continuity_stream(chat_stream, script_text: str, global_state: Dict[str, Any], front_memory: str) -> Generator[str, None, None]:
    gs = json.dumps(global_state, ensure_ascii=False, indent=2)
    prompt = CONTINUITY_PROMPT.format(global_state=gs, scene_text=script_text, front_memory=front_memory)
    resume_tip = "继续列出未覆盖的一致性问题及修正建议，避免重复；若已完成，请停止。"
    for buf in auto_resume_stream_text(
        chat_stream,
        system="连续性检查员",
        user_prompt=prompt,
        max_tokens=3500,
        temperature=0.35,
        top_p=0.9,
        resume_instruction=resume_tip,
        tail_chars=2000,
        max_rounds=2
    ):
        yield buf

def revision_stream(chat_stream, original: str, critic: str, continuity: str) -> Generator[str, None, None]:
    prompt = REVISION_PROMPT.format(original=original, critic=critic, continuity=continuity)
    resume_tip = "继续完整给出修订后的剧本文本，避免重复已输出部分；若已完成，请停止。不得输出任何说明文字。"
    for buf in auto_resume_stream_text(
        chat_stream,
        system="修订者",
        user_prompt=prompt,
        max_tokens=3500,
        temperature=0.45,
        top_p=0.95,
        resume_instruction=resume_tip,
        tail_chars=3000,
        max_rounds=3
    ):
        yield buf

def memory_stream(chat_stream, episode_text: str) -> Generator[str, None, None]:
    prompt = MEMORY_PROMPT.format(episode_text=episode_text)
    resume_tip = "继续补充记忆摘要要点，避免重复；若已简洁完整，请停止。"
    for buf in auto_resume_stream_text(
        chat_stream,
        system="记忆管理员",
        user_prompt=prompt,
        max_tokens=1500,
        temperature=0.3,
        top_p=0.9,
        resume_instruction=resume_tip,
        tail_chars=1200,
        max_rounds=2
    ):
        yield buf

# -------------------------
# 流式：按集生成
# -------------------------
def generate_episode_stream(ep_index: int) -> Generator[Tuple[str, str, str], None, None]:
    if not LAST_OUTLINE.get("episodes"):
        yield ("[错误] 未找到大纲，请先到“大纲生成”页签基于梗概生成跨集大纲。", "", "")
        return
    if ep_index < 1 or ep_index > len(LAST_OUTLINE["episodes"]):
        yield (f"[错误] 请求的集数 {ep_index} 超出范围（1~{len(LAST_OUTLINE['episodes'])}）。", "", "")
        return

    _, chat_stream = ChatLLM()
    ep_meta = LAST_OUTLINE["episodes"][ep_index - 1]

    if ep_meta.get("scenes"):
        scene_plan = "\n".join(f"- {s}" for s in ep_meta["scenes"])
    else:
        raw = "\n".join(ep_meta.get("raw", [])) or "S1: 开场冲突；S2: 关系推进；S3: 转折；S4: 高潮；S5: 悬念收尾"
        scene_plan = "\n".join(f"- {line}" for line in split_nonempty_lines(raw)[:6])

    front_memory = get_front_memory()
    discussion = f"【智能体】开始生成 第 {ep_index} 集\nTheme: {ep_meta.get('theme','')}\n[任务]\n{scene_plan}\n"

    draft_buf = ""
    for buf in writer_stream(chat_stream, ep_meta.get("theme", ""), scene_plan, front_memory, tone="戏剧性"):
        draft_buf = buf
        disc_live = discussion + "\n[剧本作家-流]\n" + draft_buf
        combined_preview = "\n\n".join([f"=== Ep {s['ep']} ===\n{s['script']}" for s in LAST_OUTLINE.get('scripts', [])])
        yield (disc_live, "", combined_preview)

    discussion += "\n【剧本作家】初稿完成。"

    critic_buf = ""
    for buf in critic_stream(chat_stream, draft_buf, front_memory):
        critic_buf = buf
        disc_live = discussion + "\n[评论家-流]\n" + critic_buf
        yield (disc_live, "", "\n\n".join([f"=== Ep {s['ep']} ===\n{s['script']}" for s in LAST_OUTLINE.get('scripts', [])]))
    if not critic_buf.strip():
        critic_buf = "无 -- 请补充对节奏、冲突、人物弧线、台词张力、信息埋设等方面的改进建议。"
    discussion += "\n【评论家】意见生成完成。"

    global_state = {
        "outline_genre": LAST_OUTLINE.get("genre"),
        "outline_synopsis": LAST_OUTLINE.get("synopsis"),
        "episodes_count": LAST_OUTLINE.get("total_eps"),
        "prior_scripts": [{"ep": s["ep"], "len": len(s["script"])} for s in LAST_OUTLINE.get("scripts", [])]
    }
    continuity_buf = ""
    for buf in continuity_stream(chat_stream, draft_buf, global_state, front_memory):
        continuity_buf = buf
        disc_live = discussion + "\n[连续性-流]\n" + continuity_buf
        yield (disc_live, "", "\n\n".join([f"=== Ep {s['ep']} ===\n{s['script']}" for s in LAST_OUTLINE.get('scripts', [])]))
    if not continuity_buf.strip():
        continuity_buf = "无 -- 请补充与设定/时间线/人物一致性相关的核对与修正建议。"
    discussion += "\n【连续性检查员】一致性检查完成。"

    revised_buf = ""
    for buf in revision_stream(chat_stream, draft_buf, critic_buf, continuity_buf):
        revised_buf = buf
        disc_live = discussion + "\n[修订者-流]\n" + revised_buf
        combined_preview = []
        for s in LAST_OUTLINE.get('scripts', []):
            combined_preview.append(f"=== Ep {s['ep']} ===\n{s['script']}")
        combined_preview.append(f"=== Ep {ep_index} (修订中) ===\n" + revised_buf)
        yield (disc_live, revised_buf, "\n\n".join(combined_preview))

    discussion += "\n【修订者】修订完成，正在保存与记忆归档..."

    mem_buf = ""
    for buf in memory_stream(chat_stream, revised_buf):
        mem_buf = buf
        disc_live = discussion + "\n[记忆管理员-流]\n" + mem_buf
        combined_preview = "\n\n".join([f"=== Ep {s['ep']} ===\n{s['script']}" for s in LAST_OUTLINE.get('scripts', [])])
        combined_preview += ("\n\n=== Ep {ep} (修订完成) ===\n" + revised_buf).format(ep=ep_index)
        yield (disc_live, revised_buf, combined_preview)

    mem_final = (mem_buf or "").strip() or "（未生成显著记忆片段）"
    LAST_OUTLINE.setdefault("memories", []).append(mem_final)

    replaced = False
    for i, s in enumerate(LAST_OUTLINE.get("scripts", [])):
        if s.get("ep") == ep_index:
            LAST_OUTLINE["scripts"][i] = {"ep": ep_index, "script": revised_buf, "memory": mem_final}
            replaced = True
            break
    if not replaced:
        LAST_OUTLINE.setdefault("scripts", []).append({"ep": ep_index, "script": revised_buf, "memory": mem_final})

    combined_final = "\n\n".join([f"=== Ep {s['ep']} ===\n{s['script']}" for s in sorted(LAST_OUTLINE.get('scripts', []), key=lambda x: x['ep'])])
    discussion += "\n【记忆管理员】本集保存完毕。"
    yield (discussion, revised_buf, combined_final)

# -------------------------
# 流式：修订现有剧集
# -------------------------
def revise_episode_stream(ep_index: int, revision_instructions: str) -> Generator[Tuple[str, str, str], None, None]:
    if ep_index < 1:
        yield ("[错误] 无效的集序号。", "", "")
        return

    existing = get_script_by_ep(ep_index)
    if not existing:
        yield ("[错误] 未找到要修订的剧集脚本。", "", "")
        return

    _, chat_stream = ChatLLM()
    front_memory = get_front_memory()
    discussion = f"【智能体】开始修订 第 {ep_index} 集\n用户指令：{revision_instructions or '（无特别指令）'}\n"

    critic_buf = ""
    for buf in critic_stream(chat_stream, existing, front_memory):
        critic_buf = buf
        disc_live = discussion + "\n[评论家-流]\n" + critic_buf
        yield (disc_live, "", "\n\n".join([f"=== Ep {s['ep']} ===\n{s['script']}" for s in LAST_OUTLINE.get('scripts', [])]))
    if not critic_buf.strip():
        critic_buf = "无 -- 请补充对节奏、冲突、人物弧线、台词张力、信息埋设等方面的改进建议。"
    critic_buf = f"用户修订指令优先落实：{revision_instructions or '（无）'}\n\n" + critic_buf
    discussion += "\n【评论家】意见生成完成。"

    global_state = {
        "outline_genre": LAST_OUTLINE.get("genre"),
        "outline_synopsis": LAST_OUTLINE.get("synopsis"),
        "episodes_count": LAST_OUTLINE.get("total_eps"),
        "prior_scripts": [{"ep": s["ep"], "len": len(s["script"])} for s in LAST_OUTLINE.get("scripts", [])]
    }
    continuity_buf = ""
    for buf in continuity_stream(chat_stream, existing, global_state, front_memory):
        continuity_buf = buf
        disc_live = discussion + "\n[连续性-流]\n" + continuity_buf
        yield (disc_live, "", "\n\n".join([f"=== Ep {s['ep']} ===\n{s['script']}" for s in LAST_OUTLINE.get('scripts', [])]))
    if not continuity_buf.strip():
        continuity_buf = "无 -- 请补充与设定/时间线/人物一致性相关的核对与修正建议。"
    discussion += "\n【连续性检查员】一致性检查完成。"

    revised_buf = ""
    for buf in revision_stream(chat_stream, existing, critic_buf, continuity_buf):
        revised_buf = buf
        disc_live = discussion + "\n[修订者-流]\n" + revised_buf
        combined_preview = []
        for s in LAST_OUTLINE.get('scripts', []):
            if s['ep'] == ep_index:
                combined_preview.append(f"=== Ep {s['ep']} (修订中) ===\n{revised_buf}")
            else:
                combined_preview.append(f"=== Ep {s['ep']} ===\n{s['script']}")
        yield (disc_live, revised_buf, "\n\n".join(combined_preview))

    discussion += "\n【修订者】修订完成，正在保存与记忆归档..."

    mem_buf = ""
    for buf in memory_stream(chat_stream, revised_buf):
        mem_buf = buf
        disc_live = discussion + "\n[记忆管理员-流]\n" + mem_buf
        yield (disc_live, revised_buf, "\n\n".join([f"=== Ep {s['ep']} ===\n{s['script']}" for s in LAST_OUTLINE.get('scripts', [])]))

    mem_final = (mem_buf or "").strip() or "（未生成显著记忆片段）"
    updated = False
    for i, s in enumerate(LAST_OUTLINE.get("scripts", [])):
        if s.get("ep") == ep_index:
            LAST_OUTLINE["scripts"][i]["script"] = revised_buf
            LAST_OUTLINE["scripts"][i]["memory"] = mem_final
            updated = True
            break
    if not updated:
        LAST_OUTLINE.setdefault("scripts", []).append({"ep": ep_index, "script": revised_buf, "memory": mem_final})
    LAST_OUTLINE.setdefault("memories", []).append(mem_final)

    combined_final = "\n\n".join([f"=== Ep {s['ep']} ===\n{s['script']}" for s in sorted(LAST_OUTLINE.get('scripts', []), key=lambda x: x['ep'])])
    discussion += "\n【记忆管理员】修订保存完毕。"
    yield (discussion, revised_buf, combined_final)

# -------------------------
# 导出功能
# -------------------------
def export_episode_file_original(idx: Any) -> Optional[str]:
    try:
        ep = int(idx)
    except Exception:
        return None
    script = get_script_by_ep(ep)
    if not script:
        return None
    outline_text = (LAST_OUTLINE.get("text") or "").strip()
    content_parts = []
    content_parts.append(f"类型: {LAST_OUTLINE.get('genre','')}")
    if LAST_OUTLINE.get("synopsis", "").strip():
        content_parts.append("梗概：\n" + LAST_OUTLINE["synopsis"].strip())
    if outline_text:
        content_parts.append("=" * 40)
        content_parts.append("【全局大纲】\n" + outline_text)
    content_parts.append("=" * 40)
    content_parts.append(f"=== Episode {ep} ===\n{script}\n")
    content = "\n".join(content_parts)
    return write_text_tempfile(content, filename=f"episode_{ep}.txt")

def export_all_file_original() -> Optional[str]:
    if not LAST_OUTLINE.get("scripts"):
        return None
    content = combine_all_scripts_text()
    return write_text_tempfile(content, filename="all_episodes.txt")

def export_episode_file_with_token(idx, token=None) -> Optional[str]:
    try:
        ep = int(idx)
    except Exception:
        return None
    u = get_user_by_token(token or "")
    if u:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM scripts WHERE user_id = ? AND ep = ? ORDER BY created_at DESC LIMIT 1", (u["user_id"], ep))
        row = cur.fetchone()
        conn.close()
        if row:
            content_parts = []
            content_parts.append(f"类型: {LAST_OUTLINE.get('genre','')}")
            if LAST_OUTLINE.get("synopsis", "").strip():
                content_parts.append("梗概：\n" + LAST_OUTLINE["synopsis"].strip())
            outline_text = (LAST_OUTLINE.get("text") or "").strip()
            if outline_text:
                content_parts.append("=" * 40)
                content_parts.append("【全局大纲】\n" + outline_text)
            content_parts.append("=" * 40)
            content_parts.append(f"=== Episode {ep} (user saved) ===\n{row['script']}\n")
            return write_text_tempfile("\n".join(content_parts), filename=f"episode_{ep}.txt")
    return export_episode_file_original(ep)

def export_all_file_with_token(token=None) -> Optional[str]:
    u = get_user_by_token(token or "")
    if u:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM scripts WHERE user_id = ? ORDER BY created_at DESC LIMIT 200", (u["user_id"],))
        rows = cur.fetchall()
        conn.close()
        if rows:
            parts = []
            parts.append(f"用户: {u['username']}")
            if LAST_OUTLINE.get("synopsis", "").strip():
                parts.append("梗概：\n" + LAST_OUTLINE["synopsis"].strip())
            outline_text = (LAST_OUTLINE.get("text") or "").strip()
            if outline_text:
                parts.append("=" * 40)
                parts.append("【全局大纲】\n" + outline_text)
            parts.append("=" * 40)
            for r in rows:
                parts.append(f"=== Ep {r['ep']} | id:{r['id']} | {r['created_at']} ===\n{r['script']}\n")
                parts.append("-" * 40)
            return write_text_tempfile("\n".join(parts), filename=f"all_episodes_user_{u['username']}.txt")
    return export_all_file_original()

# -------------------------
# 主 UI
# -------------------------
def build_main_ui():
    custom_css = """
        #left_history { background: #fafafa; padding: 0.6rem; border-right: 1px solid #eee; height: 80vh; overflow: auto; }
        .gr-button { min-height: 36px; }
        .hist-item { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
        #mini_admin_link { position: fixed; bottom: 8px; right: 10px; font-size: 12px; opacity: .5; }
        #mini_admin_link a { color: #999; text-decoration: none; }
        #mini_admin_link a:hover { color: #666; text-decoration: underline; }
    """
    with gr.Blocks(title="多智能体短剧生成器", css=custom_css) as demo:
        demo.load(lambda: None)

        # 右下角极小“管理”链接 -> 独立路由 /admin
        gr.HTML('<div id="mini_admin_link"><a href="/admin/" target="_blank" title="后台（需Token）">管理</a></div>')

        # 顶部：标题 + 右上按钮 + 隐藏 token 与状态
        with gr.Row():
            with gr.Column(scale=8):
                gr.Markdown("## 多智能体短剧生成器")
            with gr.Column(scale=4):
                with gr.Row():
                    auth_btn = gr.Button("👤 登录 / 注册", variant="primary")
                user_token = gr.Textbox(label="会话令牌", visible=False)
                auth_visible = gr.State(False)

        # 折叠：认证面板（默认隐藏）
        with gr.Column(visible=False) as auth_box:
            with gr.Row():
                with gr.Column(scale=1):
                    reg_username = gr.Textbox(label="用户名（注册）")
                    reg_password = gr.Textbox(label="密码（注册）", type="password")
                    btn_register = gr.Button("注册")
                    reg_msg = gr.Textbox(label="注册提示", interactive=False)
                with gr.Column(scale=1):
                    login_username = gr.Textbox(label="用户名（登录）")
                    login_password = gr.Textbox(label="密码（登录）", type="password")
                    btn_login = gr.Button("登录")
                    login_msg = gr.Textbox(label="登录提示", interactive=False)

        with gr.Row():
            # 左侧：历史记录 直观列表 + 搜索 + 详情/下载
            with gr.Column(scale=4, min_width=360, elem_id="left_history"):
                gr.Markdown("### 我的历史记录")
                hist_search = gr.Textbox(label="搜索（标题或内容片段）", placeholder="输入关键字后回车或点击刷新")
                hist_limit = gr.Number(label="显示条数", value=50, precision=0)
                btn_refresh_hist = gr.Button("刷新")
                # 用 Radio 显示列表，直接排列，点击触发详情
                history_radio = gr.Radio(label="记录列表", choices=[], interactive=True)
                with gr.Row():
                    btn_export_sel = gr.Button("下载选中记录", variant="secondary")
                script_preview = gr.Textbox(label="剧本片段预览", lines=15, interactive=False)
                script_meta = gr.Textbox(label="剧本信息（标题 | 创建时间）", lines=2, interactive=False)
                dl_selected = gr.File(label="下载（选中剧本txt）", interactive=False)
            # 右侧：创作区
            with gr.Column(scale=8, min_width=700):
                with gr.Tab("步骤1: 生成/修订梗概"):
                    with gr.Row():
                        with gr.Column(scale=1):
                            genre = gr.Dropdown(
                                label="类型",
                                choices=["商战","邻家","逆后宫","朋友变恋人","超能力","代理新娘","团宠","因果报应","自我成长","萌宝","友谊","重生","年龄差距","心意难宣","伪骨科","爱恨交织","时间旅行","魂穿","假怀孕","道德与伦理","冒险","相亲","错认身份","校园恋人","隐藏身份","外遇","赎回","复仇","秘密","为时已晚","离婚后的爱情","爱情三角关系","命中注定的爱人","失散子女","天选之人","合约情人","扮猪吃虎","办公室恋情","禁忌","从敌人到恋人","初恋","破镜重圆","闪婚","先婚后爱","假关系","怀孕","多重身份","后宫"],
                                value="商战"
                            )
                            synopsis_seed = gr.Textbox(label="初始梗概（可选）", lines=3, placeholder="可留空；系统将自动生成梗概")
                            btn_gen_syn = gr.Button("生成梗概")
                            gr.Markdown("---")
                            syn_rev_in = gr.Textbox(label="梗概修订指令", lines=3, placeholder="例如：把背景改到北方小城；女主更主动；加一处职场反转。")
                            btn_refine_syn = gr.Button("根据指令改写梗概")
                            btn_save_syn = gr.Button("保存当前梗概（用于后续大纲生成）")
                        with gr.Column(scale=1):
                            out_synopsis = gr.Textbox(label="梗概（可手动编辑）", lines=12)
                            out_syn_disc = gr.Textbox(label="梗概阶段输出", lines=20)

                    def run_syn(g, syn_seed):
                        syn_final = ""
                        for syn_buf in generate_synopsis_stream(g, syn_seed):
                            syn_final = syn_buf
                            yield syn_final, "【梗概生成器】正在生成梗概...\n" + syn_final
                        LAST_OUTLINE["genre"] = g
                        LAST_OUTLINE["synopsis"] = (syn_final or syn_seed or "").strip()

                    btn_gen_syn.click(fn=run_syn, inputs=[genre, synopsis_seed], outputs=[out_synopsis, out_syn_disc])

                    def refine_syn(syn_text, rev_in):
                        syn_final = ""
                        for buf in refine_synopsis_stream(syn_text or "", rev_in or ""):
                            syn_final = buf
                            yield syn_final, "【梗概修订器】正在改写梗概...\n" + syn_final
                        LAST_OUTLINE["synopsis"] = (syn_final or syn_text or "").strip()

                    btn_refine_syn.click(fn=refine_syn, inputs=[out_synopsis, syn_rev_in], outputs=[out_synopsis, out_syn_disc])

                    def save_syn(syn_text, g):
                        syn_text = (syn_text or "").strip()
                        LAST_OUTLINE["genre"] = g
                        LAST_OUTLINE["synopsis"] = syn_text
                        msg = "【保存成功】已保存为梗概。下一步请切换到“步骤2: 生成大纲”。" if syn_text else "【提示】梗概为空，尚未保存有效内容。"
                        return syn_text, msg

                    btn_save_syn.click(fn=save_syn, inputs=[out_synopsis, genre], outputs=[out_synopsis, out_syn_disc])

                with gr.Tab("步骤2: 生成大纲（需先保存梗概）"):
                    with gr.Row():
                        with gr.Column(scale=1):
                            btn_plan_from_syn = gr.Button("根据已保存的梗概生成大纲")
                        with gr.Column(scale=1):
                            out_outline = gr.Textbox(label="大纲", lines=22)
                            out_disc = gr.Textbox(label="大纲阶段讨论/输出", lines=20)
                            out_synopsis_ro = gr.Textbox(label="当前梗概（只读）", value=lambda: LAST_OUTLINE.get("synopsis",""), lines=8)

                    def plan_from_current_syn(g):
                        current_syn = LAST_OUTLINE.get("synopsis", "").strip()
                        for syn, outline, disc in generate_outline_only_stream(g, current_syn):
                            yield outline, disc, syn

                    btn_plan_from_syn.click(fn=plan_from_current_syn, inputs=[genre], outputs=[out_outline, out_disc, out_synopsis_ro])

                with gr.Tab("步骤3: 生成本集剧本"):
                    with gr.Row():
                        with gr.Column(scale=1):
                            ep_index = gr.Number(label="集序号", value=1, precision=0)
                            gen_ep = gr.Button("生成本集剧本")
                            dl_ep_btn = gr.Button("下载本集剧本")
                            dl_all_btn = gr.Button("下载全部剧本")
                        with gr.Column(scale=1):
                            out_disc2 = gr.Textbox(label="智能体讨论", lines=18)
                            out_script2 = gr.Textbox(label="本集最终剧本", lines=20)
                            combined_script = gr.Textbox(label="已保存的全部剧集剧本（合并预览）", lines=20)
                            dl_ep_file = gr.File(label="下载本集剧本（txt）", interactive=False)
                            dl_all_file = gr.File(label="下载全部剧本（txt）", interactive=False)

                with gr.Tab("步骤4: 依据指令修订本集"):
                    with gr.Row():
                        with gr.Column(scale=1):
                            ep_index_r = gr.Number(label="集序号", value=1, precision=0)
                            revision_in = gr.Textbox(label="修订指令（例如：加强冲突；压缩中段；人物X更主动）", lines=3)
                            apply_rev = gr.Button("提交修订并保存")
                            dl_ep_btn_r = gr.Button("下载本集剧本")
                            dl_all_btn_r = gr.Button("下载全部剧本")
                        with gr.Column(scale=1):
                            out_disc_rev = gr.Textbox(label="智能体讨论", lines=18)
                            out_script_rev = gr.Textbox(label="修订后的本集剧本", lines=20)
                            combined_script_rev = gr.Textbox(label="已保存的全部剧集剧本（合并预览）", lines=20)
                            dl_ep_file_r = gr.File(label="下载本集剧本（txt）", interactive=False)
                            dl_all_file_r = gr.File(label="下载全部剧本（txt）", interactive=False)

        # -----------------------
        # 回调逻辑
        # -----------------------
        # 认证折叠
        def toggle_auth_panel(cur: bool):
            new_v = not cur
            return new_v, gr.update(visible=new_v)
        auth_btn.click(fn=toggle_auth_panel, inputs=[auth_visible], outputs=[auth_visible, auth_box])

        # 注册
        def handle_register(u, p):
            if not u or not p:
                return "用户名与密码不能为空", ""
            ok, msg = register_user_db(u.strip(), p)
            return msg, ""
        btn_register.click(fn=handle_register, inputs=[reg_username, reg_password], outputs=[reg_msg, user_token])

        # 登录
        def handle_login(u, p):
            if not u or not p:
                return "用户名/密码不能为空", ""
            ok, token_or_msg = login_user_db(u.strip(), p)
            if not ok:
                return token_or_msg, ""
            return "登录成功", token_or_msg
        btn_login.click(fn=handle_login, inputs=[login_username, login_password], outputs=[login_msg, user_token])

        # 历史：装载 Radio 选项
        def load_history_radio(token: str, search_term: str, limit: int):
            if not token:
                return gr.update(choices=[])
            u = get_user_by_token(token)
            if not u:
                return gr.update(choices=[])
            rows = list_user_scripts(u["user_id"], limit=int(limit or 100))
            st = (search_term or "").strip().lower()
            choices = []
            for r in rows:
                snippet = (r["script"] or "").replace("\n", " ")
                label10 = snippet[:10] if snippet else "(空白片段)"
                if st and (st not in ((r["title"] or "").lower() + " " + snippet.lower())):
                    continue
                # label 中加入 id 与时间，便于辨识
                label = f"[id:{r['id']}] Ep{r['ep']} | {r['created_at']} | {label10}"
                choices.append((label, str(r["id"])))
            return gr.update(choices=choices, value=None)

        btn_refresh_hist.click(fn=load_history_radio, inputs=[user_token, hist_search, hist_limit], outputs=[history_radio])
        hist_search.change(fn=load_history_radio, inputs=[user_token, hist_search, hist_limit], outputs=[history_radio])
        demo.load(fn=load_history_radio, inputs=[user_token, hist_search, hist_limit], outputs=[history_radio])

        # 选中 -> 显示详情 + 下载
        def show_script_detail_by_id(script_id: str, token: str):
            if not script_id:
                return "未选择记录。", "", None
            try:
                sid = int(script_id)
            except Exception:
                return "所选项无效。", "", None
            u = get_user_by_token(token or "")
            if not u:
                return "请先登录以查看详情。", "", None
            r = get_script_by_id_for_user(sid, u["user_id"])
            if not r:
                return "未找到该剧本或无权限。", "", None
            preview = r["script"][:1200] + ("..." if len(r["script"] or "") > 1200 else "")
            meta = f"标题: {r['title'] or ('Ep'+str(r['ep']))} | 创建: {r['created_at']}"
            # 立即提供下载文件
            content = f"标题: {r['title']}\n创建: {r['created_at']}\n\n{r['script']}"
            file_path = write_text_tempfile(content, filename=f"script_{sid}.txt")
            return preview, meta, file_path

        history_radio.change(fn=show_script_detail_by_id, inputs=[history_radio, user_token], outputs=[script_preview, script_meta, dl_selected])

        # “下载选中记录”按钮（与上面联动，冗余提供）
        def export_selected_by_value(script_id: str, token: str):
            if not script_id:
                return None
            try:
                sid = int(script_id)
            except Exception:
                return None
            u = get_user_by_token(token or "")
            if not u:
                return None
            row = get_script_by_id_for_user(sid, u["user_id"])
            if not row:
                return None
            content = f"标题: {row['title']}\n创建: {row['created_at']}\n\n{row['script']}"
            return write_text_tempfile(content, filename=f"script_{sid}.txt")

        btn_export_sel.click(fn=export_selected_by_value, inputs=[history_radio, user_token], outputs=[dl_selected])

        # 生成/修订包装：不再刷新历史在流过程中，结束后刷新
        def gen_ep_wrap(idx, token, limit):
            try:
                idx = int(idx)
            except Exception:
                yield ("[错误] 请提供合法集序号。", "", "",)
                return

            user_row = get_user_by_token(token or "")
            user_id = user_row["user_id"] if user_row else None

            last_output = None
            for disc, script, combined in generate_episode_stream(idx):
                last_output = (disc, script, combined)
                yield disc, script, combined

            if last_output:
                _, final_script, _ = last_output
                if (user_id is not None) and final_script:
                    mem = None
                    for s in LAST_OUTLINE.get("scripts", []):
                        if s.get("ep") == idx:
                            mem = s.get("memory")
                            break
                    try:
                        save_script_db(user_id, idx, final_script, mem or "")
                    except Exception as e:
                        print("保存剧本到 DB 失败：", e)

            # 最终刷新历史
            # 注意：这里不返回到 history_radio，主调方会手动触发刷新
            return

        def apply_rev_wrap(idx, rev_text, token, limit):
            try:
                idx = int(idx)
            except Exception:
                yield ("[错误] 请提供合法集序号。", "", "",)
                return

            user_row = get_user_by_token(token or "")
            user_id = user_row["user_id"] if user_row else None

            last_output = None
            for disc, script, combined in revise_episode_stream(idx, rev_text or ""):
                last_output = (disc, script, combined)
                yield disc, script, combined

            if last_output:
                _, final_script, _ = last_output
                if (user_id is not None) and final_script:
                    mem = None
                    for s in LAST_OUTLINE.get("scripts", []):
                        if s.get("ep") == idx:
                            mem = s.get("memory")
                            break
                    try:
                        save_script_db(user_id, idx, final_script, mem or "")
                    except Exception as e:
                        print("保存修订剧本到 DB 失败：", e)
            return

        gen_ep.click(fn=gen_ep_wrap, inputs=[ep_index, user_token, hist_limit], outputs=[out_disc2, out_script2, combined_script])
        apply_rev.click(fn=apply_rev_wrap, inputs=[ep_index_r, revision_in, user_token, hist_limit], outputs=[out_disc_rev, out_script_rev, combined_script_rev])

        # 下载本集/全部
        dl_ep_btn.click(fn=lambda idx, tok: export_episode_file_with_token(idx, tok), inputs=[ep_index, user_token], outputs=[dl_ep_file])
        dl_all_btn.click(fn=lambda tok: export_all_file_with_token(tok), inputs=[user_token], outputs=[dl_all_file])
        dl_ep_btn_r.click(fn=lambda idx, tok: export_episode_file_with_token(idx, tok), inputs=[ep_index_r, user_token], outputs=[dl_ep_file_r])
        dl_all_btn_r.click(fn=lambda tok: export_all_file_with_token(tok), inputs=[user_token], outputs=[dl_all_file_r])

    return demo

# -------------------------
# 后台 UI
# -------------------------
def build_admin_ui():
    with gr.Blocks(title="后台管理（需 Token）") as admin_app:
        gr.Markdown("### 后台管理")
        with gr.Row():
            access_in = gr.Textbox(label="Access Token", type="password", placeholder="请输入后台访问令牌")
            btn_check = gr.Button("进入后台", variant="primary")
        auth_ok = gr.State(False)

        with gr.Column(visible=False) as admin_panel:
            admin_search = gr.Textbox(label="搜索（用户名或内容片段）")
            admin_limit = gr.Number(label="显示条数", value=200, precision=0)
            admin_refresh = gr.Button("刷新")
            admin_table = gr.Dataframe(
                headers=["脚本ID","用户名","Ep","标题","创建时间","前10字"],
                datatype=["number","str","number","str","str","str"],
                interactive=False,
                value=[]
            )
            admin_export_csv = gr.Button("导出为CSV")
            admin_file = gr.File(label="下载（CSV）", interactive=False)

        # 验证
        def check_token(tok: str):
            ok = bool(tok and tok == ADMIN_ACCESS_CODE)
            print(f"Input token: '{tok}', Expected: '{ADMIN_ACCESS_CODE}', Match: {ok}", flush=True)  # 添加 flush=True
            return ok, gr.update(visible=ok)

        btn_check.click(fn=check_token, inputs=[access_in], outputs=[auth_ok, admin_panel])

        # 加载/导出
        def admin_load(tok: bool, query: str, limit: int):
            if not tok:
                return []
            rows = admin_list_all_scripts(limit=int(limit or 200))
            q = (query or "").strip().lower()
            data = []
            for r in rows:
                snippet = (r["script"] or "").replace("\n", " ")
                if q and (q not in (r["username"] or "").lower() + " " + snippet.lower()):
                    continue
                data.append([r["id"], r["username"], r["ep"], r["title"], r["created_at"], snippet[:10]])
            return data

        admin_refresh.click(fn=admin_load, inputs=[auth_ok, admin_search, admin_limit], outputs=[admin_table])

        def admin_export(tok: bool, query: str, limit: int):
            if not tok:
                return None
            rows = admin_load(True, query, limit)
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["脚本ID","用户名","Ep","标题","创建时间","前10字"])
            for row in rows:
                writer.writerow(row)
            return write_text_tempfile(buf.getvalue(), filename="admin_export.csv")

        admin_export_csv.click(fn=admin_export, inputs=[auth_ok, admin_search, admin_limit], outputs=[admin_file])

    return admin_app

# -------------------------
# 启动
# -------------------------
# 创建 FastAPI 应用
fastapi_app = FastAPI()

# 构建你的 Gradio 应用
main_ui = build_main_ui()
admin_ui = build_admin_ui()

fastapi_app = gr.mount_gradio_app(fastapi_app, admin_ui, path="/admin")
fastapi_app = gr.mount_gradio_app(fastapi_app, main_ui, path="/")


# 启动应用
if __name__ == "__main__":
    uvicorn.run(fastapi_app, host="127.0.0.1", port=7861)
