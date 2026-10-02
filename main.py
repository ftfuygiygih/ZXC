import os, json, hmac, hashlib, asyncio, logging
from aiohttp import web
from telethon import TelegramClient, events
from telethon.sessions import StringSession
from telethon.errors import (
    SessionPasswordNeededError, PhoneCodeInvalidError, PhoneCodeExpiredError,
    PasswordHashInvalidError, FloodWaitError, PhoneNumberInvalidError,
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("forwarder")

API_ID = int(os.environ["API_ID"])
API_HASH = os.environ["API_HASH"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]  # пароль для входа на сайт
PORT = int(os.environ.get("PORT", 10000))
DATA_DIR = os.environ.get("DATA_DIR", ".")
SESSION_FILE = os.path.join(DATA_DIR, "session.txt")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")


def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def write(path, text):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        log.warning("Не удалось сохранить %s: %s", path, e)


cfg = {"source": None, "target": "me", "enabled": False}
try:
    cfg.update(json.loads(read(CONFIG_FILE) or "{}"))
    cfg["enabled"] = False  # после перезапуска всегда выключено
except ValueError:
    pass

client = TelegramClient(StringSession(os.environ.get("SESSION") or read(SESSION_FILE)), API_ID, API_HASH)
login = {"phone": None, "hash": None, "step": "phone"}

# ---------- пересылка ----------
@client.on(events.NewMessage())
async def forwarder(event):
    if not cfg["enabled"] or cfg["source"] is None or event.chat_id != int(cfg["source"]):
        return
    target = "me" if cfg["target"] == "me" else int(cfg["target"])
    try:
        await client.forward_messages(target, event.message)
    except Exception as e:
        log.warning("Пересылка не удалась (%s), пробую копию", e)
        try:
            m = event.message
            if m.media and not getattr(m.media, "webpage", None):
                await client.send_file(target, m.media, caption=m.text or "")
            elif m.text:
                await client.send_message(target, m.text)
        except Exception as e2:
            log.error("Копия не удалась: %s", e2)

# ---------- авторизация сайта ----------
def token():
    return hmac.new(ADMIN_PASSWORD.encode(), b"tg-forwarder", hashlib.sha256).hexdigest()


def authed(request):
    return hmac.compare_digest(request.cookies.get("auth", ""), token())


def guard(handler):
    async def wrapper(request):
        if not authed(request):
            return web.json_response({"error": "auth"}, status=401)
        try:
            return await handler(request)
        except FloodWaitError as e:
            return web.json_response({"error": f"Слишком много попыток, подожди {e.seconds} сек."}, status=400)
        except Exception as e:
            log.exception("API error")
            return web.json_response({"error": str(e)}, status=400)
    return wrapper


def err(text):
    return web.json_response({"error": text}, status=400)

# ---------- API ----------
async def api_login(request):
    data = await request.json()
    if not hmac.compare_digest(data.get("password", ""), ADMIN_PASSWORD):
        await asyncio.sleep(1.5)
        return err("Неверный пароль")
    resp = web.json_response({"ok": True})
    resp.set_cookie("auth", token(), httponly=True, samesite="Lax", max_age=30 * 86400,
                    secure=request.headers.get("X-Forwarded-Proto") == "https")
    return resp


@guard
async def api_state(request):
    ok = await client.is_user_authorized()
    out = {"authorized": ok, "step": login["step"], "cfg": cfg}
    if ok:
        me = await client.get_me()
        out["me"] = me.first_name or me.username or str(me.id)
    return web.json_response(out)


@guard
async def api_send_code(request):
    phone = (await request.json()).get("phone", "").strip()
    if not phone:
        return err("Введи номер телефона")
    try:
        sent = await client.send_code_request(phone)
    except PhoneNumberInvalidError:
        return err("Неверный номер телефона")
    login.update(phone=phone, hash=sent.phone_code_hash, step="code")
    return web.json_response({"step": "code"})


@guard
async def api_sign_in(request):
    data = await request.json()
    try:
        if login["step"] == "password":
            await client.sign_in(password=data.get("password", ""))
        else:
            await client.sign_in(phone=login["phone"], code=data.get("code", "").strip(),
                                 phone_code_hash=login["hash"])
    except SessionPasswordNeededError:
        login["step"] = "password"
        return web.json_response({"step": "password"})
    except (PhoneCodeInvalidError, PhoneCodeExpiredError):
        return err("Неверный или устаревший код")
    except PasswordHashInvalidError:
        return err("Неверный пароль 2FA")
    login["step"] = "phone"
    write(SESSION_FILE, client.session.save())
    await client.get_dialogs()
    return web.json_response({"ok": True})


@guard
async def api_dialogs(request):
    if not await client.is_user_authorized():
        return err("Не авторизован")
    items = []
    async for d in client.iter_dialogs():
        if d.is_group or d.is_channel:
            items.append({"id": str(d.id), "name": d.name})
    return web.json_response({"dialogs": items})


@guard
async def api_config(request):
    data = await request.json()
    src, tgt = data.get("source"), data.get("target", "me")
    if data.get("enabled") and not src:
        return err("Сначала выбери группу-источник")
    if src and str(src) == str(tgt):
        return err("Источник и получатель совпадают")
    cfg.update(source=src or None, target=tgt or "me", enabled=bool(data.get("enabled")))
    write(CONFIG_FILE, json.dumps(cfg))
    return web.json_response({"cfg": cfg})


@guard
async def api_session(request):
    if not await client.is_user_authorized():
        return err("Не авторизован")
    return web.json_response({"session": client.session.save()})


async def health(_):
    return web.Response(text="ok")


async def index(_):
    return web.Response(text=read(os.path.join(os.path.dirname(__file__), "index.html")),
                        content_type="text/html")

# ---------- запуск ----------
async def main():
    app = web.Application()
    app.add_routes([
        web.get("/", index), web.get("/health", health),
        web.post("/api/login", api_login), web.get("/api/state", api_state),
        web.post("/api/send_code", api_send_code), web.post("/api/sign_in", api_sign_in),
        web.get("/api/dialogs", api_dialogs), web.post("/api/config", api_config),
        web.get("/api/session", api_session),
    ])
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start()

    await client.connect()
    if await client.is_user_authorized():
        await client.get_dialogs()
        log.info("Telegram: авторизован")
    log.info("Сайт запущен на порту %s", PORT)
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
