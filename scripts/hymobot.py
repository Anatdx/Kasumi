import asyncio
import os
import sys
from pathlib import Path
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon import errors

API_ID = 611335
API_HASH = "d524b414d21f4d37f08684c1df41ac9c"

# Session file for local persistence (avoids ImportBotAuthorization flood wait)
SESSION_FILE = Path(__file__).resolve().parent / ".hymobot_session"

BOT_TOKEN = os.environ.get("BOT_TOKEN")
CHAT_ID = os.environ.get("CHAT_ID")
MESSAGE_THREAD_ID = os.environ.get("MESSAGE_THREAD_ID")
COMMIT_URL = os.environ.get("COMMIT_URL")
COMMIT_MESSAGE = os.environ.get("COMMIT_MESSAGE")
RUN_URL = os.environ.get("RUN_URL")
TITLE = os.environ.get("TITLE")
VERSION = os.environ.get("VERSION")
BRANCH = os.environ.get("BRANCH")
MSG_TEMPLATE = """
**{title}**
Branch: {branch}
#ci_{version}
```
{commit_message}
```
[Commit]({commit_url})
[Workflow run]({run_url})
""".strip()


def get_caption():
    commit_url = COMMIT_URL or RUN_URL or ""
    commit_message = (COMMIT_MESSAGE or "").strip() or "(no message)"
    msg = MSG_TEMPLATE.format(
        title=TITLE,
        branch=BRANCH,
        version=VERSION,
        commit_message=commit_message,
        commit_url=commit_url,
        run_url=RUN_URL,
    )
    if len(msg) > 1024:
        return commit_url
    return msg


def check_environ():
    global CHAT_ID, MESSAGE_THREAD_ID
    if BOT_TOKEN is None:
        print("[-] Invalid BOT_TOKEN")
        exit(1)
    if CHAT_ID is None or CHAT_ID.strip() == "":
        print("[-] Invalid CHAT_ID")
        exit(1)
    try:
        CHAT_ID = int(CHAT_ID)
    except Exception:
        pass
    if RUN_URL is None:
        print("[-] Invalid RUN_URL")
        exit(1)
    if TITLE is None:
        print("[-] Invalid TITLE")
        exit(1)
    if VERSION is None:
        print("[-] Invalid VERSION")
        exit(1)
    if BRANCH is None:
        print("[-] Invalid BRANCH")
        exit(1)
    if MESSAGE_THREAD_ID and MESSAGE_THREAD_ID != "":
        try:
            MESSAGE_THREAD_ID = int(MESSAGE_THREAD_ID)
        except Exception:
            print("[-] Invalid MESSAGE_THREAD_ID")
            exit(1)
    else:
        MESSAGE_THREAD_ID = None


def load_session():
    """Load session from SESSION_STRING env or .hymobot_session file."""
    session_str = os.environ.get("SESSION_STRING")
    if session_str and session_str.strip():
        return StringSession(session_str.strip()), False
    if SESSION_FILE.exists():
        try:
            s = SESSION_FILE.read_text().strip()
            if s:
                return StringSession(s), False
        except Exception:
            pass
    return StringSession(""), True


def save_session(client):
    """Persist session to file so next run skips ImportBotAuthorization (avoids flood wait)."""
    try:
        session_str = client.session.save()
        try:
            SESSION_FILE.write_text(session_str)
            SESSION_FILE.chmod(0o600)
            print("[+] Session saved to", SESSION_FILE)
        except Exception:
            pass  # CI has no persistent fs
    except Exception as e:
        print("[!] Could not save session:", e)


async def main():
    print("[+] Uploading to telegram")
    check_environ()
    files = sys.argv[1:]
    print("[+] Files:", files)
    if len(files) <= 0:
        print("[-] No files to upload")
        exit(1)
    session, is_new = load_session()
    client = TelegramClient(session, API_ID, API_HASH)
    try:
        if is_new:
            print("[+] Logging in Telegram with bot (first run, may hit flood wait)")
        else:
            print("[+] Using saved session")
        await client.start(bot_token=BOT_TOKEN)
        if is_new:
            save_session(client)
    except errors.FloodWaitError as e:
        print(f"[-] Flood wait: must wait {e.seconds} seconds (ImportBotAuthorization)")
        print("[-] Add TELEGRAM_SESSION_STRING to repo secrets (same as hymo repo).")
        raise
    try:
        caption = [""] * len(files)
        caption[-1] = get_caption()
        print("[+] Caption: ")
        print("---")
        print(caption)
        print("---")
        print("[+] Sending")
        await client.send_file(
            entity=CHAT_ID,
            file=files,
            caption=caption,
            reply_to=MESSAGE_THREAD_ID,
            parse_mode="markdown",
        )
        print("[+] Done!")
    finally:
        await client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"[-] An error occurred: {e}")
