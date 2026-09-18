"""
Получение, хранение и обновление токена авторизации Яндекс.Музыки.

Реализует OAuth Device Flow через библиотеку yandex_music (см.
https://ym.marshal.dev/token/), сохраняет полученный токен вместе с
метаданными в файл и умеет прозрачно обновлять его по истечении срока
действия. Если refresh-токен оказался недействителен -- запускается
повторный вход (повторный Device Flow).
"""

import json
import os
import stat
import time
import webbrowser
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import requests
from yandex_music import Client, DeviceCode
from yandex_music.exceptions import DeviceAuthError

TOKEN_HELP_URL = "https://ym.marshal.dev/token/"
OAUTH_TOKEN_URL = "https://oauth.yandex.ru/token"

# Публичные OAuth-креды официального Android-приложения Яндекс.Музыки.
# Используются самой библиотекой yandex_music для Device Flow (см.
# yandex_music/_client/device_auth.py) и известны из README/документации
# проекта. Нужны здесь только чтобы иметь возможность самостоятельно
# обновить access_token по refresh_token -- сама библиотека такого метода
# не предоставляет.
DEFAULT_CLIENT_ID = "23cabbbdc6cd418abb4b39c32c41195d"
DEFAULT_CLIENT_SECRET = "53bc75238f0c4d08a118e51fe9203300"

# Обновлять токен заранее, чтобы не наткнуться на его истечение прямо
# посреди запроса к API.
EXPIRY_LEEWAY_SECONDS = 5 * 60


class RefreshTokenInvalidError(Exception):
    """Refresh-токен недействителен/отозван, требуется повторный вход."""


def default_token_file() -> Path:
    """Путь к файлу токена по умолчанию, специфичный для ОС."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", str(Path.home())))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    return base / "yandex-music-downloader" / "token.json"


@dataclass
class TokenData:
    access_token: str
    refresh_token: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None
    obtained_at: float = 0.0
    account_login: Optional[str] = None

    @property
    def expires_at(self) -> Optional[float]:
        if self.expires_in is None:
            return None
        return self.obtained_at + self.expires_in

    def is_expired(self, leeway: int = EXPIRY_LEEWAY_SECONDS) -> bool:
        expires_at = self.expires_at
        if expires_at is None:
            # Сервер не сообщил срок действия - считаем токен действительным
            # до тех пор, пока API явно не откажет в авторизации.
            return False
        return time.time() >= (expires_at - leeway)

    @classmethod
    def from_dict(cls, data: dict) -> "TokenData":
        return cls(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type"),
            expires_in=data.get("expires_in"),
            obtained_at=data.get("obtained_at", 0.0),
            account_login=data.get("account_login"),
        )

    def to_dict(self) -> dict:
        result = asdict(self)
        result["expires_at"] = self.expires_at
        return result


def load_token(token_file: Path) -> Optional[TokenData]:
    try:
        raw = token_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        return TokenData.from_dict(json.loads(raw))
    except (json.JSONDecodeError, KeyError, TypeError):
        print(f'Не удалось прочитать файл токена "{token_file}", он будет перезаписан')
        return None


def save_token(token_file: Path, data: TokenData) -> None:
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(
        json.dumps(data.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if os.name != "nt":
        try:
            token_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def _on_code(code: DeviceCode) -> None:
    print()
    print("Для авторизации в Яндекс.Музыке откройте ссылку и введите код:")
    print(f"  Ссылка: {code.verification_url}")
    print(f"  Код:    {code.user_code}")
    print()
    try:
        webbrowser.open(code.verification_url)
    except Exception:
        pass
    print("Ожидание подтверждения входа в браузере...")


def perform_device_auth() -> TokenData:
    """Запускает Device Flow, дожидается подтверждения и возвращает токен."""
    client = Client()
    try:
        token = client.device_auth(on_code=_on_code)
    except DeviceAuthError as e:
        raise DeviceAuthError(
            f"Не удалось выполнить авторизацию через Device Flow ({e}).\n"
            f"Альтернативные способы получения токена описаны здесь: {TOKEN_HELP_URL}"
        ) from e

    account_login = None
    try:
        client.init()
        if client.me and client.me.account:
            account_login = client.me.account.login
    except Exception:
        pass

    print("Авторизация прошла успешно" + (f" ({account_login})" if account_login else ""))

    return TokenData(
        access_token=token.access_token,
        refresh_token=token.refresh_token,
        token_type=token.token_type,
        expires_in=token.expires_in,
        obtained_at=time.time(),
        account_login=account_login,
    )


def refresh_access_token(refresh_token: str) -> TokenData:
    """Обновляет access_token по refresh_token напрямую через OAuth API Яндекса."""
    response = requests.post(
        OAUTH_TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": DEFAULT_CLIENT_ID,
            "client_secret": DEFAULT_CLIENT_SECRET,
        },
        timeout=20,
    )

    if response.status_code == 400:
        try:
            error = response.json().get("error")
        except ValueError:
            error = None
        if error in ("invalid_grant", "invalid_client"):
            raise RefreshTokenInvalidError(error)
        raise RuntimeError(f"Не удалось обновить токен: {error or response.text}")

    response.raise_for_status()
    payload = response.json()

    return TokenData(
        access_token=payload["access_token"],
        refresh_token=payload.get("refresh_token") or refresh_token,
        token_type=payload.get("token_type"),
        expires_in=payload.get("expires_in"),
        obtained_at=time.time(),
    )


def get_access_token(token_file: Path, relogin: bool = False) -> str:
    """
    Основная точка входа: возвращает рабочий access_token, по возможности
    без участия пользователя.

    - Если сохранённого токена нет -- запускает Device Flow.
    - Если токен ещё действителен -- возвращает его как есть.
    - Если истёк, но есть refresh_token -- обновляет его.
    - Если refresh_token недействителен (или отсутствует) -- запрашивает
      повторный вход.
    """
    if relogin:
        print("Запрошен повторный вход в аккаунт Яндекс.Музыки")
        data = perform_device_auth()
        save_token(token_file, data)
        print(f'Токен сохранён в "{token_file}"')
        return data.access_token

    data = load_token(token_file)

    if data is None:
        print("Сохранённый токен не найден, требуется авторизация")
        data = perform_device_auth()
        save_token(token_file, data)
        print(f'Токен сохранён в "{token_file}"')
        return data.access_token

    if not data.is_expired():
        return data.access_token

    if data.refresh_token:
        print("Срок действия токена истёк, пробуем обновить его...")
        try:
            refreshed = refresh_access_token(data.refresh_token)
            refreshed.account_login = data.account_login
            save_token(token_file, refreshed)
            print(f'Токен обновлён и сохранён в "{token_file}"')
            return refreshed.access_token
        except RefreshTokenInvalidError:
            print("Refresh-токен недействителен, требуется повторный вход")
        except (requests.RequestException, RuntimeError) as e:
            print(f"Не удалось обновить токен ({e}), требуется повторный вход")
    else:
        print("Срок действия токена истёк, а refresh-токен отсутствует, требуется повторный вход")

    data = perform_device_auth()
    save_token(token_file, data)
    print(f'Токен сохранён в "{token_file}"')
    return data.access_token
