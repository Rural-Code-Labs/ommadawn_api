"""Logica de negocio del modulo de auth relacionada con los tokens.

A diferencia de `core/security.py` (funciones puras), este `service` SI toca la
base de datos: crea, valida, rota y revoca refresh tokens. Sigue sin saber nada
de HTTP -> no devuelve respuestas, ni codigos de estado; devuelve datos o None,
y sera el `router` (Fase 4) quien traduzca eso a 200 / 401.

Recordatorio del diseno:
  - El refresh token en CLARO solo lo ve el cliente. En BD guardamos su hash.
  - "Rotar" = al renovar, se revoca el token usado y se emite uno nuevo. Asi un
    token robado deja de servir en cuanto el usuario legitimo renueva.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import generate_refresh_token, hash_refresh_token
from app.modules.auth.models import RefreshToken

settings = get_settings()


def _build_refresh_token(session: AsyncSession, user_id: int) -> str:
    """Construye una fila de refresh token y la anade a la sesion, SIN confirmar.

    Devuelve el token en CLARO (el unico momento en que existe fuera de BD).
    No hace `commit` a proposito: asi quien llama decide cuando confirmar, lo que
    permite agrupar varias operaciones en una sola transaccion (clave para que la
    rotacion sea atomica). Es un helper interno (prefijo `_`).
    """
    token = generate_refresh_token()
    row = RefreshToken(
        token_hash=hash_refresh_token(token),
        user_id=user_id,
        expires_at=datetime.now(timezone.utc)
        + timedelta(days=settings.refresh_token_expire_days),
    )
    session.add(row)
    return token


async def create_refresh_token(session: AsyncSession, user_id: int) -> str:
    """Emite un refresh token nuevo para un usuario y lo persiste.

    Se usara tras un login correcto. Devuelve el token en claro para entregarselo
    al cliente; en BD queda solo su hash.
    """
    token = _build_refresh_token(session, user_id)
    await session.commit()
    return token


async def get_valid_refresh_token(
    session: AsyncSession, token: str
) -> RefreshToken | None:
    """Busca la fila de un refresh token y comprueba que siga siendo valida.

    "Valida" = existe + no revocada + no caducada. La busqueda es por el HASH del
    token (nunca por el token en claro, que no esta en BD). Devuelve la fila o
    None; no lanza excepcion.
    """
    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_refresh_token(token),
            RefreshToken.revoked.is_(False),
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
    )
    return result.scalar_one_or_none()


async def rotate_refresh_token(
    session: AsyncSession, token: str
) -> tuple[int, str] | None:
    """Rota un refresh token: revoca el actual y emite uno nuevo (atomico).

    Devuelve `(user_id, nuevo_token_en_claro)` si el token era valido, o `None`
    si no lo era (inexistente, revocado o caducado). Con el `user_id` el router
    podra ademas emitir un access token nuevo.

    Todo ocurre en una sola transaccion: revocar el viejo y crear el nuevo se
    confirman juntos en un unico `commit`. Si algo fallara, no quedaria el token
    viejo revocado "a medias".
    """
    current = await get_valid_refresh_token(session, token)
    if current is None:
        return None

    current.revoked = True
    new_token = _build_refresh_token(session, current.user_id)
    await session.commit()
    return current.user_id, new_token


async def revoke_refresh_token(session: AsyncSession, token: str) -> bool:
    """Revoca un refresh token valido (para el logout).

    Devuelve True si habia un token valido y se ha revocado, False si no habia
    nada que revocar (token inexistente, ya revocado o caducado).
    """
    current = await get_valid_refresh_token(session, token)
    if current is None:
        return False

    current.revoked = True
    await session.commit()
    return True
