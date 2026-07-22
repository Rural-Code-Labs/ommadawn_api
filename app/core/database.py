"""Capa de acceso a la base de datos (SQLAlchemy async).

Aqui viven las tres piezas que comparte todo el proyecto:
  1. `engine`   -> la conexion (pool) a la base de datos.
  2. `Base`     -> la clase base de la que heredan todos los modelos ORM.
  3. `get_session` -> dependencia de FastAPI que da una sesion por request.
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

# El engine gestiona el pool de conexiones. Es async: no bloquea el event loop
# mientras espera a la base de datos.
engine = create_async_engine(settings.database_url, echo=False)

# Fabrica de sesiones. Cada request abrira su propia sesion a partir de aqui.
# expire_on_commit=False para poder seguir usando los objetos tras el commit.
SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Clase base de todos los modelos ORM.

    SQLAlchemy recopila en `Base.metadata` todas las tablas de las clases que
    hereden de aqui. Alembic (y la creacion automatica en dev) usan ese metadata
    para saber que tablas existen.
    """


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependencia de FastAPI: entrega una sesion de BD y la cierra al terminar.

    Uso en un endpoint:
        async def endpoint(session: AsyncSession = Depends(get_session)):
            ...
    El bloque `async with` garantiza que la sesion se cierra siempre, incluso si
    el endpoint lanza una excepcion.
    """
    async with SessionLocal() as session:
        yield session
