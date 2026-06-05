from contextlib import contextmanager
from typing import Generator, List, Dict, Any, Optional, Type, TypeVar
from functools import wraps

from sqlalchemy import create_engine, event, text, and_
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError
from sqlalchemy.dialects import postgresql, mysql

from config import config

ModelType = TypeVar("ModelType", bound="Base")

Base = declarative_base()


def get_engine() -> Engine:
    db_url = config.database.get_database_url()
    engine_kwargs = {
        "echo": config.database.ECHO,
        "pool_pre_ping": config.database.POOL_PRE_PING,
    }

    if config.database.DB_TYPE != "sqlite":
        engine_kwargs.update({
            "pool_size": config.database.POOL_SIZE,
            "max_overflow": config.database.MAX_OVERFLOW,
            "pool_recycle": config.database.POOL_RECYCLE,
        })

    engine = create_engine(db_url, **engine_kwargs)

    if config.database.DB_TYPE == "sqlite":
        try:
            from sqlalchemy.dialects.sqlite import aiosqlite  # noqa
        except Exception:
            pass
        engine.dialect.supports_returning = False
        engine.dialect.supports_empty_insert = False

        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            try:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA cache_size=-20000")
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
            except Exception:
                pass

    return engine


engine = get_engine()

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


class DatabaseManager:
    def __init__(self):
        self.engine = engine
        self.SessionLocal = SessionLocal

    def init_db(self) -> None:
        Base.metadata.create_all(bind=self.engine)

    def drop_db(self) -> None:
        Base.metadata.drop_all(bind=self.engine)

    @contextmanager
    def get_session(self) -> Generator[Session, None, None]:
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @contextmanager
    def get_session_no_commit(self) -> Generator[Session, None, None]:
        session = self.SessionLocal()
        try:
            yield session
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def bulk_insert(self, session: Session, model: Type[ModelType], data: List[Dict[str, Any]], batch_size: Optional[int] = None) -> int:
        if not data:
            return 0

        batch_size = batch_size or config.concurrency.BATCH_INSERT_SIZE
        total_inserted = 0

        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            try:
                if config.database.DB_TYPE == "postgresql":
                    stmt = postgresql.insert(model).values(batch)
                    session.execute(stmt)
                elif config.database.DB_TYPE == "mysql":
                    stmt = mysql.insert(model).values(batch)
                    session.execute(stmt)
                else:
                    session.bulk_insert_mappings(model, batch)
                total_inserted += len(batch)
            except IntegrityError as e:
                session.rollback()
                for item in batch:
                    try:
                        session.add(model(**item))
                        session.flush()
                        total_inserted += 1
                    except IntegrityError:
                        session.rollback()
                        continue
        return total_inserted

    def bulk_update(self, session: Session, model: Type[ModelType], data: List[Dict[str, Any]], batch_size: Optional[int] = None) -> int:
        if not data:
            return 0

        batch_size = batch_size or config.concurrency.BATCH_UPDATE_SIZE
        total_updated = 0

        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            try:
                if config.database.DB_TYPE == "postgresql":
                    stmt = postgresql.insert(model).values(batch)
                    update_cols = {c.name: c for c in stmt.excluded if c.name not in ["id", "created_at"]}
                    stmt = stmt.on_conflict_do_update(index_elements=["id"], set_=update_cols)
                    result = session.execute(stmt)
                    total_updated += result.rowcount
                elif config.database.DB_TYPE == "mysql":
                    stmt = mysql.insert(model).values(batch)
                    update_cols = {c.name: c for c in stmt.excluded if c.name not in ["id", "created_at"]}
                    stmt = stmt.on_duplicate_key_update(**update_cols)
                    result = session.execute(stmt)
                    total_updated += result.rowcount
                else:
                    session.bulk_update_mappings(model, batch)
                    total_updated += len(batch)
            except SQLAlchemyError:
                session.rollback()
                for item in batch:
                    try:
                        obj = session.query(model).get(item.get("id"))
                        if obj:
                            for key, value in item.items():
                                if hasattr(obj, key) and key not in ["id", "created_at"]:
                                    setattr(obj, key, value)
                            session.flush()
                            total_updated += 1
                    except SQLAlchemyError:
                        session.rollback()
                        continue
        return total_updated

    def bulk_upsert(self, session: Session, model: Type[ModelType], data: List[Dict[str, Any]], conflict_columns: List[str], batch_size: Optional[int] = None) -> int:
        if not data:
            return 0

        batch_size = batch_size or config.concurrency.BATCH_INSERT_SIZE
        total_processed = 0

        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            try:
                if config.database.DB_TYPE == "postgresql":
                    stmt = postgresql.insert(model).values(batch)
                    update_cols = {c.name: c for c in stmt.excluded if c.name not in conflict_columns and c.name != "created_at"}
                    stmt = stmt.on_conflict_do_update(index_elements=conflict_columns, set_=update_cols)
                    result = session.execute(stmt)
                    total_processed += result.rowcount
                elif config.database.DB_TYPE == "mysql":
                    stmt = mysql.insert(model).values(batch)
                    update_cols = {c.name: c for c in stmt.excluded if c.name not in conflict_columns and c.name != "created_at"}
                    stmt = stmt.on_duplicate_key_update(**update_cols)
                    result = session.execute(stmt)
                    total_processed += result.rowcount
                else:
                    for item in batch:
                        try:
                            filter_stmt = []
                            for col in conflict_columns:
                                val = item.get(col)
                                if val is not None:
                                    filter_stmt.append(getattr(model, col) == val)
                                else:
                                    filter_stmt.append(getattr(model, col).is_(None))
                            existing = session.query(model).filter(and_(*filter_stmt)).first()
                            if existing:
                                for key, value in item.items():
                                    if hasattr(existing, key) and key not in conflict_columns and key != "created_at":
                                        setattr(existing, key, value)
                            else:
                                session.add(model(**item))
                            total_processed += 1
                            session.flush()
                        except IntegrityError:
                            session.rollback()
                            continue
            except SQLAlchemyError as e:
                session.rollback()
                raise e
        return total_processed

    def execute_with_retry(self, session: Session, query_func, max_retries: int = 3, retry_on: tuple = (OperationalError,)):
        for attempt in range(max_retries):
            try:
                return query_func(session)
            except retry_on as e:
                if attempt == max_retries - 1:
                    raise
                session.rollback()
                continue

    def get_table_size(self, session: Session, table_name: str) -> int:
        if config.database.DB_TYPE == "postgresql":
            result = session.execute(text(f"SELECT count(*) FROM {table_name}"))
        elif config.database.DB_TYPE == "mysql":
            result = session.execute(text(f"SELECT count(*) FROM {table_name}"))
        else:
            result = session.execute(text(f"SELECT count(*) FROM {table_name}"))
        return result.scalar() or 0

    def vacuum_analyze(self, session: Session, table_name: Optional[str] = None) -> None:
        if config.database.DB_TYPE == "postgresql":
            if table_name:
                session.execute(text(f"VACUUM ANALYZE {table_name}"))
            else:
                session.execute(text("VACUUM ANALYZE"))
        elif config.database.DB_TYPE == "mysql":
            if table_name:
                session.execute(text(f"OPTIMIZE TABLE {table_name}"))
            else:
                pass
        elif config.database.DB_TYPE == "sqlite":
            session.execute(text("VACUUM"))
            session.execute(text("ANALYZE"))


db_manager = DatabaseManager()


def with_session(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        session_arg = kwargs.get("session")
        if session_arg is not None:
            return func(*args, **kwargs)

        with db_manager.get_session() as session:
            kwargs["session"] = session
            return func(*args, **kwargs)

    return wrapper


def with_read_session(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        session_arg = kwargs.get("session")
        if session_arg is not None:
            return func(*args, **kwargs)

        with db_manager.get_session_no_commit() as session:
            kwargs["session"] = session
            return func(*args, **kwargs)

    return wrapper
