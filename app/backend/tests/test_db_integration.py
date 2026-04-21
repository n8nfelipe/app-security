from app.db.session import SessionLocal


def test_session_local_creation():
    session = SessionLocal()
    assert session is not None
    session.close()


def test_session_local_query():
    from app.db.models import Scan
    session = SessionLocal()
    result = session.query(Scan).all()
    assert isinstance(result, list)
    session.close()


def test_session_with_query_filter():
    from app.db.models import Scan
    session = SessionLocal()
    result = session.query(Scan).filter(Scan.status == "completed").all()
    assert isinstance(result, list)
    session.close()