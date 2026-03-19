import sys
import os

# Adiciona o diretório do app ao sys.path para importar os módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.session import get_db
from sqlalchemy.orm import Session

def test_context_manager():
    print("Testando context manager get_db()...")
    try:
        with get_db() as db:
            print(f"Sucesso! Recebido objeto do tipo: {type(db)}")
            assert isinstance(db, Session)
        print("Context manager funcionou corretamente.")
    except Exception as e:
        print(f"Erro ao usar context manager: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_context_manager()
