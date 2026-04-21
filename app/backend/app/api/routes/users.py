from fastapi import APIRouter, Depends, HTTPException
from app.core.auth import require_api_token
from app.core.config import settings
from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path
from app.services.parser import parse_passwd

router = APIRouter(dependencies=[Depends(require_api_token)])

class UserAccount(BaseModel):
    username: str
    uid: int
    gid: int
    gecos: Optional[str] = None
    home: str
    shell: str

class UsersSummary(BaseModel):
    total: int
    human_users: int
    users: List[UserAccount]

@router.get("/users", response_model=UsersSummary)
def get_users() -> UsersSummary:
    try:
        passwd_path = Path(f"{settings.host_fs_prefix}/etc/passwd")
        content = passwd_path.read_text()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao ler usuarios: {str(e)}")
    
    accounts = parse_passwd(content)
    users = [
        UserAccount(
            username=user["username"],
            uid=user["uid"],
            gid=user["gid"],
            gecos=user.get("gecos"),
            home=user["home"],
            shell=user["shell"],
        )
        for user in accounts
    ]
    
    human_users = [u for u in users if u.uid >= 1000 and not u.shell.endswith("nologin")]
    
    return UsersSummary(total=len(users), human_users=len(human_users), users=users)