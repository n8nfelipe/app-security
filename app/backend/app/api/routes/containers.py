from fastapi import APIRouter, Depends, HTTPException
from app.core.auth import require_api_token

import docker
from docker.errors import DockerException

router = APIRouter(dependencies=[Depends(require_api_token)])

def list_running_containers():
    try:
        client = docker.DockerClient(base_url="unix://var/run/docker.sock")
        containers = client.containers.list()
        return [
            {
                "id": c.id,
                "name": c.name,
                "image": c.image.tags[0] if c.image.tags else c.image.short_id,
                "status": c.status,
                "ports": c.attrs.get("NetworkSettings", {}).get("Ports", {})
            }
            for c in containers
        ]
    except DockerException as e:
        raise HTTPException(status_code=500, detail=f"Falha ao acessar Docker: {str(e)}")

@router.get("/containers", summary="Lista os containers docker em execucao")
def get_containers():
    containers = list_running_containers()
    return {"total": len(containers), "containers": containers}