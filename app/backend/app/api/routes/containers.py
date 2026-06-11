from fastapi import APIRouter, Depends
from app.core.auth import require_api_token

import docker
from docker.errors import DockerException

router = APIRouter(dependencies=[Depends(require_api_token)])


def _get_container_image(container) -> str:
    try:
        img = container.image
        return img.tags[0] if img.tags else img.short_id
    except docker.errors.NotFound:
        return container.attrs.get("Config", {}).get("Image", "unknown")
    except DockerException:
        return "unknown"


def list_running_containers() -> tuple[list[dict], bool]:
    try:
        client = docker.DockerClient(base_url="unix://var/run/docker.sock")
        client.ping()
    except DockerException:
        return [], False

    containers = client.containers.list()
    result = []
    for c in containers:
        try:
            result.append({
                "id": c.id,
                "name": c.name,
                "image": _get_container_image(c),
                "status": c.status,
                "ports": (c.attrs.get("NetworkSettings") or {}).get("Ports") or {},
            })
        except DockerException:
            continue
    return result, True


@router.get("/containers", summary="Lista os containers docker em execucao")
def get_containers():
    containers, available = list_running_containers()
    return {"total": len(containers), "containers": containers, "docker_available": available}