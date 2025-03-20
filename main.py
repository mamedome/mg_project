from fastapi import FastAPI, UploadFile, HTTPException, File, Form
from pydantic import BaseModel
from typing import List, Dict
import uuid
import cachetools
import httpx
import re

app = FastAPI()

# In-memory storage
applications = []
all_dependencies = {}
cache = cachetools.TTLCache(maxsize=1000, ttl=3600)


class ApplicationResponse(BaseModel):
    app_id: str
    name: str
    description: str
    has_vulnerabilities: bool


class Dependency(BaseModel):
    name: str
    version: str
    vulnerabilities: List[Dict]


class DependencyDetail(Dependency):
    used_in: List[str]


def parse_requirements(requirements: str) -> List[Dict]:
    dependencies = []
    for line in requirements.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):  # We don't care about comments in the file
            parts = re.split(r'==|>=|<=|>|<', line, 1)
            name = parts[0].strip()
            version = parts[1].strip() if len(parts) > 1 else 'Unknown'
            dependencies.append({'name': name, 'version': version})
    return dependencies


async def fetch_vulnerabilities(name: str, version: str) -> List[Dict]:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                "https://api.osv.dev/v1/query",
                json={
                    "version": version,
                    "package": {
                        "name": name,
                        "ecosystem": "PyPI"
                    }
                }
            )
            return response.json().get('vulns', []) if response.status_code == 200 else []
        except httpx.RequestError:
            return []
