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
cache = cachetools.TTLCache(maxsize=1000, ttl=86400)  # Data remains in cache for 24 hours


class ApplicationResponse(BaseModel):
    app_id: str
    name: str
    description: str
    has_vulnerabilities: bool


class Dependency(BaseModel):
    name: str
    version: str
    vulnerable: bool
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
    key = (name, version)
    if key in cache:
        return cache[key]
    else:
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
                if response.status_code == 200:
                    vulns = response.json().get('vulns', [])
                    cache[key] = vulns
                    all_dependencies[key] = {'name': name, 'version': version, 'vulnerabilities': vulns}
                    return vulns
                else:
                    return []
            except httpx.RequestError:
                return []


def is_dep_vulnerable(name: str, version: str) -> bool:
    return True if len(all_dependencies[(name, version)]['vulnerabilities']) > 0 else False


@app.post("/applications", response_model=ApplicationResponse)
async def create_application(name: str = Form(...),
                             description: str = Form(...),
                             requirements_file: UploadFile = File(...)):
    contents = await requirements_file.read()
    deps = parse_requirements(contents.decode('utf-8'))

    app_dependencies = []
    for dep in deps:
        vulns = await fetch_vulnerabilities(dep['name'], dep['version'])
        app_dependencies.append({'name': dep['name'], 'version': dep['version'], 'vulnerabilities': vulns})

    app_id = str(uuid.uuid4())
    new_app = {
        'id': app_id,
        'name': name,
        'description': description,
        'dependencies': app_dependencies
    }
    applications.append(new_app)
    return {
        'app_id': app_id,
        'name': name,
        'description': description,
        'has_vulnerabilities': any(len(d['vulnerabilities']) > 0 for d in app_dependencies)
    }


@app.get("/applications", response_model=List[ApplicationResponse])
def get_applications():
    return [{
        'app_id': appl['id'],
        'name': appl['name'],
        'description': appl['description'],
        'has_vulnerabilities': any(len(d['vulnerabilities']) > 0 for d in appl['dependencies'])
    } for appl in applications]


@app.get("/applications/dependencies/{app_id}", response_model=List[Dependency])
def get_app_dependencies(app_id: str):
    appl = next((appl for appl in applications if appl['id'] == app_id), None)
    if not appl:
        raise HTTPException(404, "Application not found")
    return [{'name': d['name'],
             'version': d['version'],
             'vulnerabilities': d['vulnerabilities'],
             'vulnerable': is_dep_vulnerable(d['name'], d['version'])} for d in appl['dependencies']]


@app.get("/all-dependencies", response_model=List[Dependency])
def get_dependencies():
    return [{'name': d['name'],
             'version': d['version'],
             'vulnerabilities': d['vulnerabilities'],
             'vulnerable': is_dep_vulnerable(d['name'], d['version'])} for d in all_dependencies.values()]


@app.get("/dependencies", response_model=List[DependencyDetail])
def get_dependency_details(name: str, version: str):
    dependency = all_dependencies.get((name, version))
    if not dependency:
        raise HTTPException(404, "Dependency not found")

    return [{
        'name': dependency['name'],
        'version': dependency['version'],
        'vulnerabilities': dependency['vulnerabilities'],
        'vulnerable': is_dep_vulnerable(dependency['name'], dependency['version']),
        'used_in': [appl['name'] for appl in applications
                    if any(d['name'] == dependency['name'] and d['version'] == dependency['version'] for d in
                           appl['dependencies'])]
    }]
