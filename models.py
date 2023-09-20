from pydantic import BaseModel
from typing import List, Dict

class Affected(BaseModel):
    ge: str
    le: str


class Nodes(BaseModel):
    description: str
    cpe: str
    affected: Affected
    fixed_in: List[str]


class CVSSV3(BaseModel):
    base_score: float
    vector: str

class Configurations(BaseModel):
    nodes: List[Nodes]
    cvssv3: CVSSV3
    cwe: List[str]
    impact: str

class Vulnerabilities(BaseModel):
    id: str
    cve: str
    definitions: List[Configurations]


class AllPSIRT(BaseModel):
    id: str
    title: str
    summary: str
    vulnerabilites: List[Vulnerabilities]
    published: str
    updated: str
    advisory_url: str

""" Model for vulnerabilities affected by given OS and version """
class VersionAffected(BaseModel):
    version: List[str]
    fixed_in: List[str]
    is_vulnerable: bool
