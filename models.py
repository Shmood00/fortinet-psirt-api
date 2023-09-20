from pydantic import BaseModel
from typing import List, Dict

class CVVS3(BaseModel):
    base_score: float
    vector: str
class Affected(BaseModel):
    ge: str
    le: str

class SubNodes(BaseModel):
    description: str
    cpe: str
    affected: Affected
    fixed_in: List[str]

class Configurations(BaseModel):
    nodes: List[SubNodes]
    cvssv3: CVVS3
    cwe: List[str]
    impact: str

class Vulnerabilities(BaseModel):
    id: str
    cve: str
    definitions: List[Configurations]
    

class PSIRT(BaseModel):
    id: str
    title: str
    summary: str
    vulnerabilities: List[Vulnerabilities]
    published: str
    updated: str
    advisory_url: str


""" Model for vulnerabilities affected by given OS and version """
class VersionAffected(BaseModel):
    vulnerabilities: List[str]
    fixed_in: List[str]
    is_vulnerable: bool
