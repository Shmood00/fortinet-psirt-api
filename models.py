from pydantic import BaseModel
from typing import List, Optional

class Affected(BaseModel):
    ge: Optional[str] = None
    le: Optional[str] = None
    eq: Optional[str] = None

class CVSSV3(BaseModel):
    base_score: float
    vector: str

class NodeInfo(BaseModel):
    description: str
    cpe: str
    affected: Affected
    fixed_in: Optional[List[str]] = None

class ConfigurationInfo(BaseModel):
    nodes: List[NodeInfo]


class DefinitionInfo(BaseModel):
    configurations: List[ConfigurationInfo]
    cvssv3: CVSSV3
    cwe: Optional[List[str]] = None
    impact: Optional[str] = None
    exploit_status: Optional[str] = None

class VulnInfo(BaseModel):
    id: str
    cve: str
    definitions: List[DefinitionInfo]


class PSIRT(BaseModel):
    id: str
    title: str
    summary: str
    vulnerabilities: List[VulnInfo]
    published: str
    updated: str
    advisory_url: str


""" Model for vulnerabilities affected by given OS and version """
class CVSSV3(BaseModel):
    low: Optional[List[float]] = None
    medium: Optional[List[float]] = None
    high: Optional[List[float]] = None
    critical: Optional[List[float]] = None

class VersionAffected(BaseModel):
    vulnerabilities: Optional[List[str]] = None
    fixed_in: Optional[List[str]] = None
    is_vulnerable: bool
    cvssv3_scores: Optional[CVSSV3] = None

