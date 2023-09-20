from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import models
from packaging import version
from typing import List, Dict
import json, uvicorn

app = FastAPI(
    title="Fortinet PSIRT Advisories",
    description="This API was created to access Fortinet PSIRT advisories in JSON format.",
    version="1.0.0"
)

f = open("combined-vulns.json")

data = json.load(f)

origins = [
    "https://heartfelt-treacle-bef921.netlify.app"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"]
)

def compare_versions(v1,v2):
    if version.parse(v1) <= version.parse(v2):
        return -1
    elif version.parse(v1) >= version.parse(v2):
        return 1

@app.get("/", name="All PSIRTs", summary="Returns all Fortinet PSIRTs published in 2023.",
        tags=["All Vulnerabilities"],
        response_description="Returns list of dictionaries containing PSIRT advisories posted so far in 2023.",
)
async def root():
    return data

@app.get("/psirt/{psirt_id}", name="Individual PSIRT", summary="Returns information on requested PSIRT",
        tags=["Individual PSIRT"],
        response_description="Returns a dictionary containing information on requested PSIRT",
        
)
async def individual_psirt(psirt_id):
    for vuln in data:
        if vuln['id'] == psirt_id:
            return vuln

@app.get("/psirt/vulnerabilities/{os_type}", name="OS Version Affected", summary="Returns vulnerabilities the given OS and version are affected by.",
         tags=["Vulnerabilities"],
         response_description="Returns a dictionary of vulnerabilities that impact the given OS and version type.",
         response_model=models.VersionAffected
)
async def find_vuln(os_type: str, os_version: str):
    matched_vulns = {}
    vuln_names = []

    for vuln in data:
        if os_type.lower() in vuln['title'].lower():

            os_nodes_list = [node for item in vuln['vulnerabilities'][0]['definitions'][0]['configurations'] for node in item['nodes'] if os_type.lower() in node['description'].lower()]

            for node in os_nodes_list:
                try:
                    ge = node['affected']['ge']
                    le = node['affected']['le']

                    if (compare_versions(ge, os_version) == -1 and compare_versions(os_version, le) == -1):
                        vuln_names.append(vuln['title'])
                        matched_vulns["vulnerabilities"] = vuln_names
                        matched_vulns["fixed_in"] = node['fixed_in']
                except:
                    Exception
    
    if matched_vulns:
        matched_vulns["is_vulnerable"] = True

        return matched_vulns
    
    matched_vulns["is_vulnerable"] = False
    return matched_vulns

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)