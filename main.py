from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from packaging import version
from typing import List
import models
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
        response_model=List[models.PSIRT]
)
async def root():
    return data

@app.get("/psirt/{psirt_id}", name="Individual PSIRT", summary="Returns information on requested PSIRT",
        tags=["Individual PSIRT"],
        response_description="Returns a dictionary containing information on requested PSIRT",
        response_model=models.PSIRT
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
    cvssv3_dict = {}
    low = []
    medium = []
    high = []
    critical = []
    fixed_in = []
    
    vuln_data = [vuln for vuln in data if os_type.lower() in vuln['title'].lower()]
    
    for vuln in vuln_data:
        for v in range(len(vuln['vulnerabilities'])):
            for nodes in vuln['vulnerabilities'][v]['definitions'][0]['configurations']:

                matched_node = [node for node in nodes['nodes'] if os_type.lower() in node['description'].lower()]
                
                for node in matched_node:
                    try:
                        ge = node['affected']['ge']
                        le = node['affected']['le']
                        
                        if (compare_versions(ge, os_version) == -1) and (compare_versions(os_version, le) == -1):
                            
                            cvssv3 = float(vuln['vulnerabilities'][v]['definitions'][0]['cvssv3']['base_score'])
                    
                            if cvssv3 >= 0.1 and cvssv3 <= 3.9:
                                low.append(cvssv3)
                                
                            elif cvssv3 >= 4.0 and cvssv3 <= 6.9:
                                
                                medium.append(cvssv3)
                                
                            elif cvssv3 >= 7.0 and cvssv3 <= 8.9:
                                
                                high.append(cvssv3)
                                
                            elif cvssv3 >= 9.0 and cvssv3 <= 10.0:
                                
                                critical.append(cvssv3)
                            
                            cvssv3_dict['low'] = low
                            cvssv3_dict['medium'] = medium
                            cvssv3_dict['high'] = high
                            cvssv3_dict['critical'] = critical 

                            vuln_names.append(vuln['title'])
                            fixed_in.append(node['fixed_in'])

                            matched_vulns['vulnerabilities'] = vuln_names
                            matched_vulns['fixed_in'] = fixed_in

                            matched_vulns['cvssv3_scores'] = cvssv3_dict
                            
                    except:
                        Exception

    if matched_vulns:
        matched_vulns["is_vulnerable"] = True

        return matched_vulns
    
    matched_vulns["is_vulnerable"] = False
    return matched_vulns

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)