from fastapi import FastAPI
from packaging import version
import json

app = FastAPI()

f = open("combined-vulns.json")

data = json.load(f)

def compare_versions(v1,v2):
    if version.parse(v1) <= version.parse(v2):
        return -1
    elif version.parse(v1) >= version.parse(v2):
        return 1

@app.get("/")
async def root():
    return data

@app.get("/psirt/{psirt_id}")
async def individual_psirt(psirt_id):
    for vuln in data:
        if vuln['id'] == psirt_id:
            return vuln

@app.get("/psirt/vulnerabilities/{os_type}")
async def find_vuln(os_type: str, os_version: str):
    matched_vulns = {}
    vuln_names = []

    for vuln in data:
        if os_type.lower() in vuln['title'].lower():
            print(vuln['title'], vuln['id'])

            os_nodes_list = [node for item in vuln['vulnerabilities'][0]['definitions'][0]['configurations'] for node in item['nodes'] if os_type.lower() in node['description'].lower()]

            for node in os_nodes_list:
                try:
                    ge = node['affected']['ge']
                    le = node['affected']['le']

                    if (compare_versions(ge, os_version) == -1 and compare_versions(os_version, le) == -1):
                        vuln_names.append(vuln['title'])
                        matched_vulns[os_version] = vuln_names
                        matched_vulns["fixed_in"] = node['fixed_in']
                except:
                    Exception
    
    if matched_vulns:
        matched_vulns["is_vulnerable"] = True

        return matched_vulns
    
    matched_vulns["is_vulnerable"] = False
    return matched_vulns