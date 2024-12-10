import argparse
import snyk
import os
from urllib.parse import quote
import urllib
import http
import httpx
import json
from datetime import date, timedelta, datetime
import pprint

'''
Description: Program meant to:
 query Snyk Projects
 query types of targets in orgs
 tag github with those targets to run enforcement
'''
token = os.getenv('SNYK_TOKEN') # Set your API token as an environment variable
apiVersion = "2024-10-15"  # Set the API version. Needs ~beta endpoint at stated version or later
tries = 4  # Number of retries
delay = 1  # Delay between retries
backoff = 2  # Backoff factor

all_remote_repo_urls = []
remote_repos_scanned = []
remote_repos_stale = []

def search_json(json_obj, search_string):
    if isinstance(json_obj, dict):
        for key, value in json_obj.items():
            if search_json(value, search_string):
                return True
    elif isinstance(json_obj, list):
        for item in json_obj:
            if search_json(item, search_string):
                return True
    elif isinstance(json_obj, str):
        if search_string in json_obj:
            return True
    return False

def days_ago(given_date):
    today = datetime.today()
    delta = today - given_date
    return delta.days

def get_org_projects():
    #open_source_types = ['apk','cocoapods', 'composer', 'cpp', 'deb', 'golang', 'gradle', 'maven', 'npm', 'nuget', 'pip', 'pipenv', 'poetry', 'rubygems', 'sbt', 'swift', 'yarn']
    #iac_types = ['cloudformationconfig', 'armconfig', 'dockerfile', 'helm', 'k8sconfig', 'terraformconfig']

    with create_client(token=token, tenant="us") as client:
        #client = snyk.SnykClient(token, tries=tries, delay=delay, backoff=backoff)  # Context switch the client to model-based
        organizations = client.organizations.all()

        for org in organizations:
            if org.name == "snykMathesOrg":
                projects = org.projects.all()
                
                for project in projects:
                    if project.remoteRepoUrl not in all_remote_repo_urls:
                        all_remote_repo_urls.append(project.remoteRepoUrl)
                        get_scm_repo_status(project.remoteRepoUrl)

def apply_snyk_org_tags():
    with create_client(token=token, tenant="us") as client:
        #client = snyk.SnykClient(token, tries=tries, delay=delay, backoff=backoff)  # Context switch the client to model-based
        organizations = client.organizations.all()

        for org in organizations:
            if org.name == "snykMathesOrg":
                projects = org.projects.all()
                
                for project in projects:
                    print("\nupdate project tags: " + project.name)
                    delete_tags(project)
                    if project.remoteRepoUrl in remote_repos_stale:
                        #delete_tag(project, "active_repo", "true")
                        add_tag(project, "active_repo", "false")
                        print("project tagged inactive \n")
                        set_project_criticality(org, project, "low")
                    else:
                        #delete_tag(project, "active_repo", "false")
                        add_tag(project, "active_repo", "true")
                        print("project tagged active \n")
                        set_project_criticality(org, project, "high")
                    print("\n")

#remove stale tags
def delete_tags(project):
    delete_tag(project, "active_repo", "true")
    delete_tag(project, "active_repo", "false")

def delete_tag(project, key, value):
    tag = {"key": key, "value": value}
    if tag in project.tags.all():
        project.tags.delete(key, value)

def add_tag(project, key, value):
    tag = {"key": key, "value": value}
    if tag not in project.tags.all():
            project.tags.add(key, value)

def set_project_criticality(org, project, criticality):
    with create_client(token=token, tenant="us") as client:
        apply_criticality_to_project(client, org.id, project.id, criticality, project.name)

# Reach to the API and generate tokens
def create_client(token: str, tenant: str) -> httpx.Client:
    base_url = (
        f"https://api.{tenant}.snyk.io/rest"
        if tenant in ["eu", "au"]
        else "https://api.us.snyk.io/rest"
    )
    headers = {
        'Accept': 'application/vnd.api+json',
        "Authorization": f"token {token}",
        "Content-Type": 'application/vnd.api+json'
    }
    return httpx.Client(base_url=base_url, headers=headers)

def apply_criticality_to_project(
    client: httpx.Client,
    org_id: str,
    project_id: str,
    criticality: str,
    project_name: str,
) :#-> tuple:
    attribute_data = {
        "data": {
            "attributes": {
                "business_criticality": [criticality]
            },
            "id": project_id,
            "type": "project",
            "relationships": {}
        }
    }
    
    params = {'version': apiVersion}
    req = client.patch(f"orgs/{org_id}/projects/{project_id}", json=attribute_data, params=params, timeout=None)
    #print("REQUEST text: " + str(req.text))

    if req.status_code == 200:
        print(f"Successfully added {criticality} criticality to Project: {project_name}.")
    elif req.status_code == 422:
        print(f"{criticality} already applied for Project: {project_name}.")
    elif req.status_code == 404:
        print(f"Project not found, likely a READ-ONLY project. Project: {project_name}. attribute: {attribute_data}.")

def get_scm_repo_status(repo_path):
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': "Bearer " + os.getenv('GITHUB_TOKEN'),
        'User-Agent' : 'python script', 
        'X-GitHub-Api-Version': '2022-11-28',
    }

    if repo_path is not None:
        print("processing repo_path: " + repo_path)
        github_Org, repo_name = repo_path.split("/")[-2:]

        request_url = f"/repos/{github_Org}/{repo_name}"
        conn = http.client.HTTPSConnection("api.github.com")
        conn.request("GET", request_url, None, headers)
        response = conn.getresponse()
        response_data = response.read()
        conn.close()

        json_obj = json.loads(response_data.decode())
        pushed_at_date = json_obj['pushed_at']
        print(repo_path + " data is: " + pushed_at_date)

        days_since_push = days_ago(datetime.strptime(pushed_at_date, "%Y-%m-%dT%H:%M:%SZ")) 
        print(repo_path + " days since push is: " + str(days_since_push))

        if days_since_push > 90:
            remote_repos_stale.append(repo_path)
            print("added to stale repos")
        print("\n")

if __name__ == '__main__':
    # Parsing Command Line Arguments
    parser = argparse.ArgumentParser(
        description='Tag Github With Snyk Targets')
    # Required fields:

    orgs = []
    count = 0
    projects = get_org_projects()

    apply_snyk_org_tags()    

    # print count of issues with description of filter criteria from arguments
    print(f"\n")

    exit()