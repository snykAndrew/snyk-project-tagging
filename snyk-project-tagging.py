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
github_token = os.getenv('GITHUB_TOKEN')
snyk_url = "https://api.us.snyk.io/rest" #os.getenv('SNYK_URL')
v1_snyk_url = "https://api.us.snyk.io/v1" #os.getenv('SNYK_URL')
apiVersion = "2024-10-15"  # Set the API version. Needs ~beta endpoint at stated version or later

tries = 4  # Number of retries
delay = 1  # Delay between retries
backoff = 2  # Backoff factor

all_remote_repo_urls = []
all_snyk_targets = []

remote_repos_scanned = []
remote_repos_stale = []
remote_repos_archived = []

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

    client = snyk.SnykClient(token, tries=tries, delay=delay, backoff=backoff, url=snyk_url)  # Context switch the client to model-based
    print("getting orgs")
    
    organizations = client.organizations.all()
    print("orgs retrieved: " + str(organizations))

    for org in organizations:
        print("getting projects for org: " + org.name)    
        projects = org.projects.all()

        print("geting repos per project")
        for project in projects:
            if project.remoteRepoUrl not in all_remote_repo_urls:
                print("getting remote repo for project: " + project.name)
                all_remote_repo_urls.append(project.remoteRepoUrl)
                get_scm_repo_status(project.remoteRepoUrl)

def get_org_projects_rest():
    #open_source_types = ['apk','cocoapods', 'composer', 'cpp', 'deb', 'golang', 'gradle', 'maven', 'npm', 'nuget', 'pip', 'pipenv', 'poetry', 'rubygems', 'sbt', 'swift', 'yarn']
    #iac_types = ['cloudformationconfig', 'armconfig', 'dockerfile', 'helm', 'k8sconfig', 'terraformconfig']

    #with create_client(token=token, tenant="us") as client:
    rest_client = snyk.SnykClient(token, tries=tries, delay=delay, backoff=backoff, version=apiVersion, url=snyk_url)  # Context switch the client to model-based
    print("getting orgs")

    organizations = rest_client.get_rest_pages(f"/orgs/")
    print("orgs retrieved: " +  str(organizations) )

    for org in organizations:
        #print("getting projects for org: " + str(org))    
        
        targets = rest_client.get_rest_pages(f"/orgs/{org['id']}/targets")
        all_snyk_targets.append(targets)

        #print("geting repos for projects: " + str(projects))
        for target in targets:
            print("project: " + str(target))
            targetUrl = target["attributes"]["url"]

            if targetUrl not in all_remote_repo_urls:
                all_remote_repo_urls.append(targetUrl)
                get_scm_repo_status(targetUrl)

def apply_snyk_org_tags():
    #with create_client(token=token, tenant="us") as client:
    client = snyk.SnykClient(token, tries=tries, delay=delay, backoff=backoff, url=snyk_url)
    organizations = client.organizations.all()

    for org in organizations:
        projects = org.projects.all()

        #print("PROJECTS FOUND: " + str(projects))
        
        for project in projects:
            #print("\nupdate project tags: " + project.name)
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

def apply_snyk_org_tags_rest():
    #with create_client(token=token, tenant="us") as client:
    rest_client = snyk.SnykClient(token, tries=tries, delay=delay, backoff=backoff, version=apiVersion, url=snyk_url)
    v1_client = snyk.SnykClient(token, tries=tries, delay=delay, backoff=backoff, url=v1_snyk_url)   # Context switch the client to model-based
    print("getting orgs")

    organizations = rest_client.get_rest_pages(f"/orgs/")
    #organizations = client.organizations.all()

    for org in organizations:
        projects = rest_client.get_rest_pages(f"/orgs/{org['id']}/projects")
        #projects = org.projects.all()

        #print("PROJECTS FOUND: " + str(projects))
        
        for project in projects:
            #print("\nupdate project tags: " + str(project))

            #get remoteRepoUrl from target
            targetId = project["relationships"]["target"]["data"]["id"]

            print("found related targetId: " + str(targetId))
            target = rest_client.get(f"/orgs/{org['id']}/targets/{targetId}").json()
            print("found related target: " + str(target))

            targetUrl = target["data"]["attributes"]["url"]

            if targetUrl in remote_repos_stale:
                tags = [{"key": "active_repo", "value": "false"}]
                with create_client(token=token, tenant="us") as client:
                    apply_criticality_to_project(client, org["id"], project["id"], "low", project["attributes"]["name"], tags)
            else:
                tags = [{"key": "active_repo", "value": "true"}]
                with create_client(token=token, tenant="us") as client:
                    apply_criticality_to_project(client, org["id"], project["id"], "high", project["attributes"]["name"], tags)

            if targetUrl in remote_repos_archived:
                print(f"hitting url: /orgs/{org['id']}/projects/{project['id']}/deactivate")
                v1_client.post(f"/org/{org['id']}/project/{project['id']}/deactivate", body={}, headers={"Content-Type": "application/vnd.api+json"}).json()

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
        if tenant in ["eu", "au", "us"]
        else "https://api.snyk.io/rest"
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
    tags: list
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
        'Authorization': "Bearer " + github_token,
        'User-Agent' : 'python script', 
        'X-GitHub-Api-Version': '2022-11-28',
    }

    print("\n")
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

        #print("\n\n\ngithub object: " + str(json_obj))
        if 'status' in json_obj and json_obj['status'] == '404':
            print("cannot access repo: " + repo_path + " with this key (unauthorized (404) for this resource)")
        elif 'status' in json_obj and json_obj['status'] == '401':
            print("cannot access repo: " + repo_path + " : bad credentials (401) (invalid github token)")
        elif 'pushed_at' in json_obj and 'archived' in json_obj:
            pushed_at_date = json_obj['pushed_at']
            print(repo_path + " data is: " + pushed_at_date)

            print("ARCHIVE STATUS: " + str(json_obj['archived']))
            if json_obj['archived']:
                if repo_path not in remote_repos_archived:
                    remote_repos_archived.append(repo_path)

            days_since_push = days_ago(datetime.strptime(pushed_at_date, "%Y-%m-%dT%H:%M:%SZ")) 
            print(repo_path + " days since push is: " + str(days_since_push))

            if days_since_push > 90:
                remote_repos_stale.append(repo_path)
                print("added to stale repos")
        else:
            print("cannot access repo: " + repo_path + " - unknown reason - response:" + str(json_obj))

        #line break for next project
        print("\n")

if __name__ == '__main__':
    # Parsing Command Line Arguments
    parser = argparse.ArgumentParser(
        description='Tag Github With Snyk Targets')
    # Required fields:

    orgs = []
    count = 0
    projects = get_org_projects_rest()

    apply_snyk_org_tags_rest()    

    # print count of issues with description of filter criteria from arguments
    print(f"\n")

    exit()