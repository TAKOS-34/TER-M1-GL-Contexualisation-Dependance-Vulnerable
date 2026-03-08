import requests
from bs4 import BeautifulSoup
import re
import os

def fetch_url_content(url):
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    return response.content

def extract_code_changes(content):
    soup = BeautifulSoup(content, 'html.parser')
    code_changes = []

    # Identify all text elements in the page
    text_elements = soup.find_all(string=True)
    
    for element in text_elements:
        text = element.strip()
        # Check if the line starts with @@, +, -, --- or +++
        if re.match(r'^(@@|\+|\-|---|\+\+\+)', text):
            code_changes.append(text)
    
    return "\n".join(code_changes)

def extract_github_commit_links(content):
    soup = BeautifulSoup(content, 'html.parser')
    github_commit_links = []

    for link in soup.find_all('a', href=True):
        href = link['href']
        if re.match(r'^https://github.com/.+/commit/[a-f0-9]+$', href):
            github_commit_links.append(href)
    
    return github_commit_links

def process_website_for_commits(url):
    content = fetch_url_content(url)
    github_commit_links = extract_github_commit_links(content)

    if github_commit_links:
        for commit_url in github_commit_links:
            print(f"Found GitHub commit link: {commit_url}")
            
            # Fetch the content of the GitHub commit page
            #commit_content = fetch_url_content(commit_url)
            
            # Extract code changes from the commit page content
           # patch = extract_code_changes(commit_content)
            #print(f"Patch for {commit_url}:\n{patch}")
    else:
        print("No GitHub commit links found.")

# Example URL (replace with the actual URL)
url = "https://marc.info/?l=bugtraq&m=103946297703402&w=2"

process_website_for_commits(url)

