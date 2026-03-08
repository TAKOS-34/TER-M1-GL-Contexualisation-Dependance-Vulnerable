import os
from dotenv import load_dotenv
from langchain_community.llms import Ollama

load_dotenv(override=True)


url =os.getenv('OLLAMA_HOST_URL')


llm =Ollama(model="mistral:7b-instruct-v0.2-q4_0", base_url=url , temperature=0)
from langchain_core.prompts import PromptTemplate

prompt_template = PromptTemplate.from_template(
   "Given the following CVE description, please extract the affected product(s).Just provide the product names without any additional explanation or details.  Description: {cve_description} List of affected products:"
)



def extract_affected_products(cve_description):
    # Creating a prompt with examples to demonstrate the expected output
    prompt = f"""
Please list the affected product(s) from the following CVE descriptions. The response should only contain the product names, without any additional explanation or commentary.

Example 1:
CVE Description: "A vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Options). Supported versions that are affected are 8.0.26 and prior."
Affected Products: "Oracle MySQL Server"

Example 2:
CVE Description: "PEGA Platform 8.3.0 is vulnerable to a direct prweb/sso/random_token request while using a low-privilege account."
Affected Products: "PEGA Platform"

Now, given the following CVE description, please extract the affected product(s) using Named entity recognation:

CVE Description: "{cve_description}"

Affected Products:
"""
    prompt2=f"""
Please extract the vulnerability impact from the following CVE description.


Now, given the following CVE description, please extract the vulnerability impact as written exactly in the cve decription using Named entity recognation:

CVE Description: "{cve_description}"

vulnerability impact:
"""
    return llm.invoke(PromptTemplate.from_template(prompt).format())

# Extracting affected products
affected_products = extract_affected_products("EGA Platform 8.3.0 is vulnerable to a direct prweb/sso/random_token/!STANDARD?pyActivity=Data-Admin-DB-Name.DBSchema_ListDatabases request while using a low-privilege account. (This can perform actions and retrieve data that only an administrator should have access to.) NOTE: The vendor states that this vulnerability was discovered using an administrator account and they are normal administrator functions. Therefore, the claim that the CVE was done with a low privilege account is incorrect")
print(affected_products)
