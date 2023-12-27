import requests
import os
import tomllib

url = "https://detection-engineering-101-2aec7c.kb.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules?rule_id="
id="00000000-0000-0000-0000-000000000001"
full_path=url+id
api_key = "M1pGTHBvd0JVUnBYNW85WnBGZ1k6cHNSRjdOWW5UMG01UXJySHBGUlVPQQ=="
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}


elastic_data = requests.get(full_path, headers=headers).json()
