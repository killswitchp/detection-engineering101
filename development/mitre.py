import requests
from dataclasses import field
import tomllib
import sys
import os

url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
headers={
    'accept':'application/json'
}
mitreData= requests.get(url,headers=headers).json()
mitreMapped={}
#def getMapping(mitreData)

for object in mitreData['objects']:
   tactics=[]
   
   if object['type']=='attack-pattern':
      if 'external_references' in object:
         for reference in object['external_references']:
           if 'external_id' in reference:
             if((reference['external_id'].startswith("T"))):
                if 'kill_chain_phases' in object:
                   for tactic in object['kill_chain_phases']:
                      tactics.append(tactic['phase_name'])
                technique=reference['external_id']
                name=object['name']
                url=reference['url']
                if 'x_mitre_deprecated' in object:
                    deprecated = object['x_mitre_deprecated']
                    filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': deprecated}
                    mitreMapped[technique] = filtered_object
                else:
                    filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': "False"}
                    mitreMapped[technique] = filtered_object

#print(mitreMapped['T1123']['deprecated'])
alert_data={}

for root,dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
          full_path=os.path.join(root,file)
          with open(full_path,"rb") as toml:
            alert=tomllib.load(toml)

            filtered_object_array = []
            if alert['rule']['threat'][0]['framework']== "MITRE ATT&CK":
             for threat in alert['rule']['threat']:
               technique_id= threat['technique'][0]['id']
               technique_name=threat['technique'][0]['name']
               if 'tactic' in threat:
                  tactic=threat['tactic']['name']
               else:
                  tactic="none"
               
               if 'subtechnique' in threat['technique'][0]:
                  subtechnique_id=threat['technique'][0]['subtechnique'][0]['id']
                  subtechnique_name=threat['technique'][0]['subtechnique'][0]['name']
               else:
                  subtechnique_id="none"
                  subtechnique_name="none"

               filtered_object = {'tactic': tactic, 'technique_id': technique_id, "technique_name": technique_name, "subtechnique_id": subtechnique_id, "subtechnique_name": subtechnique_name}
               filtered_object_array.append(filtered_object)
               alert_data[file] = filtered_object_array

mitre_tactic_list = ['none','reconnaissance','resource development','initial access','execution','persistence','privilege escalation','defense evasion','credential access','discovery','lateral movement','collection','command and control','exfiltration','impact']
            
for file in alert_data:
   for line in alert_data[file]:
      tactic=line['tactic'].lower()
      technique_id=line['technique_id']
      subtechnique_id = line['subtechnique_id']

   #print(file+": "+tactic+": "+technique_id+": "+subtechnique_id)
      
      #check to ensure MITRE tactic exists
      if tactic not in mitre_tactic_list:
            print("The MITRE Tactic supplied does not exist: " + "\"" + tactic + "\"" + " in " + file)
            failure = 1
      #check to make sure the MITRE technique ID is valid
      try:
            if mitreMapped[technique_id]:
                pass
                
      except KeyError:
            print("Invalid MITRE Technique ID: " + "\"" + technique_id + "\"" + " in " + file)
            
      
    
        