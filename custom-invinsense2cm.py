#!/usr/bin/env python
# स्वामित्वम् (C) 2015-2020, Infopercept Consulting.
# निर्मितम् Infopercept Consulting द्वारा <info@infopercept.com>
# Infopercept Consulting सम्पत्तिः
# अयं कार्यक्रमः मुक्तसॉफ्टवेयरम् अस्ति; भवान् एतत् पुनर्वितरणं परिवर्तनं वा कर्तुं शक्नोति GPLv2 नियमानुसारम्

import json
import sys
import os
import re
import logging
import uuid
from thehive4py.api import TheHiveApi as CaseManagementApi
from thehive4py.models import Alert, AlertArtifact

# ossec.conf संरचना:
#  <integration>
#    <name>custom-w2cm</name>
#    <hook_url>http://localhost:9000</hook_url>
#    <api_key>123456790</api_key>
#    <alert_format>json</alert_format>
#  </integration>


# उपयोक्तृ-संरचना-आरम्भः

# वैश्विक-चरणानि

# siem नियमस्तरस्य सीमा
lvl_threshold=0
# suricata नियमस्तरस्य सीमा
suricata_lvl_threshold=3

debug_enabled = False
# निर्मित-सूचनायाः विषये सूचना
info_enabled = True

# उपयोक्तृ-संरचना-समाप्तिः

# मार्गाः स्थापयन्तु
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
logger = logging.getLogger(__name__)
# लॉगिंग-स्तरं स्थापयन्तु
logger.setLevel(logging.WARNING)
if info_enabled:
    logger.setLevel(logging.INFO)
if debug_enabled:
    logger.setLevel(logging.DEBUG)
# लॉगिंग-फाइल-हैंडलर निर्माणम्
fh = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)



def main(args):
    logger.debug('# मुख्य-कार्यक्रम-आरम्भः')
    logger.debug('# सूचना-फाइल-स्थानं प्राप्नुहि')
    alert_file_location = args[1]
    logger.debug('# Case Management url प्राप्नुहि')
    cm_url = args[3]
    logger.debug('# Case Management api कुञ्जी प्राप्नुहि')
    cm_api_key = args[2]
    cm_api = CaseManagementApi(cm_url, cm_api_key)
    logger.debug('# सूचना-फाइलं उद्घाटयतु')
    w_alert = json.load(open(alert_file_location))
    logger.debug('# सूचना-दत्तांशः')
    logger.debug(str(w_alert))
    logger.debug('# json बिन्दु-कुञ्जी-पाठे परिवर्तनम्')
    alt = pr(w_alert,'',[])
    logger.debug('# विवरणस्य स्वरूपणम्')
    format_alt = md_format(alt)
    logger.debug('# कलाकृतीनां अन्वेषणम्')
    artifacts_dict = artifact_detect(format_alt)
    alert = generate_alert(format_alt, artifacts_dict, w_alert)
    logger.debug('# सीमा-छननम्')
    if w_alert['rule']['groups']==['ids','suricata']:
        # data.alert.severity क्षेत्रस्य अस्तित्वं परीक्षते
        if 'data' in w_alert.keys():
            if 'alert' in w_alert['data']:
                # स्रोत-घटनायाः स्तरं परीक्षते
                if int(w_alert['data']['alert']['severity'])<=suricata_lvl_threshold:
                    send_alert(alert, cm_api)
    elif int(w_alert['rule']['level'])>=lvl_threshold:
        # यदि घटना suricata तः भिन्ना अस्ति तथा suricata-event-type: alert तर्हि lvl_threshold परीक्षते
        send_alert(alert, cm_api)


def pr(data,prefix, alt):
    for key,value in data.items():
        if hasattr(value,'keys'):
            pr(value,prefix+'.'+str(key),alt=alt)
        else:
            alt.append((prefix+'.'+str(key)+'|||'+str(value)))
    return alt



def md_format(alt,format_alt=''):
    md_title_dict = {}
    # प्रथम-कुञ्जीना सह क्रमबद्धम्
    for now in alt:
        now = now[1:]
        # प्रथम-कुञ्जीयाः अन्तिम-चिह्नं निश्चितं करोतु
        dot = now.split('|||')[0].find('.')
        if dot==-1:
            md_title_dict[now.split('|||')[0]] =[now]
        else:
            if now[0:dot] in md_title_dict.keys():
                (md_title_dict[now[0:dot]]).append(now)
            else:
                md_title_dict[now[0:dot]]=[now]
    for now in md_title_dict.keys():
        format_alt+='### '+now.capitalize()+'\n'+'| key | val |\n| ------ | ------ |\n'
        for let in md_title_dict[now]:
            key,val = let.split('|||')[0],let.split('|||')[1]
            format_alt+='| **' + key + '** | ' + val + ' |\n'
    return format_alt


def artifact_detect(format_alt):
    artifacts_dict = {}
    artifacts_dict['ip'] = re.findall(r'\d+\.\d+\.\d+\.\d+',format_alt)
    artifacts_dict['url'] =  re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',format_alt)
    artifacts_dict['domain'] = []
    for now in artifacts_dict['url']: artifacts_dict['domain'].append(now.split('//')[1].split('/')[0])
    return artifacts_dict


def generate_alert(format_alt, artifacts_dict,w_alert):
    # सूचना sourceRef निर्माणम्
    sourceRef = str(uuid.uuid4())[0:6]
    artifacts = []
    if 'agent' in w_alert.keys():
        if 'ip' not in w_alert['agent'].keys():
            w_alert['agent']['ip']='no agent ip'
    else:
        w_alert['agent'] = {'id':'no agent id', 'name':'no agent name'}

    for key,value in artifacts_dict.items():
        for val in value:
            artifacts.append(AlertArtifact(dataType=key, data=val))
    alert = Alert(title=w_alert['rule']['description'],
              tlp=2,
              tags=['siem', 
              'rule='+w_alert['rule']['id'], 
              'agent_name='+w_alert['agent']['name'],
              'agent_id='+w_alert['agent']['id'],
              'agent_ip='+w_alert['agent']['ip'],],
              description=format_alt ,
              type='siem_alert',
              source='siem',
              sourceRef=sourceRef,
              artifacts=artifacts,)
    return alert




def send_alert(alert, cm_api):
    response = cm_api.create_alert(alert)
    if response.status_code == 201:
        logger.info('Case created in CM: '+ str(response.json()['id']))
    else:
        logger.error('Error creating case in CM: {}/{}'.format(response.status_code, response.text))



if __name__ == "__main__":
    
    try:
       logger.debug('debug mode') # यदि debug सक्रियः       
       # मुख्य-कार्यम्
       main(sys.argv)

    except Exception:
       logger.exception('EGOR')
