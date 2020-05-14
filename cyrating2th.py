#!/usr/bin/env python3
# coding: utf-8

import cyrating
import sys
import os
import json
import logging
import getpass
import argparse
import base64
from io import BytesIO
from config import Cyrating, TheHive
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, CaseObservable, Case
from thehive4py.query import *

from datetime import date
import socket
    

def connection(config):
    """
    returns a cyrating instance with the token

    """
    cr=cyrating.init(token=config.get('api'))
    return cr

def get_events(cr_instance):
    """
    returns the events in a list of dictionaries
    """
    main_company=cr_instance.main_company()
    events=cr_instance.get_events(main_company, assets=cr_instance.get_assets(main_company))
    return events

def th_severity(sev):

    """
    convert Cyrating severity in TH severity

    :param sev: CR severity
    :type sev: string
    :return TH severity
    :rtype: int
    """

    severities = {
        'NONE': 1,
        1: 1,
        2: 1,
        3: 2,
        4: 3,
        5: 3
    }
    return severities[sev]

def add_tags(tags, content):

    """
    add tag to tags
    :param tags: existing tags
    :type tags: list
    :param content: string, mainly like taxonomy
    :type content: string
    """
    t = tags
    for newtag in content:
        t.append("CR:{}".format(newtag))
    return t

def add_case_artifact(artifacts, data_type, data, tags, tlp):
    """
    :param artifacts: array
    :param data_type: string
    :param data: string
    :param tags: array
    :param tlp: int
    :return: array
    :rtype: array
    """

    if data is not None:
        return artifacts.append(CaseObservable(tags=tags,
                                              dataType=data_type,
                                              data=str(data),
                                              message="From Cyrating",
                                              tlp=tlp)
                                )

def init_artifact_tags(content):
    """
    param content:
    type content:
    return: list of tags
    rtype: array
    """

    return ["src:CYRATING",
            "CR:Event",
            "Pole:{}".format(content.get('entities', 'None')),
            "Division:{}".format((content.get('tags')).get('tags'))
            ]

def prepare_artifacts(content):

    """
    param content: Cyrating event
    type content:  array
    return: list AlertArtifact
    rtype: array
    
[{'name': '217.160.0.70', 'type': 'IPv4', 'occurrences': ['Fri, 03 Apr 2020 00:00:00 GMT', 'Thu, 02 Apr 2020 00:00:00 GMT', 'Thu, 09 Apr 2020 00:00:00 GMT'], 'source': {'tag': 'SBL-XBL-SPAMHAUS', 'source_url': None}, 'tags': ['Allemagne'], 'domains': ['baureka.de'], 'entities': ['EUROVIA']}, {'name': '93.17.0.114', 'type': 'IPv4', 'occurrences': ['Thu, 02 Apr 2020 00:00:00 GMT', 'Thu, 09 Apr 2020 00:00:00 GMT'], 'source': {'tag': 'SBL-XBL-SPAMHAUS', 'source_url': None}, 'tags': ['FRANCE'], 'domains': ['grouperobert.fr'], 'entities': ['EUROVIA']}, {'name': '160.153.133.154', 'type': 'IPv4', 'occurrences': ['Fri, 27 Mar 2020 00:00:00 GMT', 'Thu, 09 Apr 2020 00:00:00 GMT', 'Thu, 26 Mar 2020 00:00:00 GMT', 'Fri, 03 Apr 2020 00:00:00 GMT', 'Thu, 02 Apr 2020 00:00:00 GMT'], 'source': {'tag': 'SBL-XBL-SPAMHAUS', 'source_url': None}, 'tags': ['UK'], 'domains': ['islandroads.com'], 'entities': ['EUROVIA']}, {'name': '107.180.27.126', 'type': 'IPv4', 'occurrences': ['Thu, 09 Apr 2020 00:00:00 GMT', 'Thu, 26 Mar 2020 00:00:00 GMT', 'Thu, 12 Mar 2020 00:00:00 GMT', 'Thu, 27 Feb 2020 00:00:00 GMT', 'Thu, 05 Mar 2020 00:00:00 GMT', 'Thu, 02 Apr 2020 00:00:00 GMT'], 'source': {'tag': 'SBL-XBL-SPAMHAUS', 'source_url': None}, 'tags': ['SF - Soletanche Freyssinet', 'Soletanche Bachy'], 'domains': ['mudbaydrilling.com'], 'entities': ['VINCI CONSTRUCTION']}, {'name': '51.140.87.39', 'type': 'IPv4', 'occurrences': ['Fri, 27 Mar 2020 00:00:00 GMT', 'Thu, 09 Apr 2020 00:00:00 GMT', 'Fri, 17 Jan 2020 00:00:00 GMT', 'Fri, 10 Jan 2020 00:00:00 GMT', 'Thu, 09 Jan 2020 00:00:00 GMT', 'Thu, 26 Mar 2020 00:00:00 GMT', 'Fri, 07 Feb 2020 00:00:00 GMT', 'Sat, 23 Nov 2019 00:00:00 GMT', 'Fri, 06 Mar 2020 00:00:00 GMT', 'Wed, 23 Oct 2019 00:00:00 GMT', 'Thu, 05 Mar 2020 00:00:00 GMT', 'Sat, 16 Nov 2019 00:00:00 GMT', 'Thu, 16 Jan 2020 00:00:00 GMT', 'Fri, 03 Apr 2020 00:00:00 GMT', 'Thu, 02 Apr 2020 00:00:00 GMT', 'Thu, 06 Feb 2020 00:00:00 GMT'], 'source': {'tag': 'SBL-XBL-SPAMHAUS', 'source_url': None}, 'tags': ['ANGLETERRE', 'GATWICK', 'VINCI Airports'], 'domains': ['gatwickairport.com'], 'entities': ['VINCI CONCESSIONS', 'VINCI AIRPORTS']}, {'name': '213.186.33.16', 'type': 'IPv4', 'occurrences': ['Fri, 10 Apr 2020 00:00:00 GMT', 'Thu, 09 Apr 2020 00:00:00 GMT'], 'source': {'tag': 'SBL-XBL-SPAMHAUS', 'source_url': None}, 'tags': ['VCIN - VINCI Construction International Network'], 'domains': ['sogea.re'], 'entities': ['VINCI CONSTRUCTION']}, {'name': '160.153.133.146', 'type': 'IPv4', 'occurrences': ['Thu, 09 Apr 2020 00:00:00 GMT'], 'source': {'tag': 'SBL-XBL-SPAMHAUS', 'source_url': None}, 'tags': ['UK'], 'domains': ['hounslowhighways.org'], 'entities': ['EUROVIA']}, {'name': '187.44.179.203', 'type': 'IPv4', 'occurrences': ['Thu, 02 Apr 2020 00:00:00 GMT', 'Thu, 09 Apr 2020 00:00:00 GMT'], 'source': {'tag': 'SBL-XBL-SPAMHAUS', 'source_url': None}, 'tags': ['BRESIL', 'VINCI Airports'], 'domains': ['salvador-airport.com.br'], 'entities': ['VINCI CONCESSIONS', 'VINCI AIRPORTS']}, {'name': 'vasundara.com', 'type': 'Domain', 'occurrences': ['Sat, 06 Jul 2019 00:00:00 GMT', 'Mon, 21 Oct 2019 00:00:00 GMT', 'Thu, 05 Mar 2020 00:00:00 GMT', 'Thu, 26 Mar 2020 00:00:00 GMT', 'Wed, 23 Oct 2019 00:00:00 GMT', 'Sat, 07 Sep 2019 00:00:00 GMT', 'Thu, 06 Feb 2020 00:00:00 GMT', 'Thu, 01 Aug 2019 00:00:00 GMT', 'Sat, 13 Jul 2019 00:00:00 GMT', 'Fri, 09 Aug 2019 00:00:00 GMT', 'Sat, 15 Jun 2019 00:00:00 GMT', 'Thu, 19 Mar 2020 00:00:00 GMT', 'Thu, 27 Feb 2020 00:00:00 GMT', 'Fri, 23 Aug 2019 00:00:00 GMT', 'Fri, 18 Oct 2019 00:00:00 GMT', 'Thu, 02 Apr 2020 00:00:00 GMT', 'Sat, 15 Feb 2020 00:00:00 GMT', 'Thu, 19 Sep 2019 00:00:00 GMT', 'Sun, 20 Oct 2019 00:00:00 GMT', 'Sat, 08 Jun 2019 00:00:00 GMT', 'Thu, 30 Jan 2020 00:00:00 GMT', 'Mon, 09 Sep 2019 00:00:00 GMT', 'Thu, 24 Oct 2019 00:00:00 GMT', 'Fri, 19 Jul 2019 00:00:00 GMT', 'Sat, 29 Jun 2019 00:00:00 GMT', 'Fri, 16 Aug 2019 00:00:00 GMT', 'Thu, 09 Apr 2020 00:00:00 GMT', 'Thu, 12 Mar 2020 00:00:00 GMT', 'Sat, 19 Oct 2019 00:00:00 GMT', 'Thu, 20 Feb 2020 00:00:00 GMT', 'Sun, 14 Jul 2019 00:00:00 GMT', 'Fri, 06 Sep 2019 00:00:00 GMT', 'Sat, 22 Jun 2019 00:00:00 GMT', 'Thu, 12 Sep 2019 00:00:00 GMT', 'Thu, 13 Feb 2020 00:00:00 GMT'], 'source': {'tag': 'DBL-SPAMHAUS', 'source_url': None}, 'tags': [], 'domains': ['vasundara.com'], 'entities': ['VINCI ENERGIES']}, {'name': '115.125.18.32', 'type': 'IPv4', 'occurrences': ['Fri, 20 Mar 2020 00:00:00 GMT', 'Thu, 09 Apr 2020 00:00:00 GMT', 'Thu, 19 Mar 2020 00:00:00 GMT'], 'source': {'tag': 'SBL-XBL-SPAMHAUS', 'source_url': None}, 'tags': ['VINCI Airports', 'ASIE'], 'domains': ['kansai-airports.co.jp'], 'entities': ['VINCI CONCESSIONS', 'VINCI AIRPORTS']}]     
   {'name': '217.160.0.70', 'type': 'IPv4', 'occurrences': ['Fri, 03 Apr 2020 00:00:00 GMT', 'Thu, 02 Apr 2020 00:00:00 GMT', 'Thu, 09 Apr 2020 00:00:00 GMT'], 'source': {'tag': 'SBL-XBL-SPAMHAUS', 'source_url': None}, 'tags': ['Allemagne'], 'domains': ['baureka.de'], 'entities': ['EUROVIA']} 
    
    
    """

    artifacts = []
    try:
        socket.inet_aton(content.get('name'))
        add_case_artifact(artifacts,
                    'ip',
                    content.get('name'),
                    add_tags(["src:CYRATING"], ["Blacklist"]),
                    1)
    # legal
    except socket.error:
        add_case_artifact(artifacts,
                    'domain',
                    content.get('name'),
                    add_tags(["src:CYRATING"], ["Blacklist"]),
                    1)
    
    return artifacts

def th_case_description(content):
    description = "Blacklist from " + content.get('source').get('tag') + '\n'
    description += 'Previous detection \n'
    for a in content.get('occurrences', {}):
        description += "  * " + a + '\n'
    return description

def generate_tags_from_event(content):
    case_tags = ["src:CYRATING"]
    case_tags = add_tags(case_tags, [
        "Entity={}".format(x) for x in content.get("entities", {})
    ])
    case_tags = add_tags(case_tags, [
        "Domain={}".format(x) for x in content.get("domains", {})
    ])
    case_tags = add_tags(case_tags, [
        "Source={}".format(content.get("source").get('tag'))
    ])
    return case_tags

def generate_title_from_event(content):
    return 'Reputation alert from Cyrating for ' + content.get('name')

def prepare_case(content):
    """
    convert a Cyrating alert into a TheHive alert
    :param incident: Cyrating Alert
    :type incident: dict
    :type thumbnails: dict
    :return: Thehive alert
    :rtype: thehive4py.models Alerts
    """
      
    case = Case(title=generate_title_from_event(content),
                  tlp=1,
                  pap=1,
                  tags=generate_tags_from_event(content),
                  severity=th_severity(content.get('severity', 1)),
                  description=th_case_description(content),
                  caseTemplate=TheHive['template'])

    return case


def create_th_case(thapi, event):
    id = None
    
    case = prepare_case(event)
    
    response = thapi.create_case(case)
    
    logging.debug('API TheHive - create_case - status code: {}'.format(
        response.status_code))
    if response.status_code > 299:
        logging.debug('API TheHive - raw error output: {}'.format(
            response.raw.read()))
    id = response.json()['id']

    artifacts = prepare_artifacts(event)
    for artifact in artifacts:
        thapi.create_case_observable(id, artifact)
    logging.debug('API TheHive - create_case_observable - status code: {}'.format(
        response.status_code))
    if response.status_code > 299:
        logging.debug('API TheHive - raw error output: {}'.format(
            response.raw.read()))


def update_case(thapi, case, event):
    
    description = case.get('description') + "\n\n============\n\nIP redetected in Cyrating " + date.today().strftime("%Y-%m-%d") + '\n\n'
    thapi.case.update(case.get('id'), status = 'Open', 
                                 description = description,
                                 tags=generate_tags_from_event(event))



def close_cases_without_alert(thapi, events):
    
    query = And(
        String("title:\"Reputation alert from Cyrating for \""),
        String("status:\"Open\"")
    )
    logging.debug('API TheHive - close_cases_without_alert')
    response = thapi.find_cases(query=query, range='all', sort=[])
    logging.debug('API TheHive - Find case - status code: {}'.format(
            response.status_code))
    if response.status_code > 299:
        logging.debug('API TheHive - raw error output: {}'.format(
            response.raw.read()))
    cases = response.json()
    for c in cases:
        found = False
        for e in events:
            if (c.get('title') == generate_title_from_event(e)):
                found = True
                break
        if (found):
            continue

        thapi.case.update(c.get('id'), status = 'Resolved',
                         resolutionStatus = 'Indeterminate',
                         impactStatus  = 'NotApplicable',
                         summary = 'No more detection on Cyrating',
                         endDate = date.today())


def process_events(config, events):
    """
    process events returned by cyrating
    """
    thapi = TheHiveApi(config.get('url', None),
                        config.get('key'),
                        config.get('password', None),
                        config.get('proxies'))
    
    for a in events:
        print("Working with " + a.get('name'))
        query = And(
            String("title:\"Reputation alert from Cyrating for \""),
            Child('case_artifact', And(
                Eq('data', a.get('name'))
            ))
        )
        #query = String("title:\"Reputation alert from Cyrating for \"" + generate_title_from_event(a) + "\"")
        logging.debug('API TheHive - case: {}'.format(a.get('name')))
        response = thapi.find_cases(query=query, range='all', sort=[])
        logging.debug('API TheHive - Find case - status code: {}'.format(
                response.status_code))
        if response.status_code > 299:
            logging.debug('API TheHive - raw error output: {}'.format(
                response.raw.read()))
            continue
        case = response.json()
        
        if len(case) == 0:
            print("Create new case")
            create_th_case(thapi, a)
        else:
            print("Previous cases found - updating")
            for c in case:
                print(" - " + c.get('id') + " (" + c.get('title') + ")")
                update_case(thapi, c, a)

    print("Closing old alerts")
    close_cases_without_alert(thapi, events)
    print("Done")
    

def run():

    """
        Download Cyrating alerts and create a new alert in TheHive
    """
    
    def alerts(args):
        cyapi = connection(Cyrating)
        events = get_events(cyapi)
        process_events(TheHive, events)
        
    parser = argparse.ArgumentParser(description="Retrieve Cyrating \
                                     events and feed them to TheHive")
    parser.add_argument("-d", "--debug",
                        action='store_true',
                        default=False,
                        help="generate a log file and active \
                              debug logging")
    subparsers = parser.add_subparsers(help="subcommand help")
  
    parser_alerts = subparsers.add_parser("alert", help="parse the Cyrating reputation")
    parser_alerts.set_defaults(func=alerts)


    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()
    
    args = parser.parse_args()
    
    if args.debug:
        logging.basicConfig(filename='{}/cyrating2th.log'.format(
                                os.path.dirname(os.path.realpath(__file__))),
                            level='DEBUG', format='%(asctime)s\
                                                   %(levelname)s\
                                                   %(message)s')
    args.func(args)


if __name__ == '__main__':
    run()