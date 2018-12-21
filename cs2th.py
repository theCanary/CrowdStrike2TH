#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import getopt
import argparse
import datetime
from io import BytesIO
import base64
import logging
import json


from CrowdStrike.api import CrowdStrikeApi
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

from config import CrowdStrike, TheHive


def th_severity(max_severity_displayname):

    """
    convert CrowdStrike severity into TheHive severity

    :param max_severity_displayname: CrowdStrike severity
    :type max_severity_displayname: string
    :return TheHive severity
    :rtype: int
    """

    severities = {
        'Low': 1,
        'Medium': 2,
        'High': 3,
        'Critical': 3,
    }
    return severities[max_severity_displayname]


def th_datatype(type):

    """
    Convert CrowdStrike IOCs to TH dataType
    :param type: CS type
    :type type: string
    :return: TH dataType
    :rtype: str
    """

    types = {
        'parent_md5': 'hash',
        'parent_sha256': 'hash',
        'filename': 'filename',
        'sha256': 'hash',
        'md5': 'hash',
        'cmdline': 'other',
        'local_ip': 'ip',
        'external_ip': 'ip'
    }

    if isinstance(type, dict):
        return "other"

    if type in types:
        return types[type]
    else:
        return "other"


def add_alert_artefact(artefacts, dataType, data, tags, tlp):

    """
    :type artefacts: array
    :type dataType: string
    :type data: string
    :type tags: array
    :type tlp: int
    :rtype: array
    """

    return artefacts.append(AlertArtifact(tags=tags,
                                          dataType=dataType,
                                          data=data,
                                          message="From CrowdStrike",
                                          tlp=tlp))


def build_observables(observables, device_id):

    """
    Convert CrowdStrike behaviors into TheHive observables
    :param observables: behaviors from CrowdStrike
    :type observables: dict
    :return: AlertArtifact
    :rtype: thehive4py.models AlertArtifact
    """

    observables = flatten_dict(observables)

    artefacts = []

    for observable_key, observable_value in observables.items():
        # print(observable_key, 'corresponds to', observable_value)
        a = AlertArtifact(
            data=observable_value,
            dataType=th_datatype(observable_value),
            message="Observable from CrowdStrike. \
                Device ID: {}".format(device_id),
            tlp=2,
            tags=["src:CrowdStrike"]
        )
    return a


def build_alert(detection, id):

    """
    Convert CrowdStrike Falcon alert into TheHive Alerts

    :param detection: Detection from CrowdStrike Alert
    :type detection: dict
    :param observables: observables from CrowdStrike Alert
    :type observables: dict
    :return: TheHive alert
    :rtype: thehive4py.models Alerts
    """

    meta = detection['data']['meta']
    resources = detection['data']['resources'][0]
    status = detection['status']
    behaviors = resources['behaviors'][0]
    device = resources['device']
    detection_title = '{} {} {} {}'.format(
        'CROWDSTRIKE ALERT - ', resources.get('max_severity_displayname'),
        'Severity', behaviors['scenario'].replace("_", " "))

    tlp = 2

    artifacts = [
        AlertArtifact(dataType='filename',
                      data=behaviors.get('filename'),
                      message="File name of the triggering process"),
        AlertArtifact(dataType='hash',
                      data=behaviors.get('sha256'),
                      tags=['sha256'],
                      message="SHA256 of the triggering process",
                      ioc=True),
        AlertArtifact(dataType='other',
                      data=behaviors.get('user_name'),
                      tags=['target-user'],
                      message="The user's name",
                      tlp=3),
        AlertArtifact(dataType='other',
                      data=behaviors.get('user_id'),
                      message="Users SID in Windows",
                      tlp=3),
        AlertArtifact(dataType='hash',
                      data=behaviors.get('md5'),
                      tags=['md5'],
                      message="MD5 of the triggering process",
                      ioc=True),
        AlertArtifact(dataType='other',
                      data=behaviors.get('cmdline'),
                      message="Command Line of the triggering process"),
        AlertArtifact(dataType='other',
                      data=behaviors.get('ioc_source'),
                      message="Source that triggered an IOC detection"),
        AlertArtifact(dataType=th_datatype(behaviors.get('ioc_type')),
                      data=behaviors.get('ioc_value'),
                      message="ioc_value",
                      ioc=True),
        AlertArtifact(dataType='other',
                      data=device.get('hostname'),
                      tags=['target-machine'],
                      message="Device hostname"),
        AlertArtifact(dataType='ip',
                      data=device.get('local_ip'),
                      tags=['host-ip'],
                      message="Hosts local ip.",
                      tlp=3),
        AlertArtifact(dataType='ip',
                      data=device.get('external_ip'),
                      tags=['external-ip'],
                      message="Hosts external ip.")
    ]
    a = Alert(
        title='{} {} {}'.format(
            detection_title,
            'on',
            device.get('hostname')),
        tlp=2,
        severity=th_severity(resources.get(
            'max_severity_displayname')),
        type="FalconHost Alert",
        tags=[
            "CrowdStrike:Scenario={}".format(
                behaviors['scenario'].replace("_", " ").title()),
            "CrowdStrike:Max Confidence={}".format(
                resources.get('max_confidence')),
            "CrowdStrike:Max Severity={}".format(
                resources.get('max_severity')),
            device.get('machine_domain'),
            device.get('hostname'),
            device.get('local_ip'),
            behaviors.get('user_name'),
            behaviors.get('tactic'),
            behaviors.get('technique')
            ],
        caseTemplate=TheHive['template'],
        source="CrowdStrike",
        sourceRef=id,
        artifacts=artifacts,
        # Switch description to named parameters?
        description="{0} {1} {2} {3} {4} {5} {6}".format(
                    "#### **" + detection_title + 'on ' + device.get('hostname') + "**",
                    "\n\n --- \n",
                    "#### **SUMMARY**\n\n",
                    "{0} {1} {2} {3} {4} {5} {6} {7}".format(
                        "- **SCENARIO: **" + behaviors.get('scenario') + "\n",
                        "- **SEVERITY: **" + resources.get('max_severity_displayname') + "\n",
                        "- **DETECT TIME: **" + behaviors.get('timestamp') + "\n",
                        "- **HOST: **" + device.get('hostname') + "\n",
                        "- **HOST IP: **" + device.get('local_ip') + "\n",
                        "- **USERNAME: **" + behaviors.get('user_name') + "\n",
                        "- **TACTIC: **" + behaviors.get('tactic') + "\n",
                        "- **TECHNIQUE: **" + behaviors.get('technique') + "\n",
                    ),
                    "\n\n --- \n",
                    "#### **DETECTION DETAILS**\n\n",
                    "{0} {1} {2}".format(
                        "```\n",
                        json.dumps(detection, indent=4, sort_keys=True),
                        "\n```",
                    ),
                )
           )
    return a


def find_detections(csapi, since):

    """
    :param csapi: CrowdStrike.api.CrowdStrikeApi
    :param since: number of minutes
    :type since: int
    :return: list of thehive4py.models Alerts
    :rtype: array
    """

    detections = csapi.find_detection(UtcNow(since))

    if detections.get('status') == 'success':
        event_count = detections['data']['meta']['pagination']['total']
        if event_count > 0:
            detection_ids = detections['data']['resources']
            for id in detection_ids:
                x = '{{"ids":["{}"]}}'.format(id)
                detection_details = csapi.find_detection_details(x)
                a = build_alert(detection_details, id)
                create_thehive_alerts(TheHive, a)


def create_thehive_alerts(config, alerts):

    """
    :param config: TheHive config
    :type config: dict
    :param alerts: List of alerts
    :type alerts: list
    :return: create TH alert
    """

    thapi = TheHiveApi(config.get('url', None), config.get('key'), config.get('password', None),
                       config.get('proxies'))

    response = thapi.create_alert(alerts)
    if response.status_code == 201:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))


def UtcNow(delta):

    """
    :param delta: timesince delta
    :type delta: int
    :return: delta
    """

    delta = datetime.datetime.utcnow() - datetime.timedelta(minutes=delta)
    return (repr(delta.strftime("%Y-%m-%dT%H:%M")))


def run():

    """
    Download CrowdStrike incident and create a new alert in TheHive
    """

    def find(args):
        if 'last' in args and args.last is not None:
            last = args.last.pop()

        if (not args.i ^ args.I) or args.i:
            alerts = find_detections(csapi, last)

        if args.monitor:
            mon = monitoring("{}/cs2th.status".format(
                os.path.dirname(os.path.realpath(__file__))))
            mon.touch()

    parser = argparse.ArgumentParser(
        description="Get CrowdStrike FalconHost alerts and create a case in \
        TheHive.")
    parser.add_argument("-d", "--debug",
                        action='store_true',
                        default=False,
                        help="generate a log file and active debug logging")
    subparsers = parser.add_subparsers(help="subcommand help")

    parser_find = subparsers.add_parser('find',
                                        help="find alerts in time")
    parser_find.add_argument("-l", "--last",
                             metavar="M",
                             nargs=1,
                             type=int, required=True,
                             help="get all alerts published during\
                              the last [M] minutes")
    parser_find.add_argument("-m", "--monitor",
                             action='store_true',
                             default=False,
                             help="active monitoring")
    parser_find.add_argument("-i",
                             action='store_true',
                             default=False,
                             help="get intel incidents only")
    parser_find.add_argument("-I",
                             action='store_true',
                             default=False,
                             help="get high and critical incidents only")
    parser_find.set_defaults(func=find)

    if len(sys.argv[1:]) == 0:
        parser.print_help()
        parser.exit()
    args = parser.parse_args()

    csapi = CrowdStrikeApi(CrowdStrike)
    args.func(args)


if __name__ == '__main__':
    run()
