#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import requests


class CrowdStrikeApi():
    """
    Python API to interact with the CrowdStrike Query API
    """


    def __init__(self, config):
        """
        Python API for CrowdStrike Query APIs
        :param config: CrowdStrike configuration from config.py
        :type config: dict
        """

        self.url = config['url']
        self.user = config['cs_user']
        self.key = config['cs_key']
        self.proxies = config['proxies']
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.auth = (self.user, self.key)


    @classmethod
    def response(cls, status, content):

        """
        :param status: str = success/failure
        :type status: string
        :paran content: data to return
        :type content: dict
        :return:
        :rtype: dict
        """

        return {'status':status, 'data': content}


    def find_detection(self, timesince, status="'new'"):

        """
        Get CrowdStrike FalconHost alerts
        :type status: text
        :return: requests response
        :rtype: requests.get
        """
        print(self.url + '/detects/queries/detects/v1?filter=status:' + status + '%2Blast_behavior:>' + timesince)
        req = self.url + '/detects/queries/detects/v1?filter=status:' + status + '%2Blast_behavior:>' + timesince

        #print(req)

        headers = self.headers
        try:
            resp = requests.get(req, headers=headers, auth=self.auth)
            if resp.status_code == 200:
                return self.response("success", resp.json())
            return self.response("failure", resp.json())
        except requests.exceptions.RequestException as exc:
            print("Error: {}".format(exc))


    def find_detection_details(self, detection_id):

        """
        Fetch CrowdStsrike Falcon detections since last `since` minutes
        :param detection_id: Detection ID
        :type id: string
        :return: requests response
        :rtype: requests.get
        """

        req = self.url + '/detects/entities/summaries/GET/v1'

        headers = self.headers
        try:
            resp = requests.post(req, headers=headers, auth=self.auth, data=detection_id)
            if resp.status_code == 200:
                return self.response("success", resp.json())
            return self.response("failure", resp.json())
        except requests.exceptions.RequestException as exc:
            print("Error: {}".format(exc))
