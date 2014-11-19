#!/usr/bin/env python
#
# Copyright 2014 Martin J Chorley
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import hmac
import uuid
import time
import json
import copy
import base64
import threading

import urllib.request
import urllib.parse

from hashlib import sha1
from datetime import datetime

from _credentials import *


class Twitter_API:

    def __init__(self):

        # URL for accessing API
        scheme = "https://"
        api_url = "api.twitter.com"
        version = "1.1"

        self.api_base = scheme + api_url + "/" + version

        #
        # seconds between queries to each endpoint
        # queries in this project limited to 180 per 15 minutes
        query_interval = float(15 * 60)/(175)

        #
        # rate limiting timer
        self.__monitor = {'wait':query_interval,
                               'earliest':None,
                               'timer':None}


    #
    # rate_controller puts the thread to sleep 
    # if we're hitting the API too fast
    def __rate_controller(self, monitor_dict):

        # 
        # join the timer thread
        if monitor_dict['timer'] is not None:
            monitor_dict['timer'].join()  

            # sleep if necessary
            while time.time() < monitor_dict['earliest']:
                time.sleep(monitor_dict['earliest'] - time.time())
            
        # work out then the next API call can be made
        earliest = time.time() + monitor_dict['wait']
        timer = threading.Timer( earliest-time.time(), lambda: None )
        monitor_dict['earliest'] = earliest
        monitor_dict['timer'] = timer
        monitor_dict['timer'].start()

    # 
    # make the signature for the API request
    def get_signature(self, method, url, params):
        
        # escape special characters in all parameter keys
        encoded_params = {}
        for k, v in params.items():
            encoded_k = urllib.parse.quote_plus(str(k))
            encoded_v = urllib.parse.quote_plus(str(v))
            encoded_params[encoded_k] = encoded_v 

        # sort the parameters alphabetically by key
        sorted_keys = sorted(encoded_params.keys())

        # create a string from the parameters
        signing_string = ""

        count = 0
        for key in sorted_keys:
            signing_string += key
            signing_string += "="
            signing_string += encoded_params[key]
            count += 1
            if count < len(sorted_keys):
                signing_string += "&"

        # construct the base string
        base_string = method.upper()
        base_string += "&"
        base_string += urllib.parse.quote_plus(url)
        base_string += "&"
        base_string += urllib.parse.quote_plus(signing_string)

        # construct the key
        signing_key = urllib.parse.quote_plus(client_secret) + "&" + urllib.parse.quote_plus(access_secret)

        # encrypt the base string with the key, and base64 encode the result
        hashed = hmac.new(signing_key.encode(), base_string.encode(), sha1)
        signature = base64.b64encode(hashed.digest())
        return signature.decode("utf-8")


    def query_get(self, endpoint, aspect, get_params={}):
        
        #
        # rate limiting
        self.__rate_controller(self.__monitor)

        # ensure we're dealing with strings as parameters
        str_param_data = {}
        for k, v in get_params.items():
            str_param_data[str(k)] = str(v)

        # construct the query url
        url = self.api_base + "/" + endpoint + "/" + aspect + ".json"
        
        # add the header parameters for authorisation
        header_parameters = {
            "oauth_consumer_key": client_id,
            "oauth_nonce": uuid.uuid4(),
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": time.time(),
            "oauth_token": access_token,
            "oauth_version": 1.0
        }

        # collect all the parameters together for creating the signature
        signing_parameters = {}
        for k, v in header_parameters.items():
            signing_parameters[k] = v
        for k, v in str_param_data.items():
            signing_parameters[k] = v

        # create the signature and add it to the header parameters
        header_parameters["oauth_signature"] = self.get_signature("GET", url, signing_parameters)

        # add the OAuth headers
        header_string = "OAuth "
        count = 0
        for k, v in header_parameters.items():
            header_string += urllib.parse.quote_plus(str(k))
            header_string += "=\""
            header_string += urllib.parse.quote_plus(str(v))
            header_string += "\""
            count += 1
            if count < 7:
                header_string += ", "

        headers = {
            "Authorization": header_string
        }

        # create the full url including parameters
        url = url + "?" + urllib.parse.urlencode(str_param_data)
        request = urllib.request.Request(url, headers=headers)

        # make the API request
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as e:
            print(e)
            raise e
        except urllib.error.URLError as e:
            print(e)
            raise e

        # read the response and return the json
        raw_data = response.read().decode("utf-8")
        return json.loads(raw_data)


if __name__ == "__main__":

    ta = Twitter_API()
    params = {"screen_name" : "martinjc"}
    print(ta.query_get("users", "lookup", params))

