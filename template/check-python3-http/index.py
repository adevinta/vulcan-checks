#!/usr/bin/env python
from flask import Flask, request, jsonify
from waitress import serve
from datetime import datetime
import requests
import json
import os

from function import handler

app = Flask(__name__)

class Event:
    def __init__(self):
        self.body = request.get_data()
        self.headers = request.headers
        self.method = request.method
        self.query = request.args
        self.path = request.path

class Context:
    def __init__(self):
        self.hostname = os.getenv('HOSTNAME', 'localhost')

def format_status_code(resp):
    if 'statusCode' in resp:
        return resp['statusCode']
    
    return 200

def format_body(resp):
    if 'body' not in resp:
        return ""
    elif type(resp['body']) == dict:
        return jsonify(resp['body'])
    else:
        return str(resp['body'])

def format_headers(resp):
    if 'headers' not in resp:
        return []
    elif type(resp['headers']) == dict:
        headers = []
        for key in resp['headers'].keys():
            header_tuple = (key, resp['headers'][key])
            headers.append(header_tuple)
        return headers
    
    return resp['headers']

def format_response(resp):
    if resp == None:
        return ('', 200)

    statusCode = format_status_code(resp)
    body = format_body(resp)
    headers = format_headers(resp)

    return (body, statusCode, headers)

def notify(event, context, status="RUNNING"):
    json= event.json
    b= {
            "progress": 1,
            "report": {
                "check_id": json["VULCAN_CHECK_ID"],
                "checktype_name": json["VULCAN_CHECKTYPE_NAME"],
                "checktype_version": json["VULCAN_CHECKTYPE_VERSION"],
                "data": event.data,
                "end_time": datetime.utcnow().isoformat()+'Z',
                "error": event.error,
                "notes": event.notes,
                "options": json["VULCAN_CHECK_OPTIONS"],
                "start_time": event.start.isoformat()+'Z',
                "status": status,
                "tag": event.tag,
                "target": json["VULCAN_CHECK_TARGET"],
                "vulnerabilities": event.vulnerabilities
            },
            "status": status
        }

    url = "http://{}/check/{}".format(json["VULCAN_AGENT_ADDRESS"], json["VULCAN_CHECK_ID"])
    r = requests.patch(url, json=b)
    r.status_code

@app.route('/', defaults={'path': ''}, methods=['GET', 'PUT', 'POST', 'PATCH', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'PUT', 'POST', 'PATCH', 'DELETE'])
def call_handler(path):
    event = Event()
    context = Context()

    event.json = json.loads(event.body)
    event.start = datetime.utcnow()
    event.error = None
    event.notes = None
    event.data = None
    event.tag = None
    event.vulnerabilities = []

    notify(event, context)

    response_data = handler.handle(event, context)
    
    notify(event, context, "FINISHED")

    resp = format_response(response_data)
    return resp

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
