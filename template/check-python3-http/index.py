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

def format_notification(event, context, status="RUNNING"):
    return {
            "progress": 1,
            "report": {
                "check_id": event.check_id,
                "checktype_name": event.checktype_name,
                "checktype_version": event.checktype_version,
                "data": event.data,
                "end_time": datetime.utcnow().isoformat()+'Z',
                "error": event.error,
                "notes": event.notes,
                "options": event.check_options,
                "start_time": event.start.isoformat()+'Z',
                "status": status,
                "tag": event.tag,
                "target": event.target,
                "vulnerabilities": event.vulnerabilities
            },
            "status": status
        }

def notify(event, context, status="RUNNING"):
    if event.notify:
        b = format_notification(event, context, status)
        r = requests.patch(event.notify_url, json=b)
        r.status_code

@app.route('/', defaults={'path': ''}, methods=['GET', 'PUT', 'POST', 'PATCH', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'PUT', 'POST', 'PATCH', 'DELETE'])
def call_handler(path):
    event = Event()
    context = Context()

    try:
        event.json = json.loads(event.body)
    except ValueError as err:
        return format_response({
            "statusCode": 400,
            "body": "json decode error: {}".format(err)
        })

    try:
        event.target = event.json["VULCAN_CHECK_TARGET"]
        event.check_id = event.json["VULCAN_CHECK_ID"]
        event.checktype_name = event.json["VULCAN_CHECKTYPE_NAME"]
        event.checktype_version = event.json["VULCAN_CHECKTYPE_VERSION"]
        event.check_options = event.json["VULCAN_CHECK_OPTIONS"]
    except KeyError as err:
        return format_response({
            "statusCode": 400,
            "body": "Missing parameter: {}".format(err)
        })

    if "VULCAN_AGENT_ADDRESS" in event.json:
        event.notify_url = "http://{}/check/{}".format(event.json["VULCAN_AGENT_ADDRESS"], event.check_id)
        event.notify = True
    else:
        event.notify = False

    event.start = datetime.utcnow()
    event.error = None
    event.notes = None
    event.data = None
    event.tag = None
    event.vulnerabilities = []

    notify(event, context)

    response_data = handler.handle(event, context)

    if event.notify:
        notify(event, context, "FINISHED")
    else:
        response_data["body"] = format_notification(event, context, "FINISHED")

    resp = format_response(response_data)
    return resp

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
