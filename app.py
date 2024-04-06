from flask import Flask, render_template, jsonify, request
import requests
import time
from zapv2 import ZAPv2

## Initiaize
app = Flask(__name__)
apiKey = ""
zap = ZAPv2(apikey=apiKey)

def limit_pscan():
    headers = {
    'Accept': 'application/json'
    }
    r = requests.get('http://localhost:8080/JSON/pscan/action/disableAllScanners/', headers = headers)
    print(r.json())
    """
        Information Leakage 10044
        Cross-Site Scripting (XSS) 10031
        Content Security Policy (CSP) Violations 10055
        Cross-Origin Resource Sharing (CORS) Issues 10098
        Information Disclosure: Suspicious Comments 10027
        Directory Listing 10033
        Server Leaks Information via “X-Powered-By” HTTP Response Header Field(s) 10037
    """
    r = requests.get('http://localhost:8080/JSON/pscan/action/enableScanners/', params={'ids': "10044,10031,10055,10098,10027,10033,10037"}, headers = headers)
    print(r.json())
limit_pscan()

def limit_ascan():
    headers = {
    'Accept': 'application/json'
    }
    r = requests.get('http://localhost:8080/JSON/ascan/action/disableAllScanners/', headers = headers)
    print(r.json())
    """
        .env Information Leak 40034
        .htaccess Information Leak 40032
        Code Injection 90019
        Cross Site Scripting (Reflected) 40012
        SQL Injection 40018
    """
    r = requests.get('http://localhost:8080/JSON/ascan/action/enableScanners/', params={'ids': "40034,40032,90019,40012,40018"}, headers = headers)
    print(r.json())
limit_ascan()

def spider_scan(target):
    scanID = zap.spider.scan(target)
    while int(zap.spider.status(scanID)) < 100:
        time.sleep(1)
    response = zap.spider.results(scanID)
    return response

def passive_scan(target):
    spider_response = spider_scan(target)    
    while int(zap.pscan.records_to_scan) > 0:
        print('Records to passive scan : ' + zap.pscan.records_to_scan)
        time.sleep(2)
    response = zap.core.alerts()
    total_list = []
    for i in response:
        temp = dict()
        temp["alert"] = i["alert"]
        temp["risk"] = i["risk"]
        temp["confidence"] = i["confidence"]
        total_list.append(temp)
    unique_dict = {v['alert']:v for v in total_list}.values()
    return unique_dict

def active_scan(target):
    scanID = zap.ascan.scan(target)
    while int(zap.ascan.status(scanID)) < 3:
        time.sleep(5)
    response = zap.core.alerts(baseurl=target)
    total_list = []
    for i in response:
        temp = dict()
        temp["alert"] = i["alert"]
        temp["risk"] = i["risk"]
        temp["confidence"] = i["confidence"]
        total_list.append(temp)
    unique_dict = {v['alert']:v for v in total_list}.values()
    return unique_dict


@app.route('/')
def index():
    data = {'data':'hello'}
    return jsonify(data)

@app.route('/spider')
def scan_route():
    if(request.args.get('target')):
            data = {'result': spider_scan(request.args.get('target'))}
            return jsonify(data)
    else:
        return jsonify({})

@app.route('/passive')
def passive():
    
    if(request.args.get('target')):
            alerts = list(passive_scan(request.args.get('target')))
            return jsonify(alerts)
    else:
        return jsonify({})

@app.route('/active')
def active():
    if(request.args.get('target')):
        print(request.args.get('target'))
        alerts = list(active_scan(request.args.get('target')))
        return jsonify(alerts)
    else:
        return jsonify({})
