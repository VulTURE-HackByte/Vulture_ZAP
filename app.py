from flask import Flask, render_template, jsonify, request,redirect
import requests
import time
from zapv2 import ZAPv2
import os
import json

## Initiaize
app = Flask(__name__,static_url_path='/static')
apiKey = ""
zap = ZAPv2(apikey=apiKey)
baseurl="localhost:5000"

def limit_pscan():
    headers = {
    'Accept': 'application/json'
    }
    r = requests.get('http://localhost:8080/JSON/pscan/action/disableAllScanners/', headers = headers)
    print(r.json())
    """
        X-Content-Type-Options (Alert ID: 10021)
        Strict Transport Security Header (Alert ID: 10035)
        Content Security Policy (CSP) Header Not Set (Alert ID: 10038)
        Cookie HttpOnly (Alert ID: 10010)
        CSRF Countermeasures (Alert ID: 100202)
        X-Frame-Options (Alert ID: 10020)
        Cache Control (Alert ID: 10015)
        HTTP Server Response Header (Alert ID: 10036)
        Mixed Content (Alert ID: 10040)
        X-AspNet-Version Response Header (Alert ID: 10061)
    """
    r = requests.get('http://localhost:8080/JSON/pscan/action/enableScanners/', params={'ids': "10021,10035,10038,10010,100202,10020,10015,10036,10040,10061"}, headers = headers)
    print(r.json())
limit_pscan()


def generate_random():
    import string
    import random
    N = 7
    res = ''.join(random.choices(string.ascii_uppercase +
                                 string.digits, k=N))
    return res

def passive_report(target):
    headers = {
        'Accept' : 'application/html'
    }
    name = generate_random()
    r = requests.get('http://localhost:8080/JSON/reports/action/generate/', params={'title': 'Vulture Scan Report',  'template': 'traditional-pdf', 'sites': target, 'reportFileName': name, 'reportDir': '/home/cap2k4/Documents/GitHub/vulture_ZAP/static'}, headers = headers)
    print(r.json())
    return name


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
    data = {'message':'hello'}
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
        url = {'url': baseurl+"/static/"+passive_report(request.args.get('target'))+".pdf"}
        alerts.append(url)
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