from flask import Flask, render_template, jsonify, request

import time
from zapv2 import ZAPv2

app = Flask(__name__)
apiKey = ""
zap = ZAPv2(apikey=apiKey)

def spider_scan(target):
    scanID = zap.spider.scan(target)
    while int(zap.spider.status(scanID)) < 100:
        time.sleep(1)
    response = zap.spider.results(scanID)
    return response

def passive_scan(target):
    spider_response = spider_scan(target)    
    for i in range(3):
        zap.pscan.records_to_scan
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
    try:
        if(request.form['target']):
            data = {'result': spider_scan(request.form['target'])}
            return jsonify(data)
    except:
        return jsonify({})

@app.route('/passive')
def passive():
    try:
        if(request.form['target']):
            alerts = list(passive_scan(request.form['target']))
            return jsonify(alerts)
    except:
        return jsonify({})

@app.route('/active')
def active():
    try:
        if(request.form['target']):
            alerts = active_scan(request.form['target'])
            return jsonify(alerts)
    except:
        return jsonify({})
