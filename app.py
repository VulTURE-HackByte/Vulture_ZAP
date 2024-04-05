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