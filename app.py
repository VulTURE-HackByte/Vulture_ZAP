from flask import Flask, render_template, jsonify, request, redirect
from utils_zap import spider_scan, ajax_spider_scan, passive_scan, active_scan
from utils_zap import limit_pscan, limit_ascan, report

app = Flask(__name__,static_url_path='/static')
zap = ZAPv2(apikey="")
baseurl = "localhost"

limit_pscan()
limit_ascan()

@app.route('/')
def index():
    return jsonify({'message':'hello'})

@app.route('/spider')
def spider():
    if(request.form['target']):
        target = request.form['target']
        try:
            return jsonify({'result': spider_scan(target)})
        except: continue
    return jsonify({'message':'No target found'})

@app.route('/ajaxspider')
def ajax_spider():
    if(request.form['target']):
        target = request.form['target']
        try:
            return jsonify({'result': ajax_spider_scan(target)})
        except: continue
    return jsonify({'message':'No target found'})

@app.route('/passive')
def passive():
    if(request.form['target']):
        target = request.form['target']
        try:
            alerts = list(passive_scan(target))
            url = {'url': baseurl+"/static/"+report(target)+".pdf"}
            alerts.append(url)
            return jsonify(alerts)
        except: continue
    return jsonify({'message':'No target found'})

@app.route('/active')
def active():
    if(request.form['target']):
        target = request.form['target']
        try:
            alerts = list(active_scan(target))
            url = {'url': baseurl+"/static/"+report(target)+".pdf"}
            alerts.append(url)
            return jsonify(alerts)
        except: continue
    return jsonify({'message':'No target found'})

if __name__ == '__main__':
    app.run()
