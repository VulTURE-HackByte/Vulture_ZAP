import requests
import time
from zapv2 import ZAPv2
from utils_common import generate_random

def spider_scan(target):
    try:
        scanID = zap.spider.scan(target)
        while int(zap.spider.status(scanID)) < 100:
            time.sleep(1)
        Results = zap.spider.results(scanID)
        return Results
    except:
        return ""

def ajax_spider_scan(target):
    try:
        scanID = zap.ajaxSpider.scan(target)
        timeout = time.time() + 60*2
        while zap.ajaxSpider.status == 'running':
            if time.time() > timeout:
                break
            time.sleep(2)
        ajaxResults = zap.ajaxSpider.results(scanID)
        return ajaxResults
    except:
        return ""

def passive_scan(target):
    try:
        spider_scan(target)
        while int(zap.pscan.records_to_scan) > 0:
            time.sleep(2)
        response = zap.core.alerts()
        total_list = []
        for i in response:
            temp = dict()
            temp["alert"] = i["alert"]
            temp["risk"] = i["risk"]
            temp["confidence"] = i["confidence"]
            total_list.append(temp)
        unique_dict = {v["alert"]: v for v in total_list}.values()
        return unique_dict
    except:
        return None

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
    unique_dict = {v["alert"]: v for v in total_list}.values()
    return unique_dict

def limit_pscan():
    headers = {"Accept": "application/json"}
    try:
        res = requests.get(
            "http://localhost:8080/JSON/pscan/action/disableAllScanners/",
            headers=headers,
        )
        """
	        Information Leakage 10044
	        Cross-Site Scripting (XSS) 10031
	        Content Security Policy (CSP) Violations 10055
	        Cross-Origin Resource Sharing (CORS) Issues 10098
	        Information Disclosure: Suspicious Comments 10027
	        Directory Listing 10033
	        Server Leaks Information via “X-Powered-By” HTTP Response Header Field(s) 10037
	    """
        res = requests.get(
            "http://localhost:8080/JSON/pscan/action/enableScanners/",
            params={"ids": "10044,10031,10055,10098,10027,10033,10037"},
            headers=headers,
        )
        return res.json()
    except Exception as e:
    	print(e)
    	return None

def limit_ascan():
    headers = {"Accept": "application/json"}
    try:
        res = requests.get(
            "http://localhost:8080/JSON/ascan/action/disableAllScanners/",
            headers=headers,
        )
        """
	        .env Information Leak 40034
	        .htaccess Information Leak 40032
	        Code Injection 90019
	        Cross Site Scripting (Reflected) 40012
	        SQL Injection 40018
	    """
        res = requests.get(
            "http://localhost:8080/JSON/ascan/action/enableScanners/",
            params={"ids": "40034,40032,90019,40012,40018"},
            headers=headers,
        )
        return res.json()
    except:
        return None

def report(target):
    headers = {"Accept": "application/html"}
    name = generate_random()
    try:
        requests.get(
            "http://localhost:8080/JSON/reports/action/generate/",
            params={
                "title": "Vulture Scan Report",
                "template": "traditional-pdf",
                "sites": target,
                "reportFileName": name,
                "reportDir": "/home/ubuntu/vulture_ZAP/static",
            },
            headers=headers,
        )
        return name
    except:
        return None