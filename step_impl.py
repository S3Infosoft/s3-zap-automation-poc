from getgauge.python import step, before_scenario, Messages, data_store
from zapv2 import ZAPv2 as ZAP
import subprocess
import os
import requests
from time import sleep
import datetime
import pprint 

zap_proxy = {"apikey":"apikey", "http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"}
zap = ZAP(proxies=zap_proxy)
apikey= 'apikey'

# --------------------------
# Gauge step implementations
# --------------------------


requests.exceptions.ProxyError: HTTPConnectionPool(host='127.0.0.1', port=8080): Max retries exceeded with 
url: http://zap/JSON/spider/action/scan/?apikey=api.key&url=target_url
(Caused by ProxyError('Cannot connect to proxy.', NewConnectionError('<urllib3.connection.HTTPConnection object at 
0x101be78e0>: Failed to establish a new connection: [Errno 61] Connection refused')))





@step("Start ZAP and Open URL <target_url>")
def zap_open_url(target_url):
    cmd = "zap.sh -config  -port {0}".format(
        8090
    )
    subprocess.Popen(cmd.split(" "), stdout=open(os.devnull, "w"))
    while True:
        try:
            status_req = requests.get("http://127.0.0.1:8090")
            if status_req.status_code == 200:
                break
        except Exception:
            pass
    zap.urlopen(target_url)
    sleep(3)

@step("Login to <url> with username <username> and password <password>")
def login(url, username, password):
    login = requests.post(
        url, proxies=zap_proxy, json={"username": username, "password": password}
    )
    if login.status_code == 200:
        auth_token = login.headers["Authorization"]
        data_store.spec.token = auth_token
        print(data_store.spec.token)
        
@step("Run spider against target <target_url>")
def zap_spider_target(target_url,auth_token):
    spider_id = zap.spider.scan(target_url,auth_token)
    data_store.spec.spider_id = spider_id


@step("Get spider status")
def spider_status():
    while int(zap.spider.status(data_store.spec["spider_id"])) < 100:
        print(
            "Spider running at {}%".format(
                int(zap.spider.status(data_store.spec["spider_id"]))
            )
        )
        sleep(5)



@step("Run Ajax spidering")
print('Ajax Spider target {}'.format(target_url,auth_token))
scanID = zap.ajaxSpider.scan(target_url,auth_token)

timeout = time.time() + 60*2   # 2 minutes from now
# Loop until the ajax spider has finished or the timeout has exceeded
while zap.ajaxSpider.status == 'running':
    if time.time() > timeout:
        break
    print('Ajax Spider status' + zap.ajaxSpider.status)
    time.sleep(2)

print('Ajax Spider completed')
ajaxResults = zap.ajaxSpider.results(start=0, count=10)



@step("Run Pasive scan")
while int(zap.pscan.records_to_scan) > 0:
    # Loop until the passive scan has finished
    print('Records to passive scan : ' + zap.pscan.records_to_scan)
    time.sleep(2)

print('Passive Scan completed')

# Print Passive scan results/alerts
print('Hosts: {}'.format(', '.join(zap.core.hosts)))
print('Alerts: ')
pprint(zap.core.alerts())



@step("Start Active Scan against <target_url>")
def zap_active_scan(target_url):
    scan_id = zap.ascan.scan(target_url, scanpolicyname="default")
    data_store.spec.scan_id = scan_id
    sleep(4)



@step("Get Active Scan status")
def ascan_status():
    while int(zap.ascan.status(data_store.spec["scan_id"])) < 100:
        print(
            "Active Scan running at {}%".format(
                int(zap.ascan.status(data_store.spec["scan_id"]))
            )
        )
        sleep(5)
        
@step("Get acsrf tokens")        
require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'X-ZAP-API-Key' => 'apikey'
}

result = RestClient.get 'http://zap/JSON/acsrf/view/optionTokensNames/',
  params: {
  }, headers: headers

p JSON.parse(result)

@step("Get parameters name")
headers = {
  'Accept': 'application/json',
  'X-ZAP-API-Key': 'apikey'
}

r = requests.get('http://zap/JSON/params/view/params/', params={

}, headers = headers)

print r.json()

require 'rest-client'
require 'json'

headers = {
  'Accept' => 'application/json',
  'X-ZAP-API-Key' => 'apikey'
}

result = RestClient.get 'http://zap/JSON/params/view/params/',
  params: {
  }, headers: headers

p JSON.parse(result)

@step("run active scan against each parameter")
params=result.message
scanID = zap.ascan.scan(target,params)
while int(zap.ascan.status(scanID)) < 100:
    # Loop until the scanner has finished
    print('Scan progress %: {}'.format(zap.ascan.status(scanID)))
    time.sleep(5)
    
@step("Get alerts on cli")
st = 0
pg = 5000
alert_dict = {}
alert_count = 0
alerts = zap.alert.alerts(baseurl=target, start=st, count=pg)
blacklist = [1,2]
while len(alerts) > 0:
    print('Reading ' + str(pg) + ' alerts from ' + str(st))
    alert_count += len(alerts)
    for alert in alerts:
        plugin_id = alert.get('pluginId')
        if plugin_id in blacklist:
            continue
        if alert.get('risk') == 'High':
            # Trigger any relevant postprocessing
            continue
        if alert.get('risk') == 'Informational':
            # Ignore all info alerts - some of them may have been downgraded by security annotations
            continue
    st += pg
    alerts = zap.alert.alerts(start=st, count=pg)
print('Total number of alerts: ' + str(alert_count))



@step("Export ZAP Report for <app_name> in <format> format with <filename> for <company_name> with <report_title>")
def export_zap_report(app_name, format, filename, company_name, report_title):
    url = "http://127.0.0.1:8090/JSON/exportreport/action/generate/"
    report_time = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
    source_info = "{0};{1};ZAP Team;{2};{3};v1;v1;{4}".format(
        report_title, "Author", report_time, report_time, report_title
    )
    alert_severity = "t;t;t;t"  # High;Medium;Low;Info
    alert_details = "t;t;t;t;t;t;t;t;t;t"  # CWEID;#WASCID;Description;Other Info;Solution;Reference;Request Header;Response Header;Request Body;Response Body
    data = {
        "absolutePath": filename,
        "fileExtension": format,
        "sourceDetails": source_info,
        "alertSeverity": alert_severity,
        "alertDetails": alert_details,
    }

    r = requests.post(url, data=data)
    if r.status_code == 200:
        print("Report generated")
        pass
    else:
        print("Unable to generate report")
        raise Exception("Unable to generate report")



@step("Shutdown ZAP")
def stop_zap():
    zap.core.shutdown()


