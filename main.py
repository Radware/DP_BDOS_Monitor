import config as cfg
import json
from vision import Vision
import bdos_parser
import urllib3
import logging_helper
import sys
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#Arguments variables
getdatafromvision = True
alarm = True
test_email_alarm = False
report = []

reports_path = "./Reports/"
raw_data_path = "./Raw Data/"
requests_path = "./Requests/"

if not os.path.exists('log'):
	os.makedirs('log')

if not os.path.exists('Raw Data'):
	os.makedirs('Raw Data')

if not os.path.exists('Reports'):
	os.makedirs('Reports')

logging_helper.log_setup(cfg.LOG_FILE_PATH, cfg.SYSLOG_SERVER, cfg.SYSLOG_PORT)


for i in sys.argv:
	#Running script with arguments
	

	if i.lower() == "--use-cache-data":
		#No data collection from vision- running script using previously collected data
		getdatafromvision = False
		logging_helper.logging.info('Running script using cache data only')
		
	if i.lower() == "--no-alarm":
		#Run script without sending email alert.
		alarm = False
		logging_helper.logging.info('Running script without email alarm')

	if i.lower() == "--test-alarm":
		#Run script- test email alert only
		logging_helper.logging.info('Running script to test email alarm only')
		getdatafromvision = False
		test_email_alarm = True
		nobdosreport = True
		nodpconfigparsing = True


def getBDOSReportFromVision():

	bdos_dict = {}

	for dp_ip,dp_attr in full_pol_dic.items():
		bdos_dict[dp_ip] = {}
		bdos_dict[dp_ip]['Name'] = dp_attr['Name']
		bdos_dict[dp_ip]['BDOS Report'] = []

		if not dp_attr['Policies']:
			continue
		for pol_attr in dp_attr['Policies']['rsIDSNewRulesTable']:
			if pol_attr["rsIDSNewRulesProfileNetflood"] != "" and pol_attr["rsIDSNewRulesName"] != "null" and pol_attr["rsIDSNewRulesProfileNetflood"] != "null" and pol_attr['rsIDSNewRulesState'] != "2":
				bdos_report = v.getBDOSTrafficReport(dp_ip,pol_attr,full_net_dic)
				bdos_dict[dp_ip]['BDOS Report'].append(bdos_report)

	with open(raw_data_path + 'BDOS_traffic_report.json', 'w') as outfile:
		json.dump(bdos_dict,outfile)
	
	return

def getDNSReportFromVision():

	dns_dict = {}

	for dp_ip,dp_attr in full_pol_dic.items():
		dns_dict[dp_ip] = {}
		dns_dict[dp_ip]['Name'] = dp_attr['Name']
		dns_dict[dp_ip]['DNS Report'] = []

		if not dp_attr['Policies']:
			continue
		for pol_attr in dp_attr['Policies']['rsIDSNewRulesTable']:
			if pol_attr["rsIDSNewRulesProfileDNS"] != "" and pol_attr["rsIDSNewRulesName"] != "null" and pol_attr["rsIDSNewRulesProfileDNS"] != "null" and pol_attr['rsIDSNewRulesState'] != "2":
				dns_report = v.getDNStrafficReport(dp_ip,pol_attr,full_net_dic)
				dns_dict[dp_ip]['DNS Report'].append(dns_report)

	with open(raw_data_path + 'DNS_traffic_report.json', 'w') as outfile:
		json.dump(dns_dict,outfile)
	
	return


if not getdatafromvision:
	#If Script run with argument "--use-cache-data"
	with open(raw_data_path + 'full_pol_dic.json') as full_pol_dic_file:
		full_pol_dic = json.load(full_pol_dic_file)
	with open(raw_data_path + 'full_net_dic.json') as full_net_dic_file:
		full_net_dic = json.load(full_net_dic_file)


if getdatafromvision:
	v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)
	
	full_pol_dic = v.getFullPolicyDictionary()
	full_net_dic = v.getFullNetClassDictionary()

	getBDOSReportFromVision()
	getDNSReportFromVision()


if not test_email_alarm:
	report = report + bdos_parser.parse()


if test_email_alarm:
	report = ['test']

if alarm:
	logging_helper.send_report(report)