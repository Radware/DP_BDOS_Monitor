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

reports_path = cfg.REPORTS_PATH
raw_data_path = cfg.RAW_DATA_PATH
requests_path = cfg.REQUESTS_PATH

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
		

	if i.lower() == "--test-alarm":
		#Run script- test email alert only
		logging_helper.logging.info('Running script to test email alarm only')
		getdatafromvision = False
		test_email_alarm = True
		nobdosreport = True
		nodpconfigparsing = True


def get_data_from_vision(dev_ip,dev_attr,cust_id= 'None'):

	global full_pol_dic
	global full_net_dic
	global bdos_stats_dict
	global bdos_stats_dict_pps
	global dns_stats_dict

	print(f'Collecting policies data from Defensepro {dev_ip}')
	logging_helper.logging.info(f'Collecting policies data from Defensepro {dev_ip}')
	full_pol_dic = v.getFullPolicyDictionary(dev_ip,dev_attr,full_pol_dic)


	print(f'Collecting network classes data from Defensepro {dev_ip}')
	logging_helper.logging.info(f'Collecting network classes data from Defensepro {dev_ip}')
	full_net_dic = v.getFullNetClassDictionary(dev_ip,dev_attr,full_net_dic)


	print(f'Collecting BDOS stats data from Defensepro {dev_ip}')
	logging_helper.logging.info('Collecting BDOS stats data')
	bdos_stats_dict = v.getBDOSReportFromVision(dev_ip,dev_attr,full_pol_dic,full_net_dic,bdos_stats_dict,cust_id)
	
	print(f'Collecting BDOS PPS stats data from Defensepro {dev_ip}')
	logging_helper.logging.info('Collecting BDOS PPS stats data')
	bdos_stats_dict_pps = v.getBDOSReportFromVision_PPS(dev_ip,dev_attr,full_pol_dic,full_net_dic,bdos_stats_dict_pps,cust_id)
	
	print(f'Collecting DNS stats data from Defensepro {dev_ip}')
	logging_helper.logging.info('Collecting DNS stats data')
	dns_stats_dict = v.getDNSReportFromVision(dev_ip,dev_attr,full_pol_dic,full_net_dic,dns_stats_dict,cust_id)
	
	print('-' * 25)



def dpconfig_cleanup():
	# For every file  in config_path and Raw_Data, delete it

	for file in os.listdir(raw_data_path):
		os.remove(raw_data_path + file)

	for file in os.listdir(reports_path):
		os.remove(reports_path + file)


if not getdatafromvision: #If Script run with argument "--use-cache-data" - script will only parse data from cache

	with open(raw_data_path + 'full_pol_dic.json') as full_pol_dic_file:
		full_pol_dic = json.load(full_pol_dic_file)
	with open(raw_data_path + 'full_net_dic.json') as full_net_dic_file:
		full_net_dic = json.load(full_net_dic_file)


else: # If Script run without argument "--use-cache-data" - script will collect data from vision and parse it

	full_pol_dic = {}
	full_net_dic = {}
	bdos_stats_dict = {}
	bdos_stats_dict_pps = {}
	dns_stats_dict = {}

	print('Cleaning up previous DP config files')
	logging_helper.logging.info('Cleaning up previous DP config files')
	dpconfig_cleanup()

	print('Starting data collection from DefensePro')
	print('-' * 50)


	if cfg.CUSTOMERS_JSON: #If customers.json is set to true, use this file to define the scope for the data collection
		print('CUSTOMERS_JSON is set to True - collecting data using the scope from customers.json file')

		if not cfg.CUSTOMERS_JSON_CUST_ID_LIST:	# if CUSTOMERS_JSON_CUST_ID_LIST is empty, collect all customers
			print('CUSTOMERS_JSON_CUST_ID_LIST is not defined - collecting data for all customers from customers.json file')
			print('-' * 25)
		else:
			print(f'CUSTOMERS_JSON_CUST_ID_LIST is defined - collecting data for customers {cfg.CUSTOMERS_JSON_CUST_ID_LIST}')
			print('-' * 25)

		with open(cfg.CUSTOMERS_JSON_PATH+ "customers.json") as customers_file:
			customers = json.load(customers_file)
			
			for customer in customers:
				cust_id = customer['id']

				if not cfg.CUSTOMERS_JSON_CUST_ID_LIST: #If CUSTOMERS_JSON_CUST_ID_LIST is empty, collect all customers
		
					vision_user = customer['user']
					vision_pass = customer['pass']

					for vision_params in customer['visions']:

						vision_ip = vision_params['ip']

						dp_list = vision_params['dps'].split(',')

						v = Vision(vision_ip, vision_user, vision_pass)

						for dev_ip, dev_val in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId
							if dev_ip in dp_list:
								
								get_data_from_vision(dev_ip,dev_val,cust_id)


				else: #If CUSTOMERS_JSON_CUST_ID_LIST is not empty, collect only the customers defined in the list	
					if cust_id in cfg.CUSTOMERS_JSON_CUST_ID_LIST:
						vision_user = customer['user']
						vision_pass = customer['pass']

						for vision_params in customer['visions']:

							vision_ip = vision_params['ip']
							dp_list = vision_params['dps'].split(',')

							v = Vision(vision_ip, vision_user, vision_pass)

							for dev_ip, dev_val in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId
								if dev_ip in dp_list:

									get_data_from_vision(dev_ip, dev_val,cust_id)

	else: #If customers.json is set to false, use the scope defined in config.py variable "DP_IP_SCOPE_LIST"
		print('CUSTOMERS_JSON is set to False - collecting data using the scope from DP_IP_SCOPE_LIST')

		v = Vision(cfg.VISION_IP, cfg.VISION_USER, cfg.VISION_PASS)

		if not cfg.DP_IP_SCOPE_LIST: #If DP_IP_SCOPE_LIST is empty, collect all policies for all DefensePro
			print('DP_IP_SCOPE_LIST is not defined - collecting data from all DefensePro in Vision')
			print('-' * 25)

			for dev_ip, dev_val in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId

				get_data_from_vision(dev_ip, dev_val)
			

		else: #If DP_IP_SCOPE_LIST is defined (not empty), collect all policies for the DefensePro in the list
			print(f'DP_IP_SCOPE_LIST is defined - collecting data from specific DefensePro from the list {cfg.DP_IP_SCOPE_LIST}')
			print('-' * 25)

			for dev_ip, dev_val in v.device_list.items(): #key - DP IP, val - DP Attributes - Type, Name, Version, OrmId

				if dev_ip in cfg.DP_IP_SCOPE_LIST:	

					get_data_from_vision(dev_ip, dev_val)

				else:
					print(f'Skipping data collection for Defensepro {dev_ip} - {dev_val["Name"]}. Not in DP_IP_SCOPE_LIST')
					print('-' * 25)


	with open(raw_data_path + 'full_pol_dic.json', 'w') as full_pol_dic_file:
		json.dump(full_pol_dic,full_pol_dic_file)

	with open(raw_data_path + 'full_net_dic.json', 'w') as full_net_dic_file:
		json.dump(full_net_dic,full_net_dic_file)

	with open(raw_data_path + 'BDOS_traffic_report.json', 'w') as outfile:
		json.dump(bdos_stats_dict,outfile)

	with open(raw_data_path + 'BDOS_traffic_report_PPS.json', 'w') as outfile:
		json.dump(bdos_stats_dict_pps,outfile)

	with open(raw_data_path + 'DNS_traffic_report.json', 'w') as outfile:
		json.dump(dns_stats_dict,outfile)

	print('Data collection is complete')
	print('-' * 50)
	logging_helper.logging.info('Data collection is complete')

if not test_email_alarm:
	report = report + bdos_parser.parse()


if test_email_alarm:
	report = ['test']

if cfg.SMTP:
	logging_helper.send_report(report)