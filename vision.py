import config as cfg
from requests import Session
import requests
import json
import time
from logging_helper import logging


reports_path = cfg.REPORTS_PATH
raw_data_path = cfg.RAW_DATA_PATH
requests_path = cfg.REQUESTS_PATH

class Vision:

	def __init__(self, ip, username, password):
		self.ip = ip
		self.login_data = {"username": username, "password": password}
		self.base_url = "https://" + ip
		self.sess = Session()
		self.sess.headers.update({"Content-Type": "application/json"})
		self.login()
		self.device_list = self.getDeviceList()
		self.report_duration = self.epochTimeGenerator(cfg.DURATION)
		self.time_now = int(time.time())*1000
		self.vision_ver = cfg.VISION_VER

		with open(requests_path + 'BDOStrafficRequest.json') as outfile:
			self.BDOSformatRequest = json.load(outfile)
		with open(requests_path + 'DNStrafficRequest.json') as dnstrafficrequest:
			self.DNSformatRequest = json.load(dnstrafficrequest)
	

	def login(self):
		logging.info('Start connecting to Vision')
		login_url = self.base_url + '/mgmt/system/user/login'
		try:
			r = self.sess.post(url=login_url, json=self.login_data, verify=False)
			r.raise_for_status()
			response = r.json()
		except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError,requests.exceptions.SSLError,requests.exceptions.Timeout,requests.exceptions.ConnectTimeout,requests.exceptions.ReadTimeout) as err:
			logging.info(str(err))
			raise SystemExit(err)

		if response['status'] == 'ok':
			self.sess.headers.update({"JSESSIONID": response['jsessionid']})
			# print("Auth Cookie is:  " + response['jsessionid'])
		else:
			logging.info('Vision Login error: ' + response['message'])
			exit(1)

	def getDeviceList(self):
		# Returns list of DP with mgmt IP, type, Name
		devices_url = self.base_url + '/mgmt/system/config/itemlist/alldevices'
		r = self.sess.get(url=devices_url, verify=False)
		json_txt = r.json()

		dev_list = {item['managementIp']: {'Type': item['type'], 'Name': item['name'],
			'Version': item['deviceVersion'], 'ormId': item['ormId']} for item in json_txt if item['type'] == "DefensePro"}

		with open(raw_data_path + 'full_dev_list.json', 'w') as full_dev_list_file:
			json.dump(dev_list,full_dev_list_file)

		return dev_list
		
	def epochTimeGenerator(self,days):
		current_time = time.time()
		daysInSeconds = 86400 * days
		return (int(current_time) - daysInSeconds) * 1000

	

	def getPolicyListByDevice(self, dp_ip):
		# Returns policies list with all its attributes
		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsIDSNewRulesTable"
		# URL params ?count=1000&props=rsIDSNewRulesName
		r = self.sess.get(url=policy_url, verify=False)
		policy_list = r.json()

		if policy_list.get("status") == "error":
			logging.info("Policies list get error. DefensePro IP: " + dp_ip + ". Error message: " + policy_list['message'])
			return []

		return policy_list

	def getNetClassListByDevice(self, dp_ip):
		#Returns Network Class list with networks

		policy_url = self.base_url + "/mgmt/device/byip/" + \
			dp_ip + "/config/rsBWMNetworkTable/"
		r = self.sess.get(url=policy_url, verify=False)
		net_list = r.json()
		
		if net_list.get("status") == "error":
			logging.info("Network class get error. DefensePro IP: " + dp_ip + ". Error message: " + net_list['message'])
			return []
		return net_list	

	def getBDOSTrafficReport(self,pol_dp_ip,pol_attr,net_list):
		pol_name = pol_attr["rsIDSNewRulesName"]
		pol_src_net = pol_attr["rsIDSNewRulesSource"]
		pol_dst_net = pol_attr["rsIDSNewRulesDestination"]

		if self.vision_ver < 4.83:
			url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/BDOS_BASELINE_RATE_REPORTS' #pre 4.83 Vision
		else:
			url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/BDOS_BASELINE_RATE_HOURLY_REPORTS' #4.83 Vision
		BDOS_portocols = ['udp','tcp-syn','tcp-syn-ack','tcp-rst','tcp-ack-fin','tcp-frag','udp-frag','icmp','igmp']
		
		self.BDOSformatRequest['criteria'][5]['upper'] = self.time_now
		self.BDOSformatRequest['criteria'][5]['lower'] = self.report_duration
		self.BDOSformatRequest['criteria'][6]["filters"][0]['filters'][0]['value'] = pol_dp_ip
		self.BDOSformatRequest['criteria'][6]["filters"][0]['filters'][1]["filters"][0]["value"] = pol_name 
		self.BDOSformatRequest['criteria'][0]['value'] = 'true' # default IPv4 true

		
		
		ipv6 = False
		ipv4 = False
		
		bdosReportList = []
		
		for net_dp_ip, dp_attr in net_list.items():

			if dp_attr == ([]):
				#if unreachable do not perform other tests
				continue
			
			if net_dp_ip == pol_dp_ip:
				

				for netcl in dp_attr['rsBWMNetworkTable']: #for each netclass element
					net_name = netcl['rsBWMNetworkName']
					net_addr = netcl['rsBWMNetworkAddress']
					#print(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name}')  
					if net_name == pol_src_net and net_name != "any":
						if ":" in net_addr:
							ipv6 = True
							# logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - src net is IPv6')  
							# self.BDOSformatRequest['criteria'][0]['value'] = 'false'
							
						if "." in net_addr:
							ipv4 = True
							# logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - src net is IPv4')  
							# self.BDOSformatRequest['criteria'][0]['value'] = 'true'			

					if net_name == pol_dst_net and net_name != "any":
						if ":" in net_addr:
							ipv6 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - dst net is IPv6')
							# self.BDOSformatRequest['criteria'][0]['value'] = 'false'
							
						if "." in net_addr:
							ipv4 = True
							#logging.info(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - dst net is IPv4')  
							# self.BDOSformatRequest['criteria'][0]['value'] = 'true'								
						
	
		for protocol in BDOS_portocols:

			self.BDOSformatRequest['criteria'][1]["value"] = protocol
			
			if ipv6:
				#print(f'dp ip is {net_dp_ip},policy {pol_name}, network {net_name} - IPv6')  

				self.BDOSformatRequest['criteria'][0]['value'] = 'false'
				r = self.sess.post(url = url, json = self.BDOSformatRequest , verify=False)

				jsonData = json.loads(r.text)

				if jsonData['data'] == ([]): #Empty response
					# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					empty_resp = [{'row': {'response': 'empty', 'protection': protocol}}]
					# print(f'Printing empty resp ipv6 - {empty_resp}')
					bdosReportList.append(empty_resp)

					# print(f'{pol_dp_ip}, policy {pol_name} - executing IPv6 query')
				else:
					bdosReportList.append(jsonData['data'])

			if ipv4:
			
				self.BDOSformatRequest['criteria'][0]['value'] = 'true'
				r = self.sess.post(url = url, json = self.BDOSformatRequest , verify=False)
				jsonData = json.loads(r.text)
				
				if jsonData['data'] == ([]): #Empty response
					# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					empty_resp = [{'row': {'response': 'empty', 'protection': protocol}}]
					# print(f'Printing empty resp ipv6 - {empty_resp}')
					bdosReportList.append(empty_resp)

				# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					# print(f'{pol_dp_ip}, policy {pol_name} - executing IPv4 query')
				else:
					bdosReportList.append(jsonData['data'])

		bdosTrafficReport = {pol_name:bdosReportList}
		
		return bdosTrafficReport

################DNS Query############################

	def getDNStrafficReport(self,pol_dp_ip,pol_attr,net_list):

		pol_name = pol_attr["rsIDSNewRulesName"]
		pol_src_net = pol_attr["rsIDSNewRulesSource"]
		pol_dst_net = pol_attr["rsIDSNewRulesDestination"]

		url = f'https://{self.ip}/mgmt/monitor/reporter/reports-ext/DNS_BASELINE_RATE_REPORTS'  
		DNS_protocols = ['dns-a','dns-aaaa',"dns-mx","dns-text","dns-soa","dns-srv","dns-ptr","dns-naptr","dns-other"]
		
		self.DNSformatRequest['criteria'][5]['upper'] = self.time_now
		self.DNSformatRequest['criteria'][5]['lower'] = self.report_duration
		self.DNSformatRequest['criteria'][6]["filters"][0]['filters'][0]['value'] = pol_dp_ip
		self.DNSformatRequest['criteria'][6]["filters"][0]['filters'][1]["filters"][0]["value"] = pol_name 
		
		ipv6 = False
		ipv4 = False
		
		dnsReportList = []

		for net_dp_ip, dp_attr in net_list.items():
			if dp_attr == ([]):
				#if unreachable do not perform other tests
				continue

			if net_dp_ip == pol_dp_ip:

				for netcl in dp_attr['rsBWMNetworkTable']: #for each netclass element
					net_name = netcl['rsBWMNetworkName']
					net_addr = netcl['rsBWMNetworkAddress']
					
					if net_name == pol_src_net and net_name != "any":
						if ":" in net_addr:
							ipv6 = True
		
						if "." in net_addr:
							ipv4 = True		

					if net_name == pol_dst_net and net_name != "any":
						if ":" in net_addr:
							ipv6 = True
							
						if "." in net_addr:
							ipv4 = True							
						
		for protocol in DNS_protocols:

			self.DNSformatRequest['criteria'][1]["value"] = protocol

			if ipv6:
						
				self.DNSformatRequest['criteria'][0]['value'] = 'false'
				r = self.sess.post(url = url, json = self.DNSformatRequest , verify=False)
				jsonData = json.loads(r.text)
				
				if jsonData['data'] == ([]): #Empty response
					# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					empty_resp = [{'row': {'response': 'empty', 'protection': protocol}}]
					# print(f'Printing empty resp ipv6 - {empty_resp}')
					dnsReportList.append(empty_resp)

					# print(f'{pol_dp_ip}, policy {pol_name} - executing IPv6 query')
				else:
					dnsReportList.append(jsonData['data'])

			if ipv4:

				self.DNSformatRequest['criteria'][0]['value'] = 'true'
				
				r = self.sess.post(url = url, json = self.DNSformatRequest , verify=False)
				jsonData = json.loads(r.text)
				
				if jsonData['data'] == ([]): #Empty response
					# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					empty_resp = [{'row': {'response': 'empty', 'protection': protocol}}]
					# print(f'Printing empty resp ipv6 - {empty_resp}')
					dnsReportList.append(empty_resp)

				# print(f'{pol_dp_ip},{pol_name},{protocol},{jsonData}')
					# print(f'{pol_dp_ip}, policy {pol_name} - executing IPv4 query')
				else:
					dnsReportList.append(jsonData['data'])

		dnsTrafficReport = {pol_name:dnsReportList}
		
		return dnsTrafficReport

	def getFullPolicyDictionary(self,key, val, full_pol_dic):
		# Create Full Policies list with attributes dictionary per DefensePro


		full_pol_dic[key] = {}
		full_pol_dic[key]['Name'] = val['Name']
		full_pol_dic[key]['Version'] = val['Version']
		full_pol_dic[key]['Policies'] = self.getPolicyListByDevice(key)
		
		return full_pol_dic


	def getFullNetClassDictionary(self,key, val, full_net_dic):
		# Create Full Network class profile list with networks dictionary per DefensePro
		
		if self.getNetClassListByDevice(key) == ([]): #If DefensePro is unreachable
			full_net_dic[key]['rsBWMNetworkTable'] = []
			full_net_dic[key]['Name'] = val['Name']

		else:

			full_net_dic[key] = self.getNetClassListByDevice(key)
			full_net_dic[key]['Name'] = val['Name']
			
		return full_net_dic
	

	def getBDOSReportFromVision(self,full_pol_dic,full_net_dic,bdos_stats_dict):


		for dp_ip,dp_attr in full_pol_dic.items():
			bdos_stats_dict[dp_ip] = {}
			bdos_stats_dict[dp_ip]['Name'] = dp_attr['Name']
			bdos_stats_dict[dp_ip]['BDOS Report'] = []

			if not dp_attr['Policies']:
				continue
			for pol_attr in dp_attr['Policies']['rsIDSNewRulesTable']:
				if pol_attr["rsIDSNewRulesProfileNetflood"] != "" and pol_attr["rsIDSNewRulesProfileNetflood"] != "null" and pol_attr["rsIDSNewRulesName"] != "null" and pol_attr['rsIDSNewRulesState'] != "2":
					bdos_report = self.getBDOSTrafficReport(dp_ip,pol_attr,full_net_dic)
					bdos_stats_dict[dp_ip]['BDOS Report'].append(bdos_report)

		return bdos_stats_dict
	

	def getDNSReportFromVision(self,full_pol_dic,full_net_dic,dns_stats_dict):

		for dp_ip,dp_attr in full_pol_dic.items():
			dns_stats_dict[dp_ip] = {}
			dns_stats_dict[dp_ip]['Name'] = dp_attr['Name']
			dns_stats_dict[dp_ip]['DNS Report'] = []

			if not dp_attr['Policies']:
				continue
			for pol_attr in dp_attr['Policies']['rsIDSNewRulesTable']:
				if pol_attr["rsIDSNewRulesProfileDNS"] != "" and pol_attr["rsIDSNewRulesProfileDNS"] != "null" and pol_attr["rsIDSNewRulesName"] != "null" and pol_attr['rsIDSNewRulesState'] != "2":
					dns_report = self.getDNStrafficReport(dp_ip,pol_attr,full_net_dic)
					dns_stats_dict[dp_ip]['DNS Report'].append(dns_report)

		return dns_stats_dict