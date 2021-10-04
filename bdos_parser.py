import json
import csv
import glob
from logging_helper import logging
import os
import config as cfg

reports_path = "./Reports/"
raw_data_path = "./Raw Data/"
requests_path = "./Requests/"
	
def parse():
	#Parses BDOS raw json data and Creates 2 reports "low_bdos_baselines.csv" and "high_bdos_baselines.csv"


	report = []

	# Creates empty csv files with headers
	with open(reports_path + 'low_bdos_baselines.csv', mode='w', newline="") as low_bdos_baselines:
		low_bdos_baselines = csv.writer(low_bdos_baselines, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		low_bdos_baselines.writerow(['DefensePro Name' , 'DefensePro IP' ,	'Policy' , 'Traffic type' ,	'No of times exceeded' , 'Exceed average ratio', 'Details'])

	with open(reports_path + 'high_bdos_baselines.csv', mode='w', newline="") as high_bdos_baselines:
		high_bdos_baselines = csv.writer(high_bdos_baselines, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		high_bdos_baselines.writerow([f'DefensePro IP' , f'DefensePro Name', f'Policy', f'Protocol' , f'Throughput average(Mbps)', f'Normal Baselin(Mbps)' , f'Delta from average traffic to Normal baseline in Mbps' , f'Average traffic ratio from baseline in %'])


	ParseBDOSStats(ParseBDOSRawReport())
		#ParseBDOSRawReport() function parses BDOS_traffic_report.json raw JSON data, counts all the occurances where the actual traffic utilization was above the Virtual baselines and creates another dictionary "final_report"
		#ParseBDOSStats() function parses "final_report" which is dictioinary with all the occurances where the actual traffic utilization was above the Virtual baselines created by ParseBDOSRawReport() function.

	if os.path.exists(raw_data_path + 'DNS_traffic_report.json'):
		ParseDNSStats(ParseDNSRawReport())
			#ParseDNSRawReport() function parses DNS_traffic_report.json raw JSON data, counts all the occurances where the actual traffic utilization was above the Virtual baselines and creates another dictionary "final_dns_report"
			#ParseDNSStats() function parses "final_report" which is dictioinary with all the occurances where the actual traffic utilization was above the Virtual baselines created by ParseDNSRawReport() function.

	
	report.append(reports_path + 'low_bdos_baselines.csv')
	report.append(reports_path + 'high_bdos_baselines.csv')

	return report


def ParseBDOSRawReport():
	
	final_report = {}

	with open(raw_data_path + 'BDOS_traffic_report.json') as json_file:
		bdos_dict = json.load(json_file)


	for dp_ip,dp_ip_attr in bdos_dict.items():
		ratio = cfg.DET_MARGIN_RATIO
		dp_name = dp_ip_attr['Name']
		final_report[dp_ip] = {}
		final_report[dp_ip]['Name'] = dp_name
		final_report[dp_ip]['Policies'] = {}
		
	
		for policy_attr_obj in dp_ip_attr['BDOS Report']: # policy_attr_obj = {"pol_dmz_prod": [[{"row": {"deviceIp": "10.107.129.209", "normal": "184320.0", "fullExcluded": "-1.0", "policyName": "pol_dmz_prod", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isIpv4": "true", "units": "bps", "timeStamp": "1620141600000", "fast": null, "id": null, "partial": "0.0", "direction": "In", "full": "0.0"}}
			for policy, pol_attr in policy_attr_obj.items(): #pol_attr is [[{"row": {"deviceIp": "10.160.207.116", "normal": "23033.0", "policyName": "FW_VPN", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isIpv4": "true", "units": "bps", "timeStamp": "1620145200000", "fast": "0.0", "id": null, "partial": "0.0", "direction": "In", "full": "0.0"}}, {"row": {"deviceIp": "10.160.207.116", "normal": "23033.0", "policyName": "FW_VPN", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isI
				notrafficstats = 0
				nonormalbaseline = 0
				flags = {"udp":[0,0],"tcp-syn":[0,0],"tcp-syn-ack":[0,0],"tcp-rst":[0,0],"tcp-ack-fin":[0,0],"tcp-frag":[0,0],"udp-frag":[0,0],"icmp":[0,0],"igmp":[0,0]} #First element is number of occurances the traffic exceeded the virtual baseline, second is the average exceeding ratio
				final_report[dp_ip]['Policies'][policy] = flags
				stampslist_count = 0
				no_traffic = 0
				
				for stampslist in pol_attr: #stampslist = IF 24 hours - list of 72 checkpoints (every 20 min) for the particular protection (udp, tcp-syn etc.) [{'row': {'deviceIp': '10.107.129.206', 'normal': '161.0', 'fullExcluded': '-1.0', 'policyName': 'NIX-NC-EB-dns', 'enrichmentContainer': '{}', 'protection': 'tcp-frag', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620141600000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}, {'row': ....
					exceedlist = []
					avg_exceededby = 0
					currthroughput_list = []
					stampslist_count +=1

					for stamp in stampslist: # every row {'row': {'deviceIp': '10.107.129.205', 'normal': '645.0', 'fullExcluded': '0.0', 'policyName': 'test_1', 'enrichmentContainer': '{}', 'protection': 'tcp-rst', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620152400000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}
						row = stamp['row']
						normal_baseline = row['normal']
						protoc = row['protection']

						if normal_baseline is None:
							# normal_baseline = 0
							nonormalbaseline +=1
							continue

						currthroughput = row['full']
						if currthroughput is None:
							notrafficstats +=1
							# currthroughput = 0
							continue

						virtual_baseline = float(normal_baseline)* ratio

						currthroughput = float(currthroughput)
						
						currthroughput_list.append(currthroughput)


						if  currthroughput > virtual_baseline:
							if virtual_baseline != 0:
								final_report[dp_ip]['Policies'][policy][protoc][0] += 1
						
							if virtual_baseline !=0:
								# print(f'Virt baseline is not 0 for {dp_name} , {dp_ip} ,{policy} , {protoc}' + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(row['timeStamp'])//1000)))
								exceededby = currthroughput / virtual_baseline # calculate the ratio the traffic surpassed the 
								exceedlist.append(exceededby)



###############Start of High BDOS baselines####################

					if len(currthroughput_list) and sum(currthroughput_list) !=0: # if current throughput list per stamplist is not empty, calculate average throughput
						# currthroughput_avg = (sum(currthroughput_list)) / (len(currthroughput_list))

						top_currthroughput_idx = sorted(range(len(currthroughput_list)), key=lambda i: currthroughput_list[i])[-10:]
						top_currthroughput_list = [currthroughput_list[i] for i in top_currthroughput_idx]
					
						top_currthroughput_avg = (sum(top_currthroughput_list)) / (len(top_currthroughput_list))

						multiplier = top_currthroughput_avg * 4

						if top_currthroughput_avg == 0.0:#if average traffic is 0.0, count this stamplist as non carrying traffic
							no_traffic +=1
						
						if top_currthroughput_avg != 0.0 and normal_baseline is not None and float(normal_baseline) !=0.0 and float(normal_baseline) > multiplier:
							# print (f'{dp_ip}, {policy}, {protoc}, {normal_baseline} {currthroughput_avg} ')
							high_baseline_ratio = (top_currthroughput_avg / float(normal_baseline)) * 100
							high_baseline_delta = float(normal_baseline) - top_currthroughput_avg
							

							with open(reports_path + 'high_bdos_baselines.csv', mode='a', newline="") as high_baselines:
								highbas = csv.writer(high_baselines, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
								highbas.writerow([f'{dp_ip}',f'{dp_name}',f'{policy}',f'{protoc}',f'{top_currthroughput_avg / 1000}',f'{float(normal_baseline) / 1000}',f'{high_baseline_delta / 1000}',f'{round(high_baseline_ratio,2)}'])

#################End of High baselines detection###############################################
						
					if len(exceedlist): # if list is not empty, calculate the average exceeding ratio
						avg_exceededby = (sum(exceedlist)) / len(exceedlist)
						final_report[dp_ip]['Policies'][policy][row['protection']][1] = avg_exceededby



				if len(stampslist): 
					# No traffic
					if no_traffic == stampslist_count:#if currthroughput_avg == 0.0 on all protocol types
						logging.info(f'DP IP {dp_ip} DP name {dp_name} policy {policy}- No traffic for any of the BDOS protocols.')
						with open(reports_path + 'low_bdos_baselines.csv', mode='a', newline="") as low_bdos_baselines:
							low_bdos_baselines = csv.writer(low_bdos_baselines, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
							low_bdos_baselines.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{policy}' , 'N/A' ,	'N/A' , 'N/A' , 'No traffic for any of the BDOS protocols'])


				if nonormalbaseline > 0 or notrafficstats > 0: 
					# If BDOS traffic statistics are lost
					logging.info(f'Lost stats for BDOS normal baselines "{nonormalbaseline}" times. DP IP {dp_ip} DP name {dp_name} policy {policy}.')
					with open(reports_path + 'low_bdos_baselines.csv', mode='a', newline="") as low_bdos_baselines:
						low_bdos_baselines = csv.writer(low_bdos_baselines, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						low_bdos_baselines.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{policy}' , 'N/A' ,	'N/A' , 'N/A' , f'Lost stats for BDOS normal baselines {nonormalbaseline} times'])

	return final_report


def ParseDNSRawReport():

	final_dns_report = {}

	with open(raw_data_path + 'DNS_traffic_report.json') as json_file:
		dns_dict = json.load(json_file)


	for dp_ip,dp_ip_attr in dns_dict.items():
		ratio = cfg.DET_MARGIN_RATIO
		dp_name = dp_ip_attr['Name']
		final_dns_report[dp_ip] = {}
		final_dns_report[dp_ip]['Name'] = dp_name
		final_dns_report[dp_ip]['Policies'] = {}
		
	
		for policy_attr_obj in dp_ip_attr['DNS Report']: # policy_attr_obj = {"DNSv4": [[{"row": {"timeStamp": "1631714400000", "deviceIp": "....
			for policy, pol_attr in policy_attr_obj.items(): #pol_attr is [[{"row": {"deviceIp": "10.160.207.116", "normal": "23033.0", "policyName": "FW_VPN", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isIpv4": "true", "units": "bps", "timeStamp": "1620145200000", "fast": "0.0", "id": null, "partial": "0.0", "direction": "In", "full": "0.0"}}, {"row": {"deviceIp": "10.160.207.116", "normal": "23033.0", "policyName": "FW_VPN", "enrichmentContainer": "{}", "protection": "udp", "isTcp": "false", "isI
				notrafficstats = 0
				nonormalbaseline = 0
				flags = {"dns-a":[0,0],"dns-aaaa":[0,0],"dns-mx":[0,0],"dns-text":[0,0],"dns-soa":[0,0],"dns-srv":[0,0],"dns-ptr":[0,0],"dns-naptr":[0,0],"dns-other":[0,0]} #First element is number of occurances the traffic exceeded the virtual baseline, second is the average exceeding ratio
				final_dns_report[dp_ip]['Policies'][policy] = flags
				stampslist_count = 0
				no_traffic = 0
				
				for stampslist in pol_attr: #stampslist = IF 24 hours - list of 72 checkpoints (every 20 min) for the particular protection (udp, tcp-syn etc.) [{'row': {'deviceIp': '10.107.129.206', 'normal': '161.0', 'fullExcluded': '-1.0', 'policyName': 'NIX-NC-EB-dns', 'enrichmentContainer': '{}', 'protection': 'tcp-frag', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620141600000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}, {'row': ....
					exceedlist = []
					avg_exceededby = 0
					currthroughput_list = []
					stampslist_count +=1

					for stamp in stampslist: # every row {'row': {'deviceIp': '10.107.129.205', 'normal': '645.0', 'fullExcluded': '0.0', 'policyName': 'test_1', 'enrichmentContainer': '{}', 'protection': 'tcp-rst', 'isTcp': 'false', 'isIpv4': 'true', 'units': 'bps', 'timeStamp': '1620152400000', 'fast': '0.0', 'id': None, 'partial': '0.0', 'direction': 'In', 'full': '0.0'}}
						row = stamp['row']
						normal_baseline = row['normal']
						protoc = row['protection']

						if normal_baseline is None:
							# normal_baseline = 0
							nonormalbaseline +=1
							continue

						currthroughput = row['full']
						if currthroughput is None:
							notrafficstats +=1
							# currthroughput = 0
							continue

						virtual_baseline = float(normal_baseline)* ratio

						currthroughput = float(currthroughput)
						
						currthroughput_list.append(currthroughput)


						if  currthroughput > virtual_baseline:
							if virtual_baseline != 0:
								final_dns_report[dp_ip]['Policies'][policy][protoc][0] += 1
						
							if virtual_baseline !=0:
								# print(f'Virt baseline is not 0 for {dp_name} , {dp_ip} ,{policy} , {protoc}' + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(row['timeStamp'])//1000)))
								exceededby = currthroughput / virtual_baseline # calculate the ratio the traffic surpassed the 
								exceedlist.append(exceededby)



###############Start of High BDOS baselines####################

					if len(currthroughput_list) and sum(currthroughput_list) !=0: # if current throughput list per stamplist is not empty, calculate average throughput
						# currthroughput_avg = (sum(currthroughput_list)) / (len(currthroughput_list))

						top_currthroughput_idx = sorted(range(len(currthroughput_list)), key=lambda i: currthroughput_list[i])[-10:]
						top_currthroughput_list = [currthroughput_list[i] for i in top_currthroughput_idx]
					
						top_currthroughput_avg = (sum(top_currthroughput_list)) / (len(top_currthroughput_list))

						multiplier = top_currthroughput_avg * 4

						if top_currthroughput_avg == 0.0:#if average traffic is 0.0, count this stamplist as non carrying traffic
							no_traffic +=1
						
						if top_currthroughput_avg != 0.0 and normal_baseline is not None and float(normal_baseline) !=0.0 and float(normal_baseline) > multiplier:
							# print (f'{dp_ip}, {policy}, {protoc}, {normal_baseline} {currthroughput_avg} ')
							high_baseline_ratio = (top_currthroughput_avg / float(normal_baseline)) * 100
							high_baseline_delta = float(normal_baseline) - top_currthroughput_avg
							

							with open(reports_path + 'high_bdos_baselines.csv', mode='a', newline="") as high_baselines:
								highbas = csv.writer(high_baselines, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
								highbas.writerow([f'{dp_ip}',f'{dp_name}',f'{policy}',f'{protoc}',f'{top_currthroughput_avg / 1000}',f'{float(normal_baseline) / 1000}',f'{high_baseline_delta / 1000}',f'{round(high_baseline_ratio,2)}'])

#################End of High baselines detection###############################################
						
					if len(exceedlist): # if list is not empty, calculate the average exceeding ratio
						avg_exceededby = (sum(exceedlist)) / len(exceedlist)
						final_dns_report[dp_ip]['Policies'][policy][row['protection']][1] = avg_exceededby



				if len(stampslist): 
					# No traffic
					if no_traffic == stampslist_count:#if currthroughput_avg == 0.0 on all protocol types
						logging.info(f'DP IP {dp_ip} DP name {dp_name} policy {policy}- No traffic for any of the DNS protocols.')
						with open(reports_path + 'low_bdos_baselines.csv', mode='a', newline="") as low_bdos_baselines:
							low_bdos_baselines = csv.writer(low_bdos_baselines, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
							low_bdos_baselines.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{policy}' , 'N/A' ,	'N/A' , 'N/A' , 'No traffic for any of the DNS protocols'])


				if nonormalbaseline > 0 or notrafficstats > 0: 
					# DNS traffic statistics are lost
					logging.info(f'Lost stats for DNS normal baselines "{nonormalbaseline}" times. DP IP {dp_ip} DP name {dp_name} policy {policy}.')
					with open(reports_path + 'low_bdos_baselines.csv', mode='a', newline="") as low_bdos_baselines:
						low_bdos_baselines = csv.writer(low_bdos_baselines, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						low_bdos_baselines.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{policy}' , 'N/A' ,	'N/A' , 'N/A' , f'Lost stats for DNS normal baselines {nonormalbaseline} times'])

	return final_dns_report


def ParseBDOSStats(final_report):
	
	alarm_threshold = cfg.DET_ALARM_THRESHOLD

	for dp_ip,dp_ip_attr in final_report.items():
		dp_name = dp_ip_attr['Name']
		for pol_name, pol_attr in dp_ip_attr['Policies'].items():
			for flag,flag_val in pol_attr.items():
				if flag_val[0] >= alarm_threshold:
					# logging.info(f'{dp_name} , {dp_ip} , {pol_name}- "{flag}" traffic utilization has exceeded the virtual baseline set to {int(ratio*100)}% of the real baseline {flag_val[0]} times. Exceed ratio - {flag_val[1]}, ')
					with open(reports_path +'low_bdos_baselines.csv', mode='a', newline="") as bdos_final_report:
						bdos_writer = csv.writer(bdos_final_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , f'{flag}' ,	f'{flag_val[0]}' , f'{flag_val[1]}' , 'N/A'])

	return



def ParseDNSStats(final_report):
	
	alarm_threshold = cfg.DET_ALARM_THRESHOLD

	for dp_ip,dp_ip_attr in final_report.items():
		dp_name = dp_ip_attr['Name']
		for pol_name, pol_attr in dp_ip_attr['Policies'].items():
			for flag,flag_val in pol_attr.items():
				if flag_val[0] >= alarm_threshold:
					# logging.info(f'{dp_name} , {dp_ip} , {pol_name}- "{flag}" traffic utilization has exceeded the virtual baseline set to {int(ratio*100)}% of the real baseline {flag_val[0]} times. Exceed ratio - {flag_val[1]}, ')
					with open(reports_path + 'low_bdos_baselines.csv', mode='a', newline="") as bdos_final_report:
						bdos_writer = csv.writer(bdos_final_report, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
						bdos_writer.writerow([f'{dp_name}' , f'{dp_ip}' ,	f'{pol_name}' , f'{flag}' ,	f'{flag_val[0]}' , f'{flag_val[1]}' , 'N/A'])

	return