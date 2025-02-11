import socket
import logging
import logging.handlers
import smtplib
from email.mime.text import MIMEText
from email.mime.base import MIMEBase 
from email.mime.multipart import MIMEMultipart
from email import encoders
from datetime import date
import os
import config as cfg
import csv

def send_report(report_list):
	fromaddr = cfg.SMTP_SENDER
	toaddr = cfg.SMTP_LIST
	password = cfg.SMTP_PASSWORD
	column_name='Severity'
	h_alert='High'
	m_alert='Medium'
	l_alert='Informational'
	h_count=0
	m_count=0
	l_count=0

	msg = MIMEMultipart()
	msg["Subject"] = cfg.SMTP_SUBJECT_PREFIX + "No issues reported - " + date.today().strftime("%B %d, %Y")
	msg["From"] = fromaddr
	msg["To"] = ', '.join(toaddr)

	
	for report in report_list:

		if report == './Reports/low_bdos_baselines.csv':
			logging.info('sending low_bdos_baselines by email')
			statinfo = os.stat(report)
			with open(report, mode='r') as file: #Modified by Fabri
				reader = csv.DictReader(file) #Modified by Fabri
				for row in reader: #Modified by Fabri
					if row[column_name] == h_alert:
						h_count+=1
					if row[column_name] == m_alert:
						m_count+=1 
					if row[column_name] == l_alert:
						l_count+=1 
			print(statinfo.st_size)
			if h_count > 0 or m_count > 0 or l_count > 0: #send report, change subject
				new_subject = cfg.SMTP_SUBJECT_PREFIX + "WARNING! - " + date.today().strftime("%B %d, %Y")
				msg.replace_header("Subject", new_subject)  # Properly replace header
				print(msg["Subject"])

			dir, filename = os.path.split(report)
			attachment = open(report, "rb")
			p = MIMEBase('application', 'octet-stream')
			p.set_payload((attachment).read())
			encoders.encode_base64(p)
			p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
			body = f'''
			{cfg.SMTP_MSG_BODY}
			Summary of the report:
			Found {l_count} informational bdos baselines alerts
			Found {m_count} medium bdos baselines alerts
			Found {h_count} high bdos baselines alerts
			'''
			msg.attach(MIMEText(body, 'plain'))
			print(body)
			msg.attach(p)
			attachment.close()

		
		if report == './Reports/high_bdos_baselines.csv':
			continue

		if report == './Reports/test':
			#Send this test email if "--test-alarm" argument is set
			logging.info('sending test email alarm')
			msg["Subject"] = cfg.SMTP_SUBJECT_PREFIX + "DefensePro test alert report  - " + date.today().strftime("%B %d, %Y")
			body = "This email is a test email alert"



	mailserver = smtplib.SMTP(host=cfg.SMTP_SERVER,port=cfg.SMTP_SERVER_PORT)
	mailserver.ehlo()
	if cfg.SMTP_AUTH:
		mailserver.starttls()
		mailserver.ehlo()
		mailserver.login(fromaddr, password)
	mailserver.sendmail(from_addr=fromaddr,to_addrs=toaddr, msg=msg.as_string())
	mailserver.quit()
	
def log_setup(log_path, syslog_ip, syslog_port):
	log_dir_name = log_path
	log_rotation_size = cfg.LOG_ROTATION_SIZE
	log_rotation_history = cfg.LOG_ROTATION_HISTORY
	

	log_handler = logging.handlers.RotatingFileHandler(log_dir_name + "monitor.log", maxBytes=log_rotation_size, backupCount=log_rotation_history)
	syslog_handler = logging.handlers.SysLogHandler(address=(syslog_ip, syslog_port),
													facility=logging.handlers.SysLogHandler.LOG_USER,
													socktype=socket.SOCK_DGRAM)
	log_formatter = logging.Formatter(
		'%(asctime)s %(message)s',
		'%b %d %H:%M:%S')
	syslog_formatter = logging.Formatter(
		'%(asctime)s %(message)s',
		'%b %d %H:%M:%S')

	log_handler.setFormatter(log_formatter)
	syslog_handler.setFormatter(syslog_formatter)
	logger = logging.getLogger()
	logger.addHandler(log_handler)
	logger.addHandler(syslog_handler)
	logger.setLevel(logging.INFO)
