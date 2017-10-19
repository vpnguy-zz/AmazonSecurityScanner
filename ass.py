#!/usr/bin/env python
from argparse import RawTextHelpFormatter
import argparse
import sys
import os
import urllib2
import datetime

#Still very active in development, please no bully

#Wrapper for handling access to the Metadata/User Data/Identity Provider on 169.254.169.254
def GetInstanceMetadata(path):
	try:
		handle = urllib2.urlopen(("http://169.254.169.254/latest/" + path), timeout = 1)
		output = handle.read()
		return output
	except urllib2.HTTPError, e:
		if e.code == 404:
			return False
		else:
			print "Failed due to unknown HTTP error"
	except urllib2.URLError, e:
		print "No metadata detected, are you sure this is ec2?"

#Parse /etc/passwd to find user home directories then check home directories for AWS access keys
def CredentialScan():
	file = "/etc/passwd"
	file_object = open(file, 'r')
	FoundCreds = False 
	for line in file_object:
	    line = line.strip()
	    fields = line.split(":")
	    credlocation = fields[-2] + "/.aws/credentials"
	    if os.path.isfile(credlocation):
	    	print "\033[1;31m[-]\033[0m Found creds: " + credlocation + " \033[1;31m(Not OK)\033[0m"
	    	FoundCreds = True
	if FoundCreds == False:
			print "\033[1;32m[+]\033[0m Detected Unable to detect AWS Access Keys \033[1;32m(OK)\033[0m"
	file_object.close()

#Does the EC2 instance have an IAM role that we could impersonate?
def RoleDetect():
	Role = GetInstanceMetadata("meta-data/iam/security-credentials/")
	if Role != False:
		print "\033[1;33m[I]\033[0m IAM Role detected: " + Role + " \033[1;33m(Informational)\033[0m"
	else:
		print "\033[1;33m[I]\033[0m No IAM Roles detected  \033[1;33m(Informational)\033[0m"

#Any user data being passed to the EC2 instance?
def UserDetect():
	UserData = GetInstanceMetadata("user-data")
	if UserData != False:
		print "\033[1;33m[I]\033[0m Successfully Recovered user data: " + UserData + " \033[1;33m(Informational)\033[0m"
	else:
		print "\033[1;32m[+]\033[0m No user data detected \033[1;32m(OK)\033[0m"	

#Enumerate VPCs connected to this device and the AccountID in preperation for peer phishing
def PeeringData():
	NicDict = {}
	NicList = GetInstanceMetadata("meta-data/network/interfaces/macs/")
	for line in NicList.splitlines():
		line = line[:-1]
		NicVPCID = GetInstanceMetadata("meta-data/network/interfaces/macs/" + line + "/vpc-id/")
		if NicVPCID == False: #If instance is launched outside a VPC this can end up empty
			NicVPCID = "Not in VPC"
		NicDict[line] = NicVPCID
	IdentityDocument = GetInstanceMetadata("dynamic/instance-identity/document")
	AccountId = 123456789012 #I don't think you can have an instance with multiple AccountIDs
	for line in IdentityDocument.splitlines():
		if "accountId" in line:
			chunk = line.split(":")
			AccountId = chunk[1]
			AccountId = AccountId[:-2] #This technique doesnt scale well but we only need to drop the first and last 2 so its ugly but works
			AccountId = AccountId[2:]
	NicID = 0 
	print "Peering Information: "
	for item in NicDict:
		print "\033[1;34m[*]\033[0m Interface #" + str(NicID) + " Mac Address: " +  item +  " VPC ID: " + NicDict[item] + " Account ID: " + AccountId
		NicID += 1

#List Subnets linked to the interfaces
def VPCSubnets(): 
	NicDict = {}
	NicList = GetInstanceMetadata("meta-data/network/interfaces/macs/")
	for line in NicList.splitlines():
		line = line[:-1]
		NicVPCSubnet = GetInstanceMetadata("meta-data/network/interfaces/macs/" + line + "/vpc-ipv4-cidr-blocks/")
		if NicVPCSubnet == False: #If instance is launched outside a VPC this can end up empty
			NicVPCSubnet = "Not in VPC"
		NicDict[line] = NicVPCSubnet

	NicID = 0 
	print "Subnet Information: "
	for item in NicDict:
		print "\033[1;34m[*]\033[0m Interface #" + str(NicID) + " Mac Address: " +  item +  " VPC Subnet: " + NicDict[item]
		NicID += 1




if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="""
	Amazon Security Scanner (ASS)
		by DarkRed
	Scan an EC2 Instance for potential AWS related attack surfaces
		Ver: 1.0 - 10/19/2017
		""",formatter_class=RawTextHelpFormatter)

	parser.add_argument('-c','--credentialscan', help='Only attempt to scan home directories for AWS Access Keys', required=False, action='store_true')
	parser.add_argument('-i','--iamrole', help='Only attempt to detect IAM Roles associated with the instance', required=False, action='store_true')
	parser.add_argument('-u','--userdata', help='Only attempt to detect user data associated with the instance', required=False, action='store_true')
	parser.add_argument('-p','--peering', help='Identify the information required to submit a peering request with the instance', required=False, action='store_true')
	parser.add_argument('-v','--vpcsubnets', help='Identify the VPC subnet masks associated with the interfaces on the instance', required=False, action='store_true')
	args = parser.parse_args()
	multiarg = False 
	print "Starting Amazon Security Scanner... "

	#Start parsing arguments
	if args.credentialscan:
		print "Scanning for AWS Access Keys in home directories..."
		multiarg = True
		CredentialScan()

	if args.iamrole:
		print "Scanning for IAM Role associated with instance..."
		multiarg = True
		RoleDetect()

	if args.userdata:
		print "Scanning for EC2 user data..."
		multiarg = True
		UserDetect()

	if args.peering:
		multiarg = True
		PeeringData()

	if args.vpcsubnets:
		multiarg = True
		VPCSubnets()

	#No args? Lets run everything!	
	if multiarg == False:
		CredentialScan()
		RoleDetect()
		UserDetect()
		PeeringData()
		VPCSubnets()

	print 'Completed at: {:%H:%M:%S on %m-%d-%Y}'.format(datetime.datetime.now())
	sys.exit(0)