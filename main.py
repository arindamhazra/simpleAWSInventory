import boto3,botocore
import csv
from datetime import datetime
from time import gmtime,strftime
import os

ROLE_ARN = ["arn:aws:iam::xxxxxxxxxxx:role/aws_lambda_inventory_execution_role","arn:aws:iam::yyyyyyyyyyyy:role/aws_lambda_inventory_execution_role"]



s3 = boto3.resource('s3')
sts = boto3.client('sts')
def lambda_handler(event,context):
    fName = "AWS_Resource_Inventory_"+strftime("%m_%d_%Y",gmtime())+".csv"
    fPath = "/tmp/"+fName
    if os.path.exists(fPath):
        os.remove(fPath)
    outFile = open(fPath,"w+")


    def get_ec2_instance_inventory(accountId,arn,aKey,sKey,sToken,oFile):
        outFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','Instance ID','Instance State','Instance Name','Instance Type','LaunchTime','Availability Zone','Instance Tenancy','Monitoring State','Private IP','Public IP','Public DNS Name','VPC ID','Subnet ID','Associated Security Groups'))
        outFile.flush()    
        ec2 = boto3.client('ec2',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allRegions = ec2.describe_regions().get('Regions',[])

        #Inventory EC2 Instance Resources for all Regions in the Account  
        #Create the header row in the .csv file to inventory EC2 Instances

        for region in allRegions:
            reg = region['RegionName']
            ec2con = boto3.client('ec2',region_name=reg,aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
            allReservations = ec2con.describe_instances().get('Reservations',[])
            allInstances = sum(
                [
                [i for i in r['Instances']]
                for r in allReservations
                ],[])
            instanceList = len(allInstances)
            if instanceList > 0:
                for instance in allInstances:
                    insState = instance['State']['Name']
                    insId = instance['InstanceId']
                    insType = instance['InstanceType']
                    insLaunchTime = instance['LaunchTime']
                    insAZ = instance['Placement']['AvailabilityZone']
                    insTenancy = instance['Placement']['Tenancy']
                    insMonitor = instance['Monitoring']['State']
                    if instance.get('Platform'):
                        if insState == 'running':
                            insPlatform = instance['Platform']
                        else:
                            insPlatform = 'NA'
                    else: 
                        insPlatform = 'NA'  
                    insPriIP = instance['PrivateIpAddress']
                    if insState == 'running':
                        insPubIP = instance['PublicIpAddress']
                    else:
                        insPubIP = 'NA'
                    if insState == 'running':
                        insPubDNSName = instance['PublicDnsName']
                    else:
                        insPubDNSName = 'NA'
                    insVPCId = instance['VpcId']
                    insSubNetId = instance['SubnetId']
                    insSGList = ''
                    for sg in instance['SecurityGroups']:
                        insSGList = insSGList + sg['GroupName'] + ";"
                    insSGList = insSGList[:-1]
                    if instance.get('Tags'):
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                insName = tag['Value']
                            else:
                                insName = 'NA'
                    else:
                        insName = 'NA'
                    oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'EC2 Instance',reg,insId,insState,insName,insType,insLaunchTime,insAZ,insTenancy,insMonitor,insPriIP,insPubIP,insPubDNSName,insVPCId,insSubNetId,insSGList))
                    oFile.flush()

    def get_ec2_volume(accountId,arn,aKey,sKey,sToken,oFile):
        #Inventory EC2 Volume Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory EC2 Volumes
        outFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','Volume ID','Volume Name','Volume Type','Volume Size','Encrypted?','KMS Key Id','Volume Creation Time','Volume State','Snapshot ID','Volume IOPs','Availability Zone','Instance ID','Device ID','Attched Time','Delete Protection'))
        oFile.flush()
        ec2 = boto3.client('ec2',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allRegions = ec2.describe_regions().get('Regions',[])        
        for region in allRegions:
            reg = region['RegionName']
            ec2con = boto3.client('ec2',region_name=reg,aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
            allVolumes = ec2con.describe_volumes().get('Volumes',[])
            for vol in allVolumes:
                volId = vol['VolumeId']
                if vol.get('Tags'):
                    for tag in vol['Tags']:
                        if tag['Key'] == 'Name':
                            volName = tag['Value']
                else:
                    volName = 'NA'
                volType = vol['VolumeType']
                volSize = str(vol['Size'])
                volEnc = vol['Encrypted']
                if vol.get('KmsKeyId'):
                    volKms = vol['KmsKeyId']
                else:
                    volKms = 'NA'
                volCreateTime = vol['CreateTime']
                volState = vol['State']
                volSnapshotId = vol['SnapshotId']
                volIops = str(vol['Iops'])
                volAZ = vol['AvailabilityZone']
                if vol.get('Attachments'):
                    for attach in vol['Attachments']:
                        volInstanceId = attach['InstanceId']
                        volDeviceId = attach['Device']
                        volAttchTime = attach['AttachTime']
                        volTermProtect = attach['DeleteOnTermination']
                oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'EC2  Volumes',reg,volId,volName,volType,volSize,volEnc,volKms,volCreateTime,volState,volSnapshotId,volIops,volAZ,volInstanceId,volDeviceId,volAttchTime,volTermProtect))
                oFile.flush()

    def get_ec2_snapshot(accountId,arn,aKey,sKey,sToken,oFile):
        #Inventory EC2 Snapshot Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory EC2 Snapshot
        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','Snapshot ID','Snapshot Name','Snapshot Owner','Snapshot Owner Alias','Snapshot Volume ID','Snapshot Volume Size','Snapshot StartTime','Snapshot Encrypted?','KMS ID','Snapshot Progress','Snapshot State'))
        oFile.flush()
        ec2 = boto3.client('ec2',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allRegions = ec2.describe_regions().get('Regions',[])
        for region in allRegions:
            reg = region['RegionName']
            ec2con = boto3.client('ec2',region_name=reg,aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
            allSnapshots = ec2con.describe_snapshots().get('Snapshots',[])
            for snapshot in allSnapshots:
                snapshotId = snapshot['SnapshotId']
                if snapshot.get('Tags'):
                    for tag in snapshot['Tags']:
                        if tag['Key'] == 'Name':
                            snapshotName = tag['Value']
                else:
                    snapshotName = 'NA'
                snapshotOwner = snapshot['OwnerId']
                if snapshot.get('OwnerAlias'):
                    snapshotOwnerAlias = snapshot['OwnerAlias']
                else:
                    snapshotOwnerAlias = 'NA'
                snapshotVol = snapshot['VolumeId']
                snapshotSize = snapshot['VolumeSize']
                snapshotStartTime = snapshot['StartTime']
                snapshotEncrpted = snapshot['Encrypted']
                if snapshot.get('KmsKeyId'):
                    snapshotKmsId = snapshot['KmsKeyId']
                else:
                    snapshotKmsId = 'NA'
                snapshotProgress = snapshot['Progress']
                snapshotState = snapshot['State']
            oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'EC2  Snapshots',reg,snapshotId,snapshotName,snapshotOwner,snapshotOwnerAlias,snapshotVol,snapshotSize,snapshotStartTime,snapshotEncrpted,snapshotKmsId,snapshotProgress,snapshotState))
            oFile.flush()

    def get_vpc_info(accountId,arn,aKey,sKey,sToken,oFile):
        #Inventory VPC Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory VPC
        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','VPC ID','VPC State','VPC Name','CIDR Block','Is Default'))
        oFile.flush()
        ec2 = boto3.client('ec2',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allRegions = ec2.describe_regions().get('Regions',[])    
        for region in allRegions:
            reg = region['RegionName']
            ec2con = boto3.client('ec2',region_name=reg,aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
            allVpcs = ec2con.describe_vpcs().get('Vpcs',[])
            for vpc in allVpcs:
                vpcId = vpc['VpcId']
                vpcState = vpc['State']
                if vpc.get('Tags'):
                    for tag in vpc['Tags']:
                        if tag['Key'] == 'Name':
                            vpcName = tag['Value']
                else:
                    vpcName = 'NA'
                vpcCidrBlock = vpc['CidrBlock']
                vpcIsDefault = vpc['IsDefault']
                oFile.write("%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'VPC',reg,vpcId,vpcState,vpcName,vpcCidrBlock,vpcIsDefault))
                oFile.flush()

    def get_vpc_subnet_info(accountId,arn,aKey,sKey,sToken,oFile):
        #Inventory VPC Subnet Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory VPC Subnet
        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','Subnet ID','Subnet Name','VPC ID','Availability Zone','Available IP Count','CIDR Block','Auto-assign Public IP','Subnet State'))
        oFile.flush()
        ec2 = boto3.client('ec2',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allRegions = ec2.describe_regions().get('Regions',[])          
        for region in allRegions:
            reg = region['RegionName']
            ec2con = boto3.client('ec2',region_name=reg,aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
            allSubnets = ec2con.describe_subnets().get('Subnets',[])
            for subnet in allSubnets:
                subnetId = subnet['SubnetId']
                if subnet.get('Tags'):
                    for tag in subnet['Tags']:
                        if tag['Key'] == 'Name':
                            subnetName = tag['Value']
                else:
                    subnetName = 'NA'
                subnetVPCId =  subnet['VpcId']
                subnetVPCAZName = subnet['AvailabilityZone']
                subnetVPCAvailIp = subnet['AvailableIpAddressCount']
                subnetCIDRBlock = subnet['CidrBlock']
                subnetAutoAssignIP = subnet['MapPublicIpOnLaunch']
                subnetState = subnet['State']
                oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'Subnet',reg,subnetId,subnetName,subnetVPCId,subnetVPCAZName,subnetVPCAvailIp,subnetCIDRBlock,subnetAutoAssignIP,subnetState))
                oFile.flush()

    def get_route_table_info(accountId,arn,aKey,sKey,sToken,oFile):
        #Inventory VPC Route Table Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory VPC Route Table
        oFile.write("%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','RouteTable ID','RouteTable Name','VPC ID','Route'))
        oFile.flush()
        ec2 = boto3.client('ec2',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allRegions = ec2.describe_regions().get('Regions',[])          
        for region in allRegions:
            reg = region['RegionName']
            ec2con = boto3.client('ec2',region_name=reg,aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
            allRouteTables = ec2con.describe_route_tables().get('RouteTables',[])
            for routeTable in allRouteTables:
                routeTableId = routeTable['RouteTableId']
                if routeTable.get('Tags'):
                    for tag in routeTable['Tags']:
                        if tag['Key'] == 'Name':
                            routeTableName = tag['Value']
                else:
                    routeTableName = 'NA'
                routeTableVPCId =  routeTable['VpcId']
                if  routeTable.get('Routes'):
                    for route in routeTable['Routes']:
                        routeTableRoute = 'Destination CIDR : ' + route['DestinationCidrBlock'] + ' ' + 'Target : ' + route['GatewayId'] + ' ' + 'State : ' + route['State']
                        oFile.write("%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'RouteTable',reg,routeTableId,routeTableName,routeTableVPCId,routeTableRoute))
                        oFile.flush()

    def get_internet_gateway_info(accountId,arn,aKey,sKey,sToken,oFile):    
        #Inventory VPC Internet Gateway Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory VPC Internet Gateway
        oFile.write("%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','InternetGateway ID','InternetGateway Name','VPC ID','State'))
        oFile.flush()
        ec2 = boto3.client('ec2',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allRegions = ec2.describe_regions().get('Regions',[])          
        for region in allRegions:
            reg = region['RegionName']
            ec2con = boto3.client('ec2',region_name=reg,aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
            allIgws = ec2con.describe_internet_gateways().get('InternetGateways',[])
            for igw in allIgws:
                igwId = igw['InternetGatewayId']
                if igw.get('Tags'):
                    for tag in igw['Tags']:
                        if tag['Key'] == 'Name':
                            igwName = tag['Value']
                else:
                    igwName = 'NA'
                for attch in igw['Attachments']:
                    igwVpcId = attch['VpcId']
                    igwState = attch['State']
                oFile.write("%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'Internet Gateway',reg,igwId,igwName,igwVpcId,igwState))
                oFile.flush()

    def get_eip_info(accountId,arn,aKey,sKey,sToken,oFile):        
        #Inventory VPC Elastic IPs Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory VPC Elastic IP
        oFile.write("%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','Elastic IPAddress','EIP Name','Instance Id','Domain'))
        oFile.flush()
        ec2 = boto3.client('ec2',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allRegions = ec2.describe_regions().get('Regions',[])          
        for region in allRegions:
            reg = region['RegionName']
            ec2con = boto3.client('ec2',region_name=reg,aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
            allEIps = ec2con.describe_addresses().get('Addresses',[])
            for eip in allEIps:
                eipAddress = eip['PublicIp']
                if eip.get('Tags'):
                    for tag in eip['Tags']:
                        if tag['Key'] == 'Name':
                            eipName = tag['Value']
                else:
                    eipName = 'NA'
                if eip.get('InstanceId'):
                    eipInstanceId = eip['InstanceId']
                else:
                    eipInstanceId = 'NA'
                eipDomain = eip['Domain']
                oFile.write("%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'Elastic IPAddress',reg,eipAddress,eipName,eipInstanceId,eipDomain))
                oFile.flush()

    def get_nacl_info(accountId,arn,aKey,sKey,sToken,oFile): 
        #Inventory VPC Network ACLs Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory VPC Network ACL
        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','NACL Id','NACL Name','VPC Id','Is Default','Associated Subnets','Inbound Rules','Outbound Rules'))
        oFile.flush()
        ec2 = boto3.client('ec2',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allRegions = ec2.describe_regions().get('Regions',[])          
        for region in allRegions:
            reg = region['RegionName']
            ec2con = boto3.client('ec2',region_name=reg,aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
            allNACLs = ec2con.describe_network_acls().get('NetworkAcls',[])
            for nacl in allNACLs:
                naclId = nacl['NetworkAclId']
                if nacl.get('Tags'):
                    for tag in nacl['Tags']:
                        if tag['Key'] == 'Name':
                            naclName =tag['Value']
                else:
                    naclName = 'NA'
                naclVpcId = nacl['VpcId']
                naclIsDefault = nacl['IsDefault']
                if nacl.get('Associations'):
                    naclSubNets = ''
                    for naclAssn in nacl['Associations']:
                        naclSubNets = naclSubNets + naclAssn['SubnetId'] + ';'
                    naclSubNets = naclSubNets[:-1]
                else:
                    naclSubNets = 'NA'
                if nacl.get('Entries'):
                    naclInboundRules = ''
                    naclOutboundRules = ''
                    for naclentry in nacl['Entries']:
                        if naclentry['Protocol'] == '-1':
                            naclprotocol = 'All'
                        else:
                            naclprotocol = naclentry['Protocol']
                        if naclentry['Egress'] == False:
                            naclInboundRules = naclInboundRules + 'Source : ' + naclentry['CidrBlock'] + ';' + 'Protocol : ' + naclprotocol + ';' + 'Allow/Deny : ' + naclentry['RuleAction'] + ';' + 'Rule Number : ' + str(naclentry['RuleNumber']) + ' | '
                            naclInboundRules = naclInboundRules[:-1]
                        else:
                            naclOutboundRules = naclOutboundRules + 'Source : ' + naclentry['CidrBlock'] + ';' + 'Protocol : ' + naclprotocol + ';' + 'Allow/Deny : ' + naclentry['RuleAction'] + ';' + 'Rule Number : ' + str(naclentry['RuleNumber']) + ' | '
                            naclOutboundRules = naclOutboundRules[:-1]
                        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'Network ACL',reg,naclId,naclName,naclVpcId,naclIsDefault,naclSubNets,naclInboundRules,naclOutboundRules))
                        oFile.flush()

    def get_security_group(accountId,arn,aKey,sKey,sToken,oFile): 
        #Inventory VPC Security Groups Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory VPC Security Group
        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','SecurityGroup Id','SecurityGroup Name','VPC Id','SG Tag Name','Inbound Rules','Outbound Rules'))
        oFile.flush()
        ec2 = boto3.client('ec2',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allRegions = ec2.describe_regions().get('Regions',[])          
        for region in allRegions:
            reg = region['RegionName']
            ec2con = boto3.client('ec2',region_name=reg,aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
            allSGs = ec2con.describe_security_groups().get('SecurityGroups',[])
            for sg in allSGs:
                sgGroupId = sg['GroupId']
                sgGroupName = sg['GroupName']
                sgVpcId = sg['VpcId']
                if sg.get('Tags'):
                    for tag in sg['Tags']:
                        if tag['Key'] == 'Name':
                            sgTagName = tag['Value']
                else:
                    sgTagName = 'NA'
                sgInboundRules = ''
                sgOutboundRules = ''
                for sgin in sg['IpPermissions']:
                    if sgin.get('FromPort'):
                        sgFromPort = str(sgin['FromPort'])
                        if sgFromPort == '-1':
                            sgFromPort = 'All'
                    else:
                        sgFromPort = 'NA'
                    if sgin.get('ToPort'):
                        sgToPort = str(sgin['ToPort'])
                        if sgToPort == '-1':
                            sgToPort = 'All'
                    else:
                        sgToPort = 'NA'
                    if sgin['IpProtocol'] == '-1':
                        sgIpProtocol = 'All'
                    else:
                        sgIpProtocol = sgin['IpProtocol']
                    if sgin.get('IpRanges'):
                        sginIpRange = ''
                        for iprange in sgin['IpRanges']:
                            sginIpRange = sginIpRange + iprange['CidrIp'] + ';'
                        sginIpRange = sginIpRange[:-1]
                    else:
                        sginIpRange = 'NA'
                sgInboundRules = sgInboundRules + 'From Port : ' + sgFromPort + ' ' + 'To Port : ' + sgToPort + ' ' + 'Protocol : ' + sgIpProtocol + ' '+ 'Source : '+ sginIpRange + ' |'
                sgInboundRules = sgInboundRules[:-1]
                for sgout in sg['IpPermissionsEgress']:
                    if sgout.get('FromPort'):
                        sgFromPort = str(sgout['FromPort'])
                        if sgFromPort == '-1':
                            sgFromPort = 'All'
                    else:
                        sgFromPort = 'NA'
                    if sgout.get('ToPort'):
                        sgToPort = str(sgout['ToPort'])
                        if sgToPort == '-1':
                            sgToPort = 'All'
                    else:
                        sgToPort = 'NA'
                    if sgout['IpProtocol'] == '-1':
                        sgIpProtocol = 'All'
                    else:
                        sgIpProtocol = sgout['IpProtocol']
                    if sgout.get('IpRanges'):
                        sgoutIpRange = ''
                        for iprange in sgout['IpRanges']:
                            sgoutIpRange = sgoutIpRange + iprange['CidrIp'] + ';'
                        sgoutIpRange = sgoutIpRange[:-1]
                    else:
                        sgoutIpRange = 'NA'
                sgOutboundRules = sgOutboundRules + 'From Port : ' + sgFromPort + ' ' + 'To Port : ' + sgToPort + ' ' + 'Protocol : ' + sgIpProtocol + ' '+ 'Destination : '+ sgoutIpRange + ' |'
                sgOutboundRules = sgOutboundRules[:-1]
                oFile.write("%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'Security Group',reg,sgGroupId,sgGroupName,sgVpcId,sgTagName,sgInboundRules,sgOutboundRules))
                oFile.flush()

    def get_iam_groups(accountId,arn,aKey,sKey,sToken,oFile):
        #Inventory IAM Groups Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory IAM Group
        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','IAM Group Id','IAM Group Name','IAM Group Path','IAM Group Arn','IAM Group CreateDate'))
        oFile.flush()
        iam = boto3.client('iam',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allIamGroups = iam.list_groups().get('Groups',[])
        for iamGroup in allIamGroups:
            iamGroupId = iamGroup['GroupId']
            iamGroupName = iamGroup['GroupName']
            iamGroupPath = iamGroup['Path']
            iamGroupArn = iamGroup['Arn']
            iamGroupCreateDate = iamGroup['CreateDate']
            oFile.write("%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'IAM Group','Global',iamGroupId,iamGroupName,iamGroupPath,iamGroupArn,iamGroupCreateDate))
            oFile.flush()

    def get_iam_users(accountId,arn,aKey,sKey,sToken,oFile):
        #Inventory IAM Users Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory IAM User
        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','IAM User Id','IAM User Name','IAM User Path','IAM User Arn','IAM User CreateDate','IAM Password Last Used'))
        oFile.flush()
        iam = boto3.client('iam',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allIamUsers = iam.list_users().get('Users',[])
        for iamUser in allIamUsers:
            iamUserId = iamUser['UserId']
            iamUserName = iamUser['UserName']
            iamUserPath = iamUser['Path']
            iamUserArn = iamUser['Arn']
            iamUserCreateDate = iamUser['CreateDate']
            if iamUser.get('PasswordLastUsed'):
                iamUserPwdLastUser = iamUser['PasswordLastUsed']
            else:
                iamUserPwdLastUser = 'None'
            oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'IAM User','Global',iamUserId,iamUserName,iamUserPath,iamUserArn,iamUserCreateDate,iamUserPwdLastUser))
            oFile.flush()


    def get_iam_roles(accountId,arn,aKey,sKey,sToken,oFile):
        #Inventory IAM Roles Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory IAM Role
        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','IAM Role Id','IAM Role Name','IAM Role Path','IAM Role Arn','IAM Role CreateDate','IAM Role Description'))
        oFile.flush()
        iam = boto3.client('iam',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allIamRoles = iam.list_roles().get('Roles',[])
        for iamRole in allIamRoles:
            iamRoleId = iamRole['RoleId']
            iamRoleName = iamRole['RoleName']
            iamRolePath = iamRole['Path']
            iamRoleArn = iamRole['Arn']
            iamRoleCreateDate = iamRole['CreateDate']
            # iamAssumeRolePolDoc = iamRole['AssumeRolePolicyDocument']
            if iamRole.get('Description'):
                iamRoleDescription = iamRole['Description']
            else:
                iamRoleDescription = 'NA'
            oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'IAM Role','Global',iamRoleId,iamRoleName,iamRolePath,iamRoleArn,iamRoleCreateDate,iamRoleDescription))
            oFile.flush()


    def get_iam_policies(accountId,arn,aKey,sKey,sToken,oFile):
        #Inventory IAM Policies Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory IAM Policy
        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','IAM Policy Id','IAM Policy Name','IAM Policy Path','IAM Policy Arn','IAM Policy CreateDate','IAM Policy UpdateDate','IAM Policy VersionId','Policy Attachable?','Policy Attachment Count','IAM Policy Description'))
        oFile.flush()
        iam = boto3.client('iam',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allIamPolicies = iam.list_policies().get('Policies',[])
        for iamPolicy in allIamPolicies:
            iamPolicyId = iamPolicy['PolicyId']
            iamPolicyName = iamPolicy['PolicyName']
            iamPolicyPath = iamPolicy['Path']
            iamPolicyArn = iamPolicy['Arn']
            iamPolicyCreateDate = iamPolicy['CreateDate']
            iamPolicyUpdateDate = iamPolicy['UpdateDate']
            iamPolicyVersionId = iamPolicy['DefaultVersionId']
            iamPolicyIsAtachable = iamPolicy['IsAttachable']
            iamPolicyAttchCount = str(iamPolicy['AttachmentCount'])
            if iamPolicy.get('Description'):
                iamPolicyDescription = iamPolicy['Description']
            else:
                iamPolicyDescription = 'NA'
            oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'IAM Policy','Global',iamPolicyId,iamPolicyName,iamPolicyPath,iamPolicyArn,iamPolicyCreateDate,iamPolicyUpdateDate,iamPolicyVersionId,iamPolicyIsAtachable,iamPolicyAttchCount,iamPolicyDescription))
            oFile.flush()


    def get_saml_idps(accountId,arn,aKey,sKey,sToken,oFile):    
        #Inventory IAM SAML Identity Provider Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory IAM SAML Identity Provider
        oFile.write("%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','SAMLProvider Arn','SAMLProvider Valid Date','SAMLProvider CreateDate'))
        oFile.flush()
        iam = boto3.client('iam',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allIamSAMLProviders = iam.list_saml_providers().get('SAMLProviderList',[])
        for iamSAMLProvider in allIamSAMLProviders:
            iamSAMLProviderArn = iamSAMLProvider['Arn']
            iamSAMLProviderValidDate = iamSAMLProvider['ValidUntil']
            iamSAMLProviderCreateDate = iamSAMLProvider['CreateDate']
            oFile.write("%s,%s,%s,%s,%s,%s\n"%(accountId,'IAM SAML Provider','Global',iamSAMLProviderArn,iamSAMLProviderValidDate,iamSAMLProviderCreateDate))
            oFile.flush()

    def get_s3_info(accountId,arn,aKey,sKey,sToken,oFile):
        #Inventory S3 Resources for all Regions in the Account
        #Create the header row in the .csv file to inventory S3 Resources
        oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('Account Name','Resource Name','Region Name','Bucket Name','Creation Date','Bucket Encryption','Bucket Lifecycle','Bucket Logging','Bucket Versioning','Object Count','Public Bucket?'))
        oFile.flush()
        s3client = boto3.client('s3',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        s3res = boto3.resource('s3',aws_access_key_id=aKey,aws_secret_access_key=sKey,aws_session_token=sToken)
        allS3Buckets = s3client.list_buckets().get('Buckets',[])
        for s3bucket in allS3Buckets:
            s3BucketName = s3bucket['Name']
            s3BucketCreateTime = s3bucket['CreationDate']
            #Bucket Encryption settings
            s3BucketEnc = ""
            try:
                response = s3client.get_bucket_encryption(Bucket=s3BucketName)
                for enc in response['ServerSideEncryptionConfiguration']['Rules']:
                    s3BucketEnc = s3BucketEnc + "SSE Algorithm : " + enc['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] + "  KMSMasterKeyID : " + enc['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID'] + ";"
                    if s3BucketEnc[-1] == ";":
                        s3BucketEnc = s3BucketEnc[:-1]
            except botocore.exceptions.ClientError as e:
                s3BucketEnc = "Not Encrypted"
            #Bucket Life Cycle settings
            s3BucketLC = ""
            try:
                response = s3client.get_bucket_lifecycle_configuration(Bucket=s3BucketName)
                for lc in response['Rules']:
                    s3BucketLC = s3BucketLC + "Id : " + lc['ID'] + "  Enabled : " + lc['Status'] + ";"
                    if s3BucketLC[-1] == ";":
                        s3BucketLC = s3BucketLC[:-1]
            except botocore.exceptions.ClientError as e:
                s3BucketLC = "Not Configured"
            #Bucket Bucket Location
            s3BucketLocation = s3client.get_bucket_location(Bucket=s3BucketName)['LocationConstraint']
            #Bucket Logging Settings
            s3BucketLog = ""
            try:
                response = s3client.get_bucket_logging(Bucket=s3BucketName)
                if response.get('LoggingEnabled'):
                    s3BucketLog = s3BucketLog + "Target Bucket : " + response['LoggingEnabled']['TargetBucket'] + "  Target Prefix : " + response['LoggingEnabled']['TargetPrefix'] + ";"
                    s3BucketLog = s3BucketLog[:-1]
                else:
                    s3BucketLog = "Not Configured"
            except botocore.exceptions.ClientError as e:
                s3BucketLog = "Not Configured"
            #Bucket Versioning Settings
            response = s3client.get_bucket_versioning(Bucket=s3BucketName)
            if response.get('Status'):
                s3BucketVer = response['Status']
            else:
                s3BucketVer = "Not Configured"
            #Bucket Object Count
            response = s3client.list_objects_v2(Bucket=s3BucketName)
            if response.get('Contents'):
                s3BucketObjectCount = str(len(response['Contents']))
            else:
                s3BucketObjectCount = "Empty"
            #Bucket Public Check
            bucketAclInfo = s3client.get_bucket_acl(Bucket=s3BucketName)
            IsPublic = False
            for grantee in bucketAclInfo['Grants']:
                if grantee['Grantee'].get('URI'):
                    if 'AllUsers' in grantee['Grantee']['URI']:
                        IsPublic = True
            try:
                bucketPolInfo = s3client.get_bucket_policy(Bucket=s3BucketName)['Policy']
                if '"Effect":"Allow"' in bucketPolInfo and '"Principal":"*"' in bucketPolInfo:
                    IsPublic = True
            except botocore.exceptions.ClientError as e:
                pass
            if IsPublic:
                s3BucketPolicy = "Public Bucket"
            else:
                s3BucketPolicy = "Private Bucket"

            oFile.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(accountId,'AWS S3',s3BucketLocation,s3BucketName,s3BucketCreateTime,s3BucketEnc,s3BucketLC,s3BucketLog,s3BucketVer,s3BucketObjectCount,s3BucketPolicy))
            oFile.flush()        



    for arn in ROLE_ARN:
        assumedRoleItem = sts.assume_role(RoleArn=arn,RoleSessionName='rolesessionname1')
        creadentials = assumedRoleItem['Credentials']
        accessKey = creadentials['AccessKeyId']
        secretKey = creadentials['SecretAccessKey']
        sessionToken = creadentials['SessionToken']
        accountName = arn.split(':')[4]
        get_ec2_instance_inventory(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_ec2_volume(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_ec2_snapshot(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_vpc_info(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_vpc_subnet_info(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_route_table_info(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_internet_gateway_info(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_eip_info(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_nacl_info(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_security_group(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_iam_groups(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_iam_users(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_iam_roles(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_iam_policies(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_saml_idps(accountName,arn,accessKey,secretKey,sessionToken,outFile)
        get_s3_info(accountName,arn,accessKey,secretKey,sessionToken,outFile)


    currentYear = datetime.now().year
    currentMonth = datetime.now().month
    accountId = boto3.client('sts').get_caller_identity()['Account']
    targetKeyName = str(accountId)+"/"+str(currentYear)+"/"+str(currentMonth)+"/"+fName
    # targetBucketName = os.environ['bucketName']
    targetBucketName = 'arindamawsinventory'
    s3.meta.client.upload_file(fPath, targetBucketName, targetKeyName)
