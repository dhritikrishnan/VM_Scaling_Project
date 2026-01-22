import boto3
import botocore
import requests
import time
import json
import re

########################################
# Constants
########################################
with open('auto-scaling-config.json') as file:
    configuration = json.load(file)

LOAD_GENERATOR_AMI = configuration['load_generator_ami']
WEB_SERVICE_AMI = configuration['web_service_ami']
INSTANCE_TYPE = configuration['instance_type']

########################################
# Tags
########################################
tag_pairs = [
    ("Project", "vm-scaling"),
]
TAGS = [{'Key': k, 'Value': v} for k, v in tag_pairs]

TEST_NAME_REGEX = r'name=(.*log)'

########################################
# Utility functions
########################################


def create_instance(ami, sg_id):
    """
    Given AMI, create and return an AWS EC2 instance object
    :param ami: AMI image name to launch the instance with
    :param sg_id: ID of the security group to be attached to instance
    :return: instance object
    """
    instance = None

    # TODO: Create an EC2 instance
    ec2 = boto3.resource('ec2', region_name='us-east-1')
    instances = ec2.create_instances(
        ImageId=ami,
        InstanceType=INSTANCE_TYPE,
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[sg_id],
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': TAGS
            },
        ]
    )
    instance = instances[0]
    instance.wait_until_running()
    instance.reload()

    return instance


def initialize_test(load_generator_dns, first_web_service_dns):
    """
    Start the auto scaling test
    :param lg_dns: Load Generator DNS
    :param first_web_service_dns: Web service DNS
    :return: Log file name
    """

    add_ws_string = 'http://{}/autoscaling?dns={}'.format(
        load_generator_dns, first_web_service_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string)
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            pass 

    # TODO: return log File name
    return get_test_id(response)


def initialize_warmup(load_generator_dns, load_balancer_dns):
    """
    Start the warmup test
    :param lg_dns: Load Generator DNS
    :param load_balancer_dns: Load Balancer DNS
    :return: Log file name
    """

    add_ws_string = 'http://{}/warmup?dns={}'.format(
        load_generator_dns, load_balancer_dns
    )
    response = None
    while not response or response.status_code != 200:
        try:
            response = requests.get(add_ws_string)
        except requests.exceptions.ConnectionError:
            time.sleep(1)
            pass  

    # TODO: return log File name
    return get_test_id(response)


def get_test_id(response):
    """
    Extracts the test id from the server response.
    :param response: the server response.
    :return: the test name (log file name).
    """
    response_text = response.text

    regexpr = re.compile(TEST_NAME_REGEX)

    return regexpr.findall(response_text)[0]


def destroy_resources():
    """
    Delete all resources created for this task

    You must destroy the following resources:
    Load Generator, Auto Scaling Group, Launch Template, Load Balancer, Security Group.
    Note that one resource may depend on another, and if resource A depends on resource B, you must delete resource B before you can delete resource A.
    Below are all the resource dependencies that you need to consider in order to decide the correct ordering of resource deletion.

    - You cannot delete Launch Template before deleting the Auto Scaling Group
    - You cannot delete a Security group before deleting the Load Generator and the Auto Scaling Groups
    - You must wait for the instances in your target group to be terminated before deleting the security groups

    :param msg: message
    :return: None
    """
    # TODO: implement this method
    print_section('X - Destroying Resources')
    
    asg_client = boto3.client('autoscaling', region_name='us-east-1')
    elbv2 = boto3.client('elbv2', region_name='us-east-1')
    ec2 = boto3.client('ec2', region_name='us-east-1')
    cw = boto3.client('cloudwatch', region_name='us-east-1')
    
    asg_name = 'ASG-Web-Service'
    lb_name = 'ASG-Load-Balancer'
    tg_name = 'ASG-Target-Group'
    lt_name = 'ASG_Launch_Template'
    
   
    print("Deleting Alarms...")
    cw.delete_alarms(AlarmNames=['Web-Service-High-CPU', 'Web-Service-Low-CPU'])

    
    print("Deleting Auto Scaling Group...")
    try:
        asg_client.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
        while True:
            try:
                response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
                if not response['AutoScalingGroups']: break
                if response['AutoScalingGroups'][0]['Status'] == 'Delete in progress':
                    time.sleep(5)
                else:
                    time.sleep(5)
            except:
                break
    except Exception as e:
        print(f"ASG deletion skipped/failed: {e}")

        
    print("Deleting Load Balancer...")
    try:
        
        response = elbv2.describe_load_balancers(Names=[lb_name])
        lb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
        
        
        listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)
        for listener in listeners.get('Listeners', []):
            elbv2.delete_listener(ListenerArn=listener['ListenerArn'])
            
        
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        
        
        waiter = elbv2.get_waiter('load_balancers_deleted')
        waiter.wait(LoadBalancerArns=[lb_arn])
        print("Load Balancer Deleted.")
    except Exception as e:
        print(f"LB deletion skipped: {e}")

    
    print("Deleting Target Group...")
    for _ in range(5):  
        try:
            response = elbv2.describe_target_groups(Names=[tg_name])
            tg_arn = response['TargetGroups'][0]['TargetGroupArn']
            elbv2.delete_target_group(TargetGroupArn=tg_arn)
            print("Target Group Deleted.")
            break
        except botocore.exceptions.ClientError as e:
            if 'ResourceInUse' in str(e):
                print("Target Group still in use, waiting...")
                time.sleep(5)
            elif 'TargetGroupNotFound' in str(e):
                break
            else:
                print(f"TG deletion failed: {e}")
                break
        except Exception as e:
            print(f"TG deletion skipped: {e}")
            break

   
    print("Deleting Launch Template...")
    try:
        ec2.delete_launch_template(LaunchTemplateName=lt_name)
    except Exception as e:
        print(f"LT deletion skipped: {e}")

   
    print("Terminating Load Generator...")
    try:
        response = ec2.describe_instances(Filters=[
            {'Name': 'tag:Project', 'Values': ['vm-scaling']},
            {'Name': 'instance-state-name', 'Values': ['running']}
        ])
        ids = [i['InstanceId'] for r in response['Reservations'] for i in r['Instances']]
        if ids:
            ec2.terminate_instances(InstanceIds=ids)
            waiter = ec2.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=ids)
    except Exception as e:
        print(f"LG termination skipped: {e}")

   
    print("Deleting Security Groups...")
    time.sleep(5)
    for name in ['Elastic_LB', 'LG']:
        try:
            res = ec2.describe_security_groups(GroupNames=[name])
            sg_id = res['SecurityGroups'][0]['GroupId']
            
            # Retry loop for dependency violations
            for _ in range(5):
                try:
                    ec2.delete_security_group(GroupId=sg_id)
                    print(f"SG {name} deleted.")
                    break
                except botocore.exceptions.ClientError as e:
                    if 'DependencyViolation' in str(e):
                        time.sleep(5)
                    else:
                        raise e
        except Exception as e:
            print(f"SG {name} deletion skipped: {e}")

def print_section(msg):
    """
    Print a section separator including given message
    :param msg: message
    :return: None
    """
    print(('#' * 40) + '\n# ' + msg + '\n' + ('#' * 40))


def is_test_complete(load_generator_dns, log_name):
    """
    Check if auto scaling test is complete
    :param load_generator_dns: lg dns
    :param log_name: log file name
    :return: True if Auto Scaling test is complete and False otherwise.
    """
    log_string = 'http://{}/log?name={}'.format(load_generator_dns, log_name)

    # creates a log file for submission and monitoring
    f = open(log_name + ".log", "w")
    log_text = requests.get(log_string).text
    f.write(log_text)
    f.close()

    return '[Test finished]' in log_text


########################################
# Main routine
########################################
def main():
    # BIG PICTURE TODO: Programmatically provision autoscaling resources
    #   - Create security groups for Load Generator and ASG, ELB
    #   - Provision a Load Generator
    #   - Generate a Launch Template
    #   - Create a Target Group
    #   - Provision a Load Balancer
    #   - Associate Target Group with Load Balancer
    #   - Create an Autoscaling Group
    #   - Initialize Warmup Test
    #   - Initialize Autoscaling Test
    #   - Terminate Resources

    print_section('1 - create two security groups')

    PERMISSIONS = [
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 80,
         'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
         'Ipv6Ranges': [{'CidrIpv6': '::/0'}],
         }
    ]

    # TODO: create two separate security groups and obtain the group ids
    ec2 = boto3.resource('ec2', region_name='us-east-1')
    try:
        sg1 = ec2.create_security_group(GroupName='LG', Description='Load Generator')
        sg1.authorize_ingress(IpPermissions=PERMISSIONS)
        sg1.create_tags(Tags=TAGS)
        sg1_id = sg1.id
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
            sgs = list(ec2.security_groups.filter(GroupNames=['LG']))
            sg1 = sgs[0]
            sg1_id = sg1.id
        else:
            raise e

  
    try:
        sg2 = ec2.create_security_group(GroupName='Elastic_LB', Description='Elastic Load Balancer and Auto Scaling Group')
        sg2.authorize_ingress(IpPermissions=PERMISSIONS)
        sg2.create_tags(Tags=TAGS)
        sg2_id = sg2.id
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
            sgs = list(ec2.security_groups.filter(GroupNames=['Elastic_LB']))
            sg2 = sgs[0]
            sg2_id = sg2.id
        else:
            raise e



    print_section('2 - create LG')

    # TODO: Create Load Generator instance and obtain ID and DNS
    lg = create_instance(LOAD_GENERATOR_AMI, sg1_id)
    lg_id = lg.id
    lg_dns = lg.public_dns_name
    print("Load Generator running: id={} dns={}".format(lg_id, lg_dns))

    print_section('3. Create LT (Launch Template)')
    # TODO: create launch Template
    ec2_client = boto3.client('ec2', region_name='us-east-1')

    try:
        ec2_client.create_launch_template(
            LaunchTemplateName='ASG-Launch-Template',
            LaunchTemplateData={
                'ImageId': WEB_SERVICE_AMI,
                'InstanceType': INSTANCE_TYPE,
                'SecurityGroupIds': [sg2_id],
                'Monitoring': {'Enabled': True},
                'TagSpecifications': [{'ResourceType': 'instance', 'Tags': TAGS}]
            }
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidLaunchTemplateName.AlreadyExists':
            pass
        else:
            raise e

    print_section('4. Create TG (Target Group)')
    # TODO: create Target Group
    elbv2 = boto3.client('elbv2', region_name='us-east-1')
    tg_arn = ''

    try:
        response = elbv2.create_target_group(
            Name='ASG-Target-Group',
            Protocol='HTTP',
            Port=80,
            VpcId=sg2.vpc_id,
            HealthCheckProtocol='HTTP',
            HealthCheckPort='80',
            HealthCheckPath='/',
            HealthCheckIntervalSeconds=30,
            HealthCheckTimeoutSeconds=5,
            HealthyThresholdCount=2,
            UnhealthyThresholdCount=2,
            TargetType='instance'
        )
        tg_arn = response['TargetGroups'][0]['TargetGroupArn']
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DuplicateTargetGroupName':
            response = elbv2.describe_target_groups(Names=["ASG-Target-Group"])
            tg_arn = response['TargetGroups'][0]['TargetGroupArn']
            print("Target Group exists, retrieved ARN")
        else:
            raise e

    print_section('5. Create ELB (Elastic/Application Load Balancer)')

    # TODO create Load Balancer
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    lb_name = "ASG-Load-Balancer"
    lb_arn = ''
    lb_dns = ''
    print("lb started. ARN={}, DNS={}".format(lb_arn, lb_dns))
    vpc = ec2.Vpc(sg2.vpc_id)
    subnets = list(vpc.subnets.all())
    
    selected_subnet_ids = []
    seen_azs = set()
    
    for subnet in subnets:
        az = subnet.availability_zone
        if az not in seen_azs:
            selected_subnet_ids.append(subnet.id)
            seen_azs.add(az)
            
            if len(seen_azs) >= 2:
                break

    try:
        response = elbv2.create_load_balancer(
            Name="ASG-Load-Balancer",
            Subnets=selected_subnet_ids,
            SecurityGroups=[sg2_id],
            Scheme='internet-facing',
            Tags=TAGS,
            Type='application',
            IpAddressType='ipv4'
        )
        
        lb_data = response['LoadBalancers'][0]
        lb_arn = lb_data['LoadBalancerArn']
        lb_dns = lb_data['DNSName']
        
        print(f"Load Balancer '{lb_name}' created.")
        print(f"ARN: {lb_arn}")
        print(f"DNS: {lb_dns}")

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DuplicateLoadBalancerName':
            print(f"Load Balancer '{lb_name}' already exists. Retrieving details...")
            response = elbv2.describe_load_balancers(Names=[lb_name])
            lb_data = response['LoadBalancers'][0]
            lb_arn = lb_data['LoadBalancerArn']
            lb_dns = lb_data['DNSName']
            print(f"Retrieved ARN: {lb_arn}")
        else:
            raise e

    print_section('6. Associate ELB with target group')
    # TODO Associate ELB with target group
    try:
        response = elbv2.create_listener(
            LoadBalancerArn=lb_arn,
            Protocol='HTTP',
            Port=80,
            DefaultActions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': tg_arn
                }
            ]
        )
        
        listener_arn = response['Listeners'][0]['ListenerArn']
        print(f"Listener created successfully. ARN: {listener_arn}")
        
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DuplicateListener':
            print("Listener already exists.")
        else:
            raise e


    print_section('7. Create ASG (Auto Scaling Group)')
    # TODO create Autoscaling group

    asg_client = boto3.client('autoscaling', region_name='us-east-1')
    asg_name = 'ASG-Web-Service'

    asg_tags = []
    for t in TAGS:
        asg_tags.append({
            'Key': t['Key'], 
            'Value': t['Value'], 
            'PropagateAtLaunch': True 
        })

    subnet_str = ",".join(selected_subnet_ids)

    try:
        asg_client.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchTemplate={
                'LaunchTemplateName': 'ASG-Launch-Template', 
                'Version': '$Latest'
            },
            MinSize=1,               
            MaxSize=2,               
            DesiredCapacity=1,       
            VPCZoneIdentifier=subnet_str, 
            TargetGroupARNs=[tg_arn],     
            HealthCheckType='EC2',        
            HealthCheckGracePeriod=300,   
            Tags=asg_tags
        )
        print(f"Auto Scaling Group '{asg_name}' created.")

    except botocore.exceptions.ClientError as e:
        if 'AlreadyExists' in str(e):
            print(f"Auto Scaling Group '{asg_name}' already exists.")
        else:
            raise e


    print_section('8. Create policy and attached to ASG')
    # TODO Create Simple Scaling Policies for ASG
    scale_out_policy_arn = ''
    scale_in_policy_arn = ''

    response_out = asg_client.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName='Scale-Out-Policy',
        PolicyType='SimpleScaling',
        AdjustmentType='ChangeInCapacity',
        ScalingAdjustment=1,     
        Cooldown=60              
    )
    scale_out_policy_arn = response_out['PolicyARN']
    #print(f"Scale Out Policy created. ARN: {scale_out_policy_arn}")
    response_in = asg_client.put_scaling_policy(
        AutoScalingGroupName=asg_name,
        PolicyName='Scale-In-Policy',
        PolicyType='SimpleScaling',
        AdjustmentType='ChangeInCapacity',
        ScalingAdjustment=-1,    
        Cooldown=60
    )
    scale_in_policy_arn = response_in['PolicyARN']
    #print(f"Scale In Policy created. ARN: {scale_in_policy_arn}")

    print_section('9. Create Cloud Watch alarm. Action is to invoke policy.')
    # TODO create CloudWatch Alarms and link Alarms to scaling policies

    cw_client = boto3.client('cloudwatch', region_name='us-east-1')

    
    cw_client.put_metric_alarm(
        AlarmName='Web-Service-High-CPU',
        MetricName='CPUUtilization',
        Namespace='AWS/EC2',
        Statistic='Average',
        Period=300,                     
        EvaluationPeriods=1,            
        Threshold=80.0,                 
        ComparisonOperator='GreaterThanThreshold',
        Dimensions=[
            {
                'Name': 'AutoScalingGroupName',
                'Value': asg_name
            },
        ],
        AlarmActions=[scale_out_policy_arn] 
    )
    print("Alarm 'Web-Service-High-CPU' created.")

   
    cw_client.put_metric_alarm(
        AlarmName='Web-Service-Low-CPU',
        MetricName='CPUUtilization',
        Namespace='AWS/EC2',
        Statistic='Average',
        Period=300,                     
        EvaluationPeriods=1,
        Threshold=20.0,                 
        ComparisonOperator='LessThanThreshold',
        Dimensions=[
            {
                'Name': 'AutoScalingGroupName',
                'Value': asg_name
            },
        ],
        AlarmActions=[scale_in_policy_arn]  
    )    


    print_section('10. Submit ELB DNS to LG, starting warm up test.')
    warmup_log_name = initialize_warmup(lg_dns, lb_dns)
    while not is_test_complete(lg_dns, warmup_log_name):
        time.sleep(1)

    print_section('11. Submit ELB DNS to LG, starting auto scaling test.')
    # May take a few minutes to start actual test after warm up test finishes
    log_name = initialize_test(lg_dns, lb_dns)
    while not is_test_complete(lg_dns, log_name):
        time.sleep(1)

    destroy_resources()


if __name__ == "__main__":
    main()
