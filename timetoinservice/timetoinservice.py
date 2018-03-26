#!/usr/bin/env python3
import os
import boto3
from datetime import datetime, timedelta
from dateutil.tz import tzlocal, tzutc
import logging
import aws_lambda_logging
import json
from flask import Flask,request
from functools import wraps
import requests

"""
* RegisterTarget event
* extract id & port
* describe instance, determine if ecs or ec2 and spot or demand
    * if ec2
        * if spot, query cloudtrail logs EventName: 'RequestSpotInstances', ResourceId: instance['SpotInstanceRequestId'] output event time
        * if not, CreateInstance (or just LaunchTime?)
    * if ecs
        * describetasks with filter, output 'createdAt'
* DescribeTargetHealth with TargetDescription
* output difference to CloudWatch with TG (?) as dimension
"""

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

aws_lambda_logging.setup(level=os.environ.get('LOGLEVEL', 'INFO'), env=os.environ.get('ENV'))
logging.info(json.dumps({'message': 'initialising'}))
aws_lambda_logging.setup(level=os.environ.get('LOGLEVEL', 'INFO'), env=os.environ.get('ENV'))

app = Flask(__name__)


def set_region():
    region = None
    session = boto3.session.Session()
    region = session.region_name
    if region: # already defined in env var or config file
        return
    else:
        try:
            region = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document").json()['region']
            boto3.setup_default_session(region_name=region)
        except:
            logging.exception(json.dumps({"message": "getting region failed from instance metadata failed"}))
            pass


def get_instance_request_time(instance_id):
    """For a given instance-id, return the time of the earliest relevant event"""

    logging.info(json.dumps({"message": "getting request time", "instance_id": instance_id}))
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(
        InstanceIds=[instance_id]
    )
    instance = [x['Instances'][0] for x in response['Reservations']][0]
    if instance['InstanceLifecycle'] == 'spot':
        spot_request_id = instance['SpotInstanceRequestId']
        logging.info(json.dumps({"message": "getting spot request time", "instance_id": instance_id, "spot_request_id": spot_request_id}))
        cloudtrail = boto3.client('cloudtrail')
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': spot_request_id
                }
            ],
            StartTime=datetime.utcnow() - timedelta(minutes=60),
            EndTime=datetime.utcnow()
        )
        event = [x for x in response['Events'] if x['EventName'] == 'RequestSpotInstances'][0]
        request_time = event['EventTime']
        logging.info(json.dumps({"message": "found spot request time", "instance_id": instance_id, "spot_request_id": spot_request_id, "request_time": request_time.timestamp()}))
    else:
        logging.info(json.dumps({"message": "getting on-demand request time", "instance_id": instance_id}))
        cloudtrail = boto3.client('cloudtrail')
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': instance_id
                }
            ],
            StartTime=datetime.utcnow() - timedelta(minutes=10),
            EndTime=datetime.utcnow()
        )
        event = [x for x in response['Events'] if x['EventName'] == 'CreateInstance'][0]
        request_time = event['EventTime']
        logging.info(json.dumps({"message": "got on-demand request time", "instance_id": instance_id, "request_time": request_time.timestamp()}))
    return request_time


def get_cluster_and_container_instance_name(instance_id):
    """For a given EC2 instance-id, return the ECS cluster name and the container instance ARN

    There is no API to get the cluster or container instance name from a EC2 instance-id, so we just have to loop through every single cluster and container instance until we find a match"""

    ecs = boto3.client('ecs')
    clusters = ecs.list_clusters()['clusterArns']
    container_instance_arn = None
    for cluster in clusters:
        container_instances = ecs.list_container_instances(cluster=cluster)['containerInstanceArns']
        if container_instances != []:
            response = ecs.describe_container_instances(
                cluster=cluster,
                containerInstances=container_instances
            )
            try:
                container_instance_arn = [instance['containerInstanceArn'] for instance in response['containerInstances'] if instance['ec2InstanceId'] == instance_id][0]
                if container_instance_arn:
                    logging.info(json.dumps({"message": "finding cluster and container instance", "cluster": cluster, "container_instance_arn": container_instance_arn}))
                    return {"cluster": cluster, "container_instance_arn": container_instance_arn}
            except IndexError:
                pass
    raise Exception('Could not find instance on any cluster')


def get_task_from_port(tasks, port):
    """Return the task that's listening on a given host port"""

    for task in tasks:
        for container in task['containers']:
            for network_binding in container['networkBindings']:
                if network_binding.get('hostPort') == port:
                    logging.info(json.dumps({"message": "deriving task from instance and port", "task": task}, default=str))
                    return task
    raise Exception('Could not find task on any cluster')


def get_container_request_time(instance_id, port):
    ecs = boto3.client('ecs')
    response = get_cluster_and_container_instance_name(instance_id)
    cluster = response['cluster']
    container_instance_arn = response['container_instance_arn']
    response = ecs.list_tasks(
        cluster=cluster,
        containerInstance=container_instance_arn
    )
    response = ecs.describe_tasks(
        cluster=cluster,
        tasks=response['taskArns']
    )
    task = get_task_from_port(response['tasks'], port)
    created_at = task['createdAt']
    logging.info(json.dumps({"message": "retrieving container request time", "created_at": created_at.timestamp(), "instance_id": instance_id, "port": port, "cluster": cluster, "container_instance_arn": container_instance_arn}))
    return 


def get_healthy_time(target_group_arn, instance_id, port):
    """Poll until an instance:port is healthy and return the current time"""

    elbv2 = boto3.client('elbv2')
    if port:
        targets = [
            {
                "Id": instance_id,
                "Port": port
            }
        ]
    else:
        targets = [
            {
                "Id": instance_id
            }
        ]
    response = elbv2.describe_target_health(
        TargetGroupArn=target_group_arn,
        Targets=targets
    )
    state = response['TargetHealthDescriptions'][0]['TargetHealth']['State']
    logging.info(json.dumps({"message": "confirming target initial state", "state": state, "target_group_arn": target_group_arn, "targets": targets}))
    if state == "healthy":
        return None  # if the target is already healthy, we probably started polling too late
    waiter = elbv2.get_waiter('target_in_service')
    logging.info(json.dumps({"message": "polling until healthy", "target_group_arn": target_group_arn, "targets": targets}))
    waiter.wait(
        TargetGroupArn=target_group_arn,
        Targets=targets
    )
    time = datetime.utcnow()
    logging.info(json.dumps({"message": "polling complete, returning time", "time": time.timestamp(), "target_group_arn": target_group_arn, "targets": targets}))
    return time


def get_time_to_in_service_from_event(event):
    """Calculate and upload the TimeToInService metric from a given RegisterTarget event"""

    logging.info(json.dumps({"message": "received event", "event": event}))
    targets = event['requestParameters']['targets']
    target_group_arn = event['requestParameters']['targetGroupArn']
    target_group = target_group_arn.split(':')[-1]
    if event['userIdentity']['invokedBy'] == 'ecs.amazonaws.com':
        event_type = 'ecs'
    else:
        event_type = 'ec2'
    for target in targets:
        instance_id = target['id']
        port = target.get('port', None)
        if event_type == 'ecs':
            request_time = get_container_request_time(instance_id, port)
        elif event_type == 'ec2':
            request_time = get_instance_request_time(instance_id)
        healthy_time = get_healthy_time(target_group_arn, instance_id, port)
        if not healthy_time:
            return None
        time_to_in_service = (healthy_time - request_time)
        logging.info(json.dumps({"message": "TimeToInService calculated", "TimeToInService": time_to_in_service.seconds, "target_group_arn": target_group_arn}))
        return time_to_in_service.seconds

def put_cw_data(target_group, seconds):
        cloudwatch = boto3.client('cloudwatch')
        response = cloudwatch.put_metric_data(
            Namespace='Scaling',
            MetricData=[
                {
                    "MetricName": "TimeToInService",
                    "Dimensions": [{"Name": "TargetGroup", "Value": target_group}],
                    "Value": seconds,
                    "Unit": "Seconds"
                }
            ]
        )

@app.route('/timetoinservice/health', methods=['GET'])
def flask_health():
    return json.dumps({'health': 'OK'})

@app.route('/timetoinservice/registertargets', methods=['POST'])
def flask_handler():
    data = request.get_json(force=True)
    logging.info(json.dumps({"message": "received post", "data": data}))
    set_region()
    if not os.environ['TIMETOINSERVICE_TOPICARN'] == data.get('TopicArn'):
            logging.info(json.dumps({"message": "not from SNS, ignoring"}))
            return '', 204
    if data.get('Type') == "SubscriptionConfirmation":
        response = requests.get(data['SubscribeURL'])
        logging.info(json.dumps({'subscription confirmation': 'sent', 'response': response.status_code}))
        return '', 200

    seconds = None
    try:
        event = json.loads(data['Message']).get('detail')
        if event.get('eventName') != "RegisterTargets":
            logging.info(json.dumps({"message": "not a RegisterTargets event, doing nothing"}))
            return '', 204
        seconds = get_time_to_in_service_from_event(event)
    except:
        logging.exception(json.dumps({"message": "failed to get seconds"}))
        return '', 500

    if seconds:
        target_group_arn = event['requestParameters']['targetGroupArn']
        target_group = target_group_arn.split(':')[-1]
        put_cw_data(seconds, target_group)
    else:
        logging.info(json.dumps({"message": "service already healthy, coud not retrieve seconds"}))
        return '', 200

    return json.dumps({'status': 'done'})


if __name__ == '__main__':
    app.run(host='0.0.0.0')
#    cloudtrail = boto3.client('cloudtrail')
#    response = cloudtrail.lookup_events(
#        LookupAttributes=[
#            {
#                    'AttributeKey': 'EventName',
#                    'AttributeValue': 'RegisterTargets'
#            }
#        ],
#        StartTime=datetime.utcnow() - timedelta(hours=3),
#        EndTime=datetime.utcnow(),
#        MaxResults=10
#    )
#    events = response['Events']
#    logging.info(json.dumps({"message": "looking up RegisterTarget events", "num": len(events), "events": events}))
#    for event in events:
#        get_time_to_in_service_from_event(event)
