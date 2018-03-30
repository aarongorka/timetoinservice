#!/usr/bin/env python3
import os
import boto3
from datetime import datetime, timedelta, tzinfo, timezone
from dateutil.tz import tzlocal, tzutc
import logging
import aws_lambda_logging
import json
from flask import Flask, request
from functools import wraps
import requests
import time
import dateutil.parser

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
    if region:  # already defined in env var or config file
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
    if instance.get('InstanceLifecycle') == 'spot':
        spot_request_id = instance['SpotInstanceRequestId']
        logging.info(json.dumps({"message": "getting spot request time", "instance_id": instance_id, "spot_request_id": spot_request_id}))
        lookup_attributes = [
            {
                'AttributeKey': 'ResourceName',
                'AttributeValue': spot_request_id
            }
        ]
        response = wait_for_cloudtrail_query(lookup_attributes)
        if not response:
            logging.warning(json.dumps({"message": "timed out getting spot instance request info"}))
            return
        event = [x for x in response['Events'] if x['EventName'] == 'RequestSpotInstances'][0]
        request_time = event['EventTime']
        logging.info(json.dumps({"message": "found spot request time", "instance_id": instance_id, "spot_request_id": spot_request_id, "request_time": request_time.timestamp()}))
    else:
        logging.info(json.dumps({"message": "getting on-demand request time", "instance_id": instance_id}))
        lookup_attributes = [
            {
                'AttributeKey': 'ResourceName',
                'AttributeValue': instance_id
            }
        ]
        response = wait_for_cloudtrail_query(lookup_attributes)
        if not response:
            logging.warning(json.dumps({"message": "timed out getting spot instance request info", "instance_id": instance_id}))
            return
        event = [x for x in response['Events'] if x['EventName'] == 'CreateInstance'][0]
        request_time = event['EventTime']
        logging.info(json.dumps({"message": "got on-demand request time", "instance_id": instance_id, "request_time": request_time.timestamp()}))
    return request_time


def wait_for_cloudtrail_query(lookup_attributes):
    start = datetime.utcnow()
    logging.info(json.dumps({"message": "beginning to poll for cloudtrail event", "lookup_attributes": lookup_attributes}))
    response = {"Events": []}
    while response['Events'] == [] and (datetime.utcnow() - start).seconds < 300:
        cloudtrail = boto3.client('cloudtrail')
        try:
            response = cloudtrail.lookup_events(
                LookupAttributes=lookup_attributes,
                StartTime=datetime.utcnow() - timedelta(minutes=120),
                EndTime=datetime.utcnow()
            )
        except botocore.exceptions.ClientError:
            logging.exception(json.dumps({"message": "could not query cloudtrail due to throttling, sleeping for 15s", "lookup_attributes": lookup_attributes, "response": response}, default=str))
            time.sleep(15)
        if response['Events'] == []:
            logging.info(json.dumps({"message": "cloudtrail event not found, sleeping for 5s", "lookup_attributes": lookup_attributes, "response": response}, default=str))
            time.sleep(5)
    if response['Events']:
        end = datetime.utcnow()
        time_taken = (end - start).seconds
        logging.info(json.dumps({"message": "cloudtrail found", "lookup_attributes": lookup_attributes, "response": response}, default=str))
        return response
    else:
        logging.info(json.dumps({"message": "cloudtrail event not found and timeout reached", "lookup_attributes": lookup_attributes, "response": response}, default=str))
        return None


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
    logging.warning(json.dumps({"message": "could not find container instance on any cluster"}))
    return None


def get_task_from_port(tasks, port):
    """Return the task that's listening on a given host port"""

    for task in tasks:
        for container in task['containers']:
            for network_binding in container['networkBindings']:
                if network_binding.get('hostPort') == port:
                    logging.info(json.dumps({"message": "deriving task from instance and port", "task": task}, default=str))
                    return task
    logging.warning(json.dumps({"message": "could not find task on any cluster"}))
    return None


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
    time = datetime.now(timezone.utc)
    logging.info(json.dumps({"message": "polling complete, returning time", "time": time.timestamp(), "target_group_arn": target_group_arn, "targets": targets}))
    return time


def put_cw_data(seconds, dimensions):
        cloudwatch = boto3.client('cloudwatch')
        response = cloudwatch.put_metric_data(
            Namespace='Scaling',
            MetricData=[
                {
                    "MetricName": "TimeToInService",
                    "Dimensions": dimensions,
                    "Value": seconds,
                    "Unit": "Seconds"
                }
            ]
        )


def put_time_to_in_service_from_registertarget(event):
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
        healthy_time = get_healthy_time(target_group_arn, instance_id, port)
        if not healthy_time:
            logging.info(json.dumps({"message": "service already healthy, coud not retrieve seconds", "target_group_arn": target_group_arn, "instance_id": instance_id, "port": port}))
            return
        if event_type == 'ecs':
            request_time = get_container_request_time(instance_id, port)
        elif event_type == 'ec2':
            request_time = get_instance_request_time(instance_id)
        logging.info(json.dumps({"message": "listing tzinfo", "healthy_time": healthy_time.tzinfo, "request_time": request_time.tzinfo}, default=str))
        time_to_in_service = (healthy_time - request_time)
        logging.info(json.dumps({"message": "TimeToInService calculated", "TimeToInService": time_to_in_service.seconds, "target_group_arn": target_group_arn}))
        dimensions = [{"Name": "TargetGroup", "Value": target_group}]
        put_cw_data(time_to_in_service.seconds, dimensions)


def get_asg_from_instance_id(instance_id):
    asg = boto3.client('asg')
    response = asg.describe_auto_scaling_instances(
        InstanceIds=[
            instance_id
        ]
    )
    asg = [instance['AutoScalingGroupName'] for instance in response['AutoScalingInstances']][0]
    return asg


def get_instance_from_ip(ip):
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(
        Filters=[
            {
                "Name": "ip-address",
                "Values": [ip]
            }
        ]
    )
    instance = [x['Instances'][0] for x in response['Reservations']][0]
    logging.info(json.dumps({"message": "finding instance from IP", "instance": instance}, default=str))
    return instance


def put_time_to_in_service_from_signalresource(event):
    """Calculate and upload the TimeToInService metric from a given SignalResource event"""

    logging.info(json.dumps({"message": "received event", "event": event}))
    ip = event['sourceIPAddress']
    signal_time = dateutil.parser.parse(event['eventTime'])
    instance = get_instance_from_ip(ip)
    instance_id = instance['InstanceId']
    request_time = get_instance_request_time(instance_id)
    time_to_in_service = (signal_time - request_time)
    logging.info(json.dumps({"message": "TimeToInService calculated", "TimeToInService": time_to_in_service.seconds}))
    asg = get_asg_from_instance_id(instance_id)
    dimensions = [{"Name": "AutoScalingGroupName", "Value": asg}]
    put_cw_data(time_to_in_service.seconds, dimensions)


@app.route('/timetoinservice/health', methods=['GET'])
def flask_health():
    return json.dumps({'health': 'OK', 'version': os.environ.get('VERSION')})


@app.route('/timetoinservice/event', methods=['POST'])
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

    try:
        event = json.loads(data['Message']).get('detail')
        if event.get('eventName') == "RegisterTargets":
            put_time_to_in_service_from_registertarget(event)
        elif event.get('eventName') == "SignalResource":
            put_time_to_in_service_from_signalresource(event)
        else:
            logging.info(json.dumps({"message": "not a supported event, doing nothing"}))
            return '', 204
    except:
        logging.exception(json.dumps({"message": "failed to put time_to_in_seconds"}))
        return '', 500

    return json.dumps({'status': 'done'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=True)  # threaded to allow healthchecks while serving a request
