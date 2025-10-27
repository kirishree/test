import requests
import json
import smtplib
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from django.http import JsonResponse
from django.views import View
from rest_framework.views import APIView
from openstack import connection
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from openstack import exceptions as os_exceptions
from datetime import datetime, timedelta
import logging
import statistics
from decimal import Decimal
logger = logging.getLogger('cloud')
from custom_log_info import custom_log_data, custom_log
from api.models import InstanceAlert, Instances, Subscription, UserReachStack
import requests
from django.utils import timezone
from .auth_views import auth_token, system_admin_token, system_admin_auth
from decouple import config
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
smtp_server = config('SMTP_SERVER')  # Your SMTP server address
smtp_port = config('SMTP_PORT')  # SMTP server port (587 for TLS, 465 for SSL)
sender_email = config('SENDER_MAIL_ID')  # Your email address
sender_password = config('SENDER_MAIL_PASSWORD')  # Your email password

def post_mail(subject, message, recipient_list):   
    subject = subject
    body = f'{message}.'
    for receiver_email in recipient_list:
        #receiver_email = "bavya@cloudetel.com"  # Recipient's email address
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = receiver_email
        message['Subject'] = subject
        message.attach(MIMEText(body, 'plain'))    
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()  # Use TLS encryption
            server.login(sender_email, sender_password)
            text = message.as_string()
            server.sendmail(sender_email, receiver_email, text)        
            print("Email sent successfully!")
            server.quit()  # Close the connection to the server
        except Exception as e:       
            print(f"An error occurred while sending Email: {str(e)}")

def get_openstack_conn(token, project_id):
    """Reuse Keystone token & project scope from your login/session."""
    return connection.Connection(
        auth_url="http://controller:5000/v3",
        token=token,
        project_id=project_id,
        compute_api_version="2",
        identity_interface="public",
    )

def get_context(request):
        conn = request.keystone_conn  
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        role = request.role
        return conn, user_info, org, project_id, role

@permission_classes([IsAuthenticated])
class AlertCreateView(APIView):
    """
    Returns CPU utilization & network stats for a given instance.
    Example: /metrics/<instance_id>/
    """
    @swagger_auto_schema(
        operation_summary="Create Alert",
        tags=['Alert Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["instance_id", "alert_type", "threshold", "comparison_operator", "interval"],
            properties={
                "instance_id": openapi.Schema(type=openapi.TYPE_STRING),
                "alert_type": openapi.Schema(type=openapi.TYPE_STRING),
                "threshold": openapi.Schema(type=openapi.TYPE_STRING),
                "comparison_operator": openapi.Schema(type=openapi.TYPE_STRING),
                "interval":openapi.Schema(type=openapi.TYPE_INTEGER)

            }
        ),
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            token = request.headers.get("X-Auth-Token")
            headers = {
                "X-Auth-Token": token,
                "Content-Type": "application/json"
            }
            data = request.data
            instance_id = data.get("instance_id")
            server = conn.compute.get_server(instance_id)
            vcpus = int(server.flavor["vcpus"])
            total_memory_bytes = int(server.flavor["ram"]) * 1024 * 1024 
            alert_type = data.get('alert_type')
            comparison_operator = data.get('comparison_operator')
            threshold = data.get('threshold')
            threshold_percent = Decimal(threshold) / 100
            url = "http://controller:8042/v2/alarms"
            granularity = 300  # or get dynamically: data.get('granularity', 300)
            if alert_type == "cpu":
                calculated_threshold = threshold_percent * vcpus * 1000000000 * granularity
                aggregation_method = "rate:mean"
            elif alert_type == "memory.usage":
                total_memory_bytes = int(server.flavor["ram"]) * 1024 * 1024
                calculated_threshold = threshold_percent * total_memory_bytes
                aggregation_method = "mean"
                
            payload = {
                "name": f"{alert_type}_{instance_id}",
                "type": "gnocchi_resources_threshold",
                "description": f"Trigger when {alert_type} {comparison_operator} {threshold}",
                "enabled": True,
                "severity": "moderate",
                "state": "insufficient data",
                "repeat_actions": False,
                "gnocchi_resources_threshold_rule": {
                    "metric": alert_type,
                    "comparison_operator": comparison_operator,
                    "threshold": float(calculated_threshold),
                    "resource_type": "instance",
                    "resource_id": instance_id,  # Replace with actual instance UUID
                    "aggregation_method": aggregation_method,
                    "granularity": granularity,  # seconds
                    "evaluation_periods": data.get('interval')
                },
                "alarm_actions": [
                    "http://localhost:5002/beapi/instance/alert/trigger"  # You can configure webhook
                ],
                "ok_actions": ["http://localhost:5002/beapi/instance/alert/resolve"],
                "insufficient_data_actions": []
            }
            response = requests.post(url, headers=headers, data=json.dumps(payload))
            aler_response = response.json()
            response = {"mesaage":f"Alert created succesfully {aler_response['name']}"}
        except Exception as e:
            print(e)
            response = {"error":str(e)}
        return JsonResponse(response, status=200)
    
    @swagger_auto_schema(
        operation_summary="Get Alert",
        tags=['Alert Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],        
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request):
        try:
            alerts = []
            conn, user_info, org, project_id, role = get_context(request)
            token = request.headers.get("X-Auth-Token")
            headers = {
                "X-Auth-Token": token,
                "Content-Type": "application/json"
            }
            resp = requests.get("http://controller:8042/v2/alarms", headers=headers)            
            responses = resp.json()
            instance_map = {}
            for res in responses:
                resource_rule = res["gnocchi_resources_threshold_rule"]
                instance_id = resource_rule["resource_id"]
                if  instance_id in instance_map:
                    server_name = instance_map[instance_id]
                else:
                    print("fetch again", instance_id)
                    #server = conn.compute.get_server(resource_rule["resource_id"])
                    #instance_map[instance_id] = server.name
                    #server_name = server.name 
                    subs = Subscription.objects.filter(resource_id=instance_id).first() 
                    if subs:
                        instance_map[instance_id] = subs.resource_name
                        server_name = subs.resource_name
                    else:
                        server_name = ""

                alerts.append({"id":res["alarm_id"],
                               "alert_type": resource_rule["metric"],
                               "description": res["description"],
                               "threshold": f'{res["description"].split(" ")[-1]}%',
                               "granularity": resource_rule["granularity"],
                               "comparison_operator": resource_rule["comparison_operator"],
                               "instance_id": resource_rule["resource_id"],
                               "instance_name": server_name,
                               "severity": res["severity"],
                               "repeat_actions": res["repeat_actions"]   })                
        except Exception as e:
            print(e)
        return JsonResponse(alerts, safe=False, status=200)

@permission_classes([IsAuthenticated])
class AlarmInfoDeleteView(APIView):
    @swagger_auto_schema(
        operation_summary="Alarm Trigger Info",
        tags=['Alert Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request, alarm_id=None):
        try:            
            alertobj = InstanceAlert.objects.filter(alarm_id = alarm_id)
            alertinfo = []
            for alert in alertobj:
                alertinfo.append({  "triggered_at": alert.triggered_at,
                                    "value": alert.threshold,
                                    "resolved": alert.resolved,
                                    "alert_type": alert.alert_type })
        except Exception as e:
            print(str(e))
        return JsonResponse(alertinfo, safe=False, status=200)
    
    @swagger_auto_schema(
        operation_summary="Delete Alert",
        tags=['Alert Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],        
        responses={200: openapi.Response("Success")}
    )
    def delete(self, request, alarm_id=None):
        try:
            
            token = request.headers.get("X-Auth-Token")
            headers = {
                "X-Auth-Token": token,
                "Content-Type": "application/json"
            }
            
            if not alarm_id:
                return JsonResponse({"error": "alarm_id is required"}, status=400)

            url = f"http://controller:8042/v2/alarms/{alarm_id}"
            resp = requests.delete(url, headers=headers)

            if resp.status_code == 204:
                InstanceAlert.objects.filter(alarm_id = alarm_id).delete()
                return JsonResponse({"message": f"Alarm {alarm_id} deleted successfully"}, status=200)
            else:
                return JsonResponse({"error": f"Failed to delete alarm: {resp.text}"}, status=resp.status_code)

        except Exception as e:
            print(e)
            return JsonResponse({"error": str(e)}, status=500)

@api_view(['POST'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def instance_alert_trigger(request):
    data = request.data
    print("alert_data", data)
    alarm_name = data.get("alarm_name")
    if "cpu" in alarm_name:
        instance_id = alarm_name.split("cpu_")[1]
        alert_type = "cpu"
    elif "memory.usage" in alarm_name:
        instance_id = alarm_name.split("memory.usage_")[1]
        alert_type = "memory"   
    alarm_id = data.get('alarm_id')
    token, conn = system_admin_token()    
    server = conn.compute.get_server(instance_id)
    instance_obj = Instances.objects.filter(instance_name=server.name).first()
    org = instance_obj.organization
    user = UserReachStack.objects.filter(organization=org, role="admin").first()
    value = data["reason_data"]["most_recent"]
    headers = {
                "X-Auth-Token": token,
                "Content-Type": "application/json"
            }
    url = f"http://controller:8042/v2/alarms/{alarm_id}"
    response = requests.get(url, headers=headers)
    alarm_data = response.json()    
    threshold_value = alarm_data.get('description').split(" ")[-1]
    alertobj = InstanceAlert.objects.create(            
            instance_id = instance_id,
            organization = org,
            instance_name = server.name,
            metric = alert_type,
            value = value,
            threshold = threshold_value,
            alert_type = alert_type,
            alarm_id = alarm_id,
            alarm_name = data.get('alarm_name')
    )    
    post_mail(
        subject=f"ReachStack: {alert_type} alert for Instance: {server.name} ",
        message=f"Instance: {server.name} exceeding the threshold for {alert_type} by {threshold_value}% \n ReachStack",        
        recipient_list=[user.email],
    )  
    conn.close()
    return Response({"status": "ok"})

@api_view(['POST'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def instance_alert_resolve(request):
    data = request.data
    print("alert_resolve_data", data)       
    InstanceAlert.objects.filter(alarm_id = data.get('alarm_id')).update(
                resolved=True,
                resolved_at=timezone.now() 
    ) 
    instancealertobj = InstanceAlert.objects.get(alarm_id=data.get('alarm_id'))
    org = instancealertobj.organization
    user = UserReachStack.objects.filter(organization=org, role="admin").first()
    alert_type = instancealertobj.alert_type
    server_name = instancealertobj.instance_name
    post_mail(
        subject=f"ReachStack: {alert_type} alert for Instance: {server_name} is Resolved Now",
        message=f"Instance: {server_name} back to the threshold for {alert_type} now \n ReachStack",        
        recipient_list=[user.email],
    )   
    return Response({"status": "ok"})
