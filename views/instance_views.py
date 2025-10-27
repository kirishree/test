from rest_framework.views import APIView
from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from openstack import exceptions as os_exceptions
from rest_framework.exceptions import ValidationError
from .tasks import createserver_task, deleteserver_task, detach_and_cleanup_volumes
import time
from decimal import Decimal
import yaml, base64
#import datetime
import logging
import crypt
import random
import string
from django.core.cache import cache
#from django.utils import timezone
from datetime import datetime, timedelta, timezone as dt_timezone

from .serializers import UpdateSecurityGroupSerializer
logger = logging.getLogger('cloud')
from custom_log_info import custom_log_data, custom_log
from django.db.models import Q
from api.models import (                       
                        FlavorPricing, 
                        SubscriptionInvoice,
                        Subscription,
                        Pricing,
                        Instances, 
                        UserReachStack
                        )
from .payment_views import charge_customer
from keystoneauth1 import session
from keystoneauth1.identity import v3
from openstack import connection
from django.conf import settings
from decouple import config
import requests
import base64
from django.utils import timezone
KEYSTONE_URL = config('KEYSTONE_URL')
logger = logging.getLogger('cloud')
from custom_log_info import custom_log_data, custom_log_celery
GNOCCHI_BASE_URL = "http://controller:8041/v1"
from decouple import config
INSTANCE_CACHE_TIME = int(config('INSTANCE_CACHE_TIME'))
SECURITY_RULES_PER_INSTANCE = int(config('SECURITY_RULES_PER_INSTANCE'))
PORTS_PER_INSTANCE = int(config('PORTS_PER_INSTANCE'))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def key_generate():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    # Serialize private (.pem)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    # Public key (OpenSSH format)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()
    return pem_private, public_key

def get_context(request):
        conn = request.keystone_conn  
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        role = request.role
        return conn, user_info, org, project_id, role

def update_quota(conn, flavor, project_id ):
    try:
        compute_quotas = conn.compute.get_quota_set(project_id).to_dict()
        volume_quotas = conn.block_storage.get_quota_set(project_id).to_dict()
        network_quotas = conn.network.get_quota(project_id).to_dict()
    except Exception as e:
        raise ValidationError(f"Failed to fetch current quotas: {str(e)}")
    
    try:        
        # Nova (compute)
        conn.compute.update_quota_set(
                project_id,
                instances = compute_quotas["instances"] + 1,
                cores = compute_quotas["cores"] + flavor.vcpus,
                ram = compute_quotas["ram"] + flavor.ram
        )

        # Cinder (volume)
        conn.block_storage.update_quota_set(
                project_id,
                gigabytes=volume_quotas["gigabytes"] + flavor.disk,
                volumes=volume_quotas["volumes"] + 1                           
        )

        # Neutron (network)
        if compute_quotas["instances"] == 0:
            conn.network.update_quota(
                project_id,                
                floating_ips = network_quotas["floating_ips"] + 1                
            )
        else:
            conn.network.update_quota(
                project_id,
                networks = network_quotas["networks"] + 1,
                routers = network_quotas["routers"] + 1,
                floating_ips = network_quotas["floating_ips"] + 1,
                security_groups = network_quotas["security_groups"] + 1,
                security_group_rules = network_quotas["security_group_rules"] + SECURITY_RULES_PER_INSTANCE,
                ports = network_quotas["ports"] + PORTS_PER_INSTANCE
            )
    except Exception as e:
        raise ValidationError(f"Error applying quota updates: {str(e)}")

def subscription_create(flavor_obj, org, project_id, user_info, instance_name):
    try:
        #if data["source_type"] == "volume":

        period_start = timezone.now()  # time the server became ACTIVE
        period_end = period_start + timedelta(days=30)  # 1-month validity  
        subscription = Subscription.objects.create(                             
                organization = org,     
                resource_type="instance",                
                project_id=project_id,
                project_name=user_info.get("project_name"),   
                resource_name = instance_name,               
                flavor_id = flavor_obj.id,                
                status="active",
                period_start=period_start,
                billed_upto = period_end,
                next_billing_date = period_end
        )
        flavorprice = FlavorPricing.objects.filter(flavor_id=flavor_obj.id).first()
        invoice = SubscriptionInvoice.objects.create(
                subscription=subscription,
                amount=flavorprice.rate_monthly,
                start_period=period_start,
                end_period=period_end,
                status="unpaid",
        )
        invoice_number = f"INV-{timezone.now().year}-{invoice.id:04d}"
        invoice.invoice_number = invoice_number
        invoice.save(update_fields=["invoice_number"])
            
        logger.info(f"Subscription record created for flavor {flavor_obj.name}",
                extra=custom_log("create_instance", user_info, org, {})
        )
        user = UserReachStack.objects.filter(email=user_info["name"]).first()
        payment_intent = charge_customer(org, user.id, invoice.amount, invoice_number, subscription.id )
        time_sleep_iteration = 10
        while time_sleep_iteration > 0:
            invoice_after_payment = SubscriptionInvoice.objects.filter(invoice_number=invoice_number).first()
            if invoice_after_payment.status == "failed":
                logger.error(f"Payment Failed for flavor {flavor_obj.name}",
                        extra=custom_log("create_instance", user_info, org, {})
                )
                return None                
            if invoice_after_payment.status == "paid":
                logger.info(f"Payment successfull for flavor {flavor_obj.name}",
                        extra=custom_log("create_instance", user_info, org, {})
                )
                return subscription.id
            time.sleep(10)
            time_sleep_iteration -= 1
    except Exception as e:
        print(e)
    return None
    
@permission_classes([IsAuthenticated])
class InstanceListCreateView(APIView):
    @swagger_auto_schema(
        operation_summary="List all instances",
        tags=['Instance Management'],
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
        conn, user_info, org, project_id, role = get_context(request)
        records = Subscription.objects.filter(
                resource_type="instance",
                status="active",
                project_id = project_id
            )
        
        servers = conn.compute.servers()
        server_data = []        
        power_state_map = {
            0: "NOSTATE",
            1: "RUNNING",
            3: "PAUSED",
            4: "SHUTDOWN",
            6: "CRASHED",
            7: "SUSPENDED"
        }     
        now = timezone.now()
        #cache_set_key = 0
        for s in servers:   
            launched_at = s.launched_at
            if launched_at:
                # Parse the string (naive datetime)
                dt = datetime.strptime(launched_at, "%Y-%m-%dT%H:%M:%S.%f")
                # Make it aware in UTC
                launched_time = timezone.make_aware(dt, timezone=dt_timezone.utc)                
                age = now - launched_time
                days = age.days
                hours, remainder = divmod(age.seconds, 3600)
                minutes, secs = divmod(remainder, 60)
                readable_age = f"{days}d {hours}h {minutes}m {secs}s"
            else:
                readable_age = "N/A"
            power_state = s.power_state
            power_state_str = power_state_map.get(power_state, "UNKNOWN")
            task_state = s.task_state  
            # Network Info
            networks_info = []
            if s.addresses:
                for ntwk_name, ntwk_list in s.addresses.items():
                    for ntwk in ntwk_list:
                        mac = ntwk.get("OS-EXT-IPS-MAC:mac_addr")
                        addr = ntwk.get("addr")
                        networks_info.append(f"{ntwk_name} - {addr}, {mac}")

            server_data.append({
                "id": s.id,
                "name": s.name,
                "image_name": "",  # Optional: fetch if needed
                "status": s.status,
                "flavor": s.flavor['id'],
                "networks": networks_info,
                "age": readable_age,
                "power_state": power_state_str,
                "task_state": task_state
            })        
        return JsonResponse(server_data, safe=False, status=200)   
        
    @swagger_auto_schema(
        operation_summary="Launch a new instance",
        tags=['Instance Management'],
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
            required=["name", "source_type", "source_id", "flavor_id", "network_id", "username", "password", "delete_on_termination", "generate_key"],
            properties={
                "name": openapi.Schema(type=openapi.TYPE_STRING),
                "source_type": openapi.Schema(type=openapi.TYPE_STRING),
                "source_id": openapi.Schema(type=openapi.TYPE_STRING),
                "flavor_id": openapi.Schema(type=openapi.TYPE_STRING),
                "network_id": openapi.Schema(type=openapi.TYPE_STRING),
                "key_name": openapi.Schema(type=openapi.TYPE_STRING),
                "security_group": openapi.Schema(type=openapi.TYPE_STRING),
                "username": openapi.Schema(type=openapi.TYPE_STRING),
                "password":openapi.Schema(type=openapi.TYPE_STRING),
                "delete_on_termination":openapi.Schema(type=openapi.TYPE_BOOLEAN),
                "generate_key":openapi.Schema(type=openapi.TYPE_BOOLEAN),
            }
        ),
        responses={202: openapi.Response("Instance creation initiated")}
    )
    def post(self, request):
        token = request.headers.get("X-Auth-Token")
        data = request.data
        try:
            conn, user_info, org, project_id, role = get_context(request)  
            instance_name = data.get('name')
            flavor = conn.compute.get_flavor(data['flavor_id'])            
            subscriton_id = subscription_create(flavor, org, project_id, user_info, instance_name)
            if not subscriton_id:
                return JsonResponse({"error":"Payment Error"}, status=500)
            update_quota(conn, flavor, project_id )
            logger.info(f"Quota updated for new subscrition",
                     extra=custom_log("create_instance", user_info, org, {}))
            # Determine volume size
            size_gb = flavor.disk if flavor.disk > 0 else 10  
            if data["source_type"] == "image" or data["source_type"] == "instance-snapshot":                
                # Create bootable volume from image
                volume = conn.block_storage.create_volume(
                    size=int(size_gb),
                    name=data['name'],
                    image_id=data["source_id"],
                    description=f"Boot Volume - instance {data['name']}"                        
                )  
                volume_id = volume.id
            elif data["source_type"] == "volume":
                volume_id = data["source_id"]
            elif data["source_type"] == "volume-snapshot":
                volume = conn.block_storage.create_volume(
                    size=int(size_gb),
                    name=data['name'],
                    snapshot_id=data["source_id"]         
                ) 
                volume_id = volume.id
            else:
                return JsonResponse({"error": "Source type is invalid"}, status=400)                    
            createserver_task.apply_async(args=[token, user_info, org.id, org.organization_name, data, volume_id, project_id, subscriton_id], countdown=6)
            logger.info(f"Volume created. Once it's available, Instance launch will be initiate",
                     extra=custom_log("create_instance", user_info, org, {}))
            return JsonResponse({
                "message": "Volume created. Once it's available, Instance launch will be initiate"                
            }, status=status.HTTP_202_ACCEPTED)

        except Exception as e:
            logger.error(f"{str(e)}",
                     extra=custom_log("create_instance", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=400)

class InstanceInfoView(APIView):
    @swagger_auto_schema(
        operation_summary="Instance Info",
        tags=['Instance Management'],
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
    def get(self, request, instance_id=None):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            cache_key = f"instanceinfo_{instance_id}"
            instance_details = cache.get(cache_key)        
            if instance_details:
                return JsonResponse(instance_details, safe=False, status=200)
            power_state_map = {
                0: "NOSTATE",
                1: "RUNNING",
                3: "PAUSED",
                4: "SHUTDOWN",
                6: "CRASHED",
                7: "SUSPENDED"
            }
            server = conn.compute.get_server(instance_id)
            launched_at = server.get("launched_at")
            if launched_at:
                now = timezone.now()
                # Parse the string (naive datetime)
                dt = datetime.strptime(launched_at, "%Y-%m-%dT%H:%M:%S.%f")
                # Make it aware in UTC
                launched_time = timezone.make_aware(dt, timezone=dt_timezone.utc)
                #launched_time = datetime.strptime(
                #    launched_at, "%Y-%m-%dT%H:%M:%S.%f"
                #).replace(tzinfo=timezone.now())
                age = now - launched_time
                days = age.days
                hours, remainder = divmod(age.seconds, 3600)
                minutes, secs = divmod(remainder, 60)
                readable_age = f"{days}d {hours}h {minutes}m {secs}s"
            else:
                readable_age = "N/A"
            # Power state & task state directly from servers() output
            power_state = server.get("power_state")
            power_state_str = power_state_map.get(power_state, "UNKNOWN")
            task_state = server.get("task_state")
            # Network Info
            #networks_info = []
            #if server.addresses:
            #    for ntwk_name, ntwk_list in server.addresses.items():
            #        for ntwk in ntwk_list:
            #            mac = ntwk.get("OS-EXT-IPS-MAC:mac_addr")
            #            addr = ntwk.get("addr")
            #            networks_info.append(f"{ntwk_name} - {addr}, {mac}")
            secgroups = conn.network.security_groups(project_id=project_id) 
            sec_group_info = []
            for sec_group in server.security_groups:            
                for secg in secgroups:
                    if secg.name == sec_group['name']:
                        sg = conn.network.get_security_group(secg.id)
                        rules = []
                        for rule in sg.security_group_rules:
                            port_min = rule.get('port_range_min')
                            if not rule.get('port_range_min'):
                                port_min = "Any"
                            port_max = rule.get('port_range_max')
                            if not rule.get('port_range_max'):
                                port_max = "Any"
                            proto = rule['protocol']
                            if not rule['protocol']:
                                proto = "Any"
                            rules.append({
                                'id': rule['id'],
                                'direction': rule['direction'],
                                'protocol': proto,
                                'port_range_min': port_min,
                                'port_range_max': port_max,
                                'remote_ip_prefix': rule.get('remote_ip_prefix'),
                                'ethertype': rule.get('ethertype')
                            })
                        sec_group_info.append({sec_group['name']:rules}) 
            #Image info
            image_name = ''
            os_type = ''
            for volume in server.volumes:
                volume_info = conn.block_storage.get_volume(volume['id']) 
                for vol in volume_info.attachments:                  
                    if vol['device'] == server.root_device_name:
                        image_name = volume_info.volume_image_metadata['image_name']
                        os_type = volume_info.volume_image_metadata['os_type'] 
                        delete_on_termination = volume.get("delete_on_termination") 
                        bootable_volume = volume_info.name
                                           
            server_data = {
                "id": server.id,
                "name": server.name,
                "image_name": image_name,  # Optional: fetch if needed
                "os_type": os_type,
                "status": server.status,
                "flavor": server.flavor['id'],
                "networks": server.addresses,
                "age": readable_age,
                "power_state": power_state_str,
                "task_state": task_state,
                "security_group_info":sec_group_info,
                "bootable_volume": {"name":bootable_volume, 
                                    "delete_on_termination":delete_on_termination}
               
            } 
            # Store in cache
            cache.set(cache_key, server_data, timeout=INSTANCE_CACHE_TIME)     
            return JsonResponse(server_data, safe=False, status=200) 
        except Exception as e:
            logger.error(str(e), extra=custom_log("Get_server_info", user_info, org, {}))
            return JsonResponse({'error': str(e)}, status=500)

def get_bandwidth(conn, token, from_time, to_time, nic_id, user_info, org):
    try:
        headers = {"X-Auth-Token": token}
        results = {}    
        consumed_bandwidth = 0  
        url = f"{GNOCCHI_BASE_URL}/resource/instance_network_interface/{nic_id}"
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        nic_detail = resp.json()        
        metrics = nic_detail.get("metrics", {})
        #print("nic", nic_detail)
        #print(metrics)
        for metric_name in [
                    "network.incoming.bytes",
                    "network.outgoing.bytes",                
                ]:
            metric_id = metrics.get(metric_name)
            #print("metric_id", metric_id)
            if metric_id:                   
                start = datetime.fromisoformat(str(from_time))               
                end = datetime.fromisoformat(str(to_time))
                params = {
                            "start": start.isoformat(),
                            "end": end.isoformat()
                        }      
                measures_url = f"{GNOCCHI_BASE_URL}/metric/{metric_id}/measures"
                m_resp = requests.get(measures_url, headers=headers, params=params)
                m_resp.raise_for_status()
                measures = m_resp.json()
                if measures:
                    cumulative_values = []
                    for i in range(1, len(measures)):
                        t1, g1, v1 = measures[i-1]
                        t2, g2, v2 = measures[i]
                        if start > datetime.fromisoformat(t2.replace("Z", "+00:00")):
                            continue
                        if start <= datetime.fromisoformat(t2.replace("Z", "+00:00")) <= end:   
                            #delta_bytes = v2 - v1
                            #delta_time = g2   # usually 300s
                            #kbps = (delta_bytes / delta_time) / 1024                                   
                            cumulative_values.append(round(v2, 2))                            
                        else:
                            break 
                    #print("cumulative", cumulative_values)
                    actual_usage = cumulative_values[-1] - cumulative_values[0]
                    #print(actual_usage)
                    consumed_bandwidth += actual_usage                   
    except Exception as e:       
        logger.error(f"{str(e)}", 
                    extra = custom_log("Consumed_bandwidth", user_info, org, {})
            )
    consumed_bandwidth_gb = (consumed_bandwidth / 1024) / 1024
    return consumed_bandwidth_gb
                  
@permission_classes([IsAuthenticated])
class InstanceDeleteView(APIView): 
    @swagger_auto_schema(
        operation_summary="Delete instance",
        tags=['Instance Management'],
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
    def delete(self, request, server_id=None):
        try:
            token = request.headers.get("X-Auth-Token")
            if not server_id:
                return JsonResponse({"error": "Missing server_id"}, status=status.HTTP_400_BAD_REQUEST)

            conn, user_info, org, project_id, role = get_context(request)

            server = conn.compute.get_server(server_id)            
            vcpus = int(server.flavor["vcpus"]) 
            ram = int(server.flavor["ram"])
            disk = int(server.flavor["disk"]) 

            if not server:
                return JsonResponse({"error": "Server not found"}, status=status.HTTP_400_BAD_REQUEST)
            
            for ntwk_name, ntwk_list in server.addresses.items():
                for ntwk in ntwk_list:
                    if ntwk.get("OS-EXT-IPS:type") == "floating":
                        floating_ip = ntwk.get("addr")                   
                        # Fetch the floating IP
                        fip = conn.network.find_ip(floating_ip, ignore_missing=True)
                        if fip:               
                            # If associated with a port, first disassociate
                            if fip.port_id:
                                conn.network.update_ip(fip, port_id=None)
                            # Delete the floating IP
                            conn.network.delete_ip(fip, ignore_missing=True)
                            logger.info(f"Floating IP delete initiated before Instance Delete - {server.name}", 
                                extra = custom_log("Delete Instance", user_info, org, {})
                            )
                        break
            serverdict = server.to_dict()
            volumes_to_delete = []
            detachable_volumes = []
            server_name = server.name
            # Separate volumes: detachable vs delete_on_termination
            for attachment in serverdict.get("attached_volumes", []):
                vol_id = attachment.get("id")
                if attachment.get("delete_on_termination", False):
                    volumes_to_delete.append(vol_id)
                detachable_volumes.append(vol_id)
            # Delete the server
            conn.compute.delete_server(server)  
                        
            #Delete the Cache
            cache_key = f"instance_{project_id}"
            cache.delete(cache_key)
            try:
                conn.compute.wait_for_delete(server, wait=120)
            except Exception as wait_err:
                logger.warning(f"Timeout/issue while waiting for instance deletion: {wait_err}",
                        extra=custom_log("delete_instance", user_info, org, {}))
            #Delete the Cache of Network Overview
            cache_key = f"networkoverview_{project_id}"
            cache.delete(cache_key)
            cache_key = f"instanceinfo_{server_id}"
            cache.delete(cache_key)            
            # First detach non-boot volumes
            for vol_id in detachable_volumes:
                try:
                    volume = conn.block_storage.get_volume(vol_id)
                    volume = volume.to_dict()
                    for attach in volume["attachments"]:
                        if attach["server_id"] == server_id:
                            try:
                                server = conn.compute.delete_volume_attachment(server_id, vol_id, ignore_missing=True)
                            except:
                                pass
                            
                            conn.block_storage.detach_volume(vol_id, attach["attachment_id"], force=True)
                            
                            logger.info(f"Detached volume-{vol_id} from instance-{server_name}",
                            extra=custom_log("delete_instance", user_info, org, {}))
                    
                    detach_and_cleanup_volumes.apply_async(args=[token, project_id, server_name, volumes_to_delete, detachable_volumes, user_info, org.id, org.organization_name, server_id, vcpus, ram, disk], countdown=60)
                    response = {"message": f"Instance-{server_name} Deleted. Associated Volume delete initiated"}
                
                except Exception as detach_err:
                    response = {"message": f"Server deleted but Failed to detach volume {vol_id}: {detach_err}"}
                    logger.warning(f"Failed to detach volume {vol_id}: {detach_err}",
                               extra=custom_log("delete_instance", user_info, org, {}))           
            return JsonResponse(response, safe=False, status=status.HTTP_202_ACCEPTED)
        except Exception as e:
            response = {"error": str(e)}
            if isinstance(e, (KeyError, ValueError)):
                rspstatus = 400
            else:
                rspstatus = 500

            logger.error(str(e),
                    extra=custom_log("delete_instance", user_info, org, {}))
            return JsonResponse(response, status=rspstatus)


@permission_classes([IsAuthenticated])
class InstanceConsoleView(APIView):    
    @swagger_auto_schema(
        operation_summary="Get instance Console",
        tags=['Instance Management'],
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
    def get(self, request, server_id=None):
        try:
            if not server_id:
                return JsonResponse({"error": "Missing server_id"}, status=status.HTTP_400_BAD_REQUEST)
            #conn, user_info, org, project_id, role = get_context(request)
            conn = request.keystone_conn  
            console = conn.compute.create_server_remote_console(
                    server=server_id,
                    protocol="vnc",
                    type="novnc"
            )
            return JsonResponse({
                "console_url": console['url'].replace('controller', '5.189.137.88'),
                "type": console['type']
            })
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

def update_quota_resize(conn, project_id, current_vcpus, current_ram, current_disk, newflavor):
    try:
        compute_quotas = conn.compute.get_quota_set(project_id).to_dict()
        volume_quotas = conn.block_storage.get_quota_set(project_id).to_dict()
        network_quotas = conn.network.get_quota(project_id).to_dict()
    except Exception as e:
        raise ValidationError(f"Failed to fetch current quotas: {str(e)}")
    
    try:
        # Nova (compute)
        conn.compute.update_quota_set(
                project_id,                
                cores = compute_quotas["cores"] + newflavor.vcpus - current_vcpus,
                ram = compute_quotas["ram"] + newflavor.ram - current_ram
        )

        # Cinder (volume)
        conn.block_storage.update_quota_set(
                project_id,
                gigabytes=volume_quotas["gigabytes"] + newflavor.disk - current_disk                            
        )
    except Exception as e:
        raise ValidationError(f"Error applying quota updates: {str(e)}")
    
class ResizeInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Resize volume-backed instance safely",
        tags=['Instance Management'],
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
            required=["flavor_id", "server_id"],
            properties={                
                "flavor_id": openapi.Schema(type=openapi.TYPE_STRING),
                "server_id": openapi.Schema(type=openapi.TYPE_STRING) 
            }
        ),
        responses={200: openapi.Response("Success")}
    )
    def post(self, request):
        conn, user_info, org, project_id, role = get_context(request)              
        server_id = request.data.get("server_id")
        new_flavor_id = request.data.get("flavor_id")
        
        # Delete cache
        cache.delete(f"instance_{project_id}")
        cache.delete(f"instanceinfo_{server_id}")
        try:
            # Fetch server and flavor
            server = conn.compute.get_server(server_id)
            #flavor = conn.compute.get_flavor(new_flavor_id)
            server_name = server.name
            current_vcpus = int(server.flavor["vcpus"]) 
            current_ram = int(server.flavor["ram"])
            current_disk = int(server.flavor["disk"]) 
            boot_volume_id = None
            for volume in server.volumes:
                volume_info = conn.block_storage.get_volume(volume['id']) 
                for vol in volume_info.attachments:                  
                    if vol['device'] == server.root_device_name:
                        image_name = volume_info.volume_image_metadata['image_name']
                        os_type = volume_info.volume_image_metadata['os_type'] 
                        delete_on_termination = volume.get("delete_on_termination") 
                        bootable_volume = volume_info.name
                        boot_volume_id = volume_info.id
            fip = None
            for ntwk_name, ntwk_list in server.addresses.items():
                for ntwk in ntwk_list:
                    if ntwk.get("OS-EXT-IPS:type") == "floating":
                        floating_ip = ntwk.get("addr")                   
                        # Fetch the floating IP
                        fip = conn.network.find_ip(floating_ip, ignore_missing=True)
                        if fip:               
                            # If associated with a port, first disassociate
                            if fip.port_id:
                                conn.network.update_ip(fip, port_id=None)                                                       
                        break            
            serverdict = server.to_dict()            
            detachable_volumes = []
            server_name = server.name
            # Separate volumes: detachable vs delete_on_termination
            for attachment in serverdict.get("attached_volumes", []):
                vol_id = attachment.get("id")                
                detachable_volumes.append(vol_id)
            # Delete the server
            conn.compute.delete_server(server)
            try:
                conn.compute.wait_for_delete(server, wait=120)
            except Exception as wait_err:
                logger.warning(f"Timeout/issue while waiting for instance deletion: {wait_err}",
                        extra=custom_log("delete_instance", user_info, org, {}))
            # Delete old instance            
            logger.info(f"Old instance {server_name} deleted",
                        extra=custom_log("Resize Instance", user_info, org, {}))
            #Delete the Cache of Network Overview
            cache_key = f"networkoverview_{project_id}"
            cache.delete(cache_key)
            cache_key = f"instanceinfo_{server_id}"
            cache.delete(cache_key)           
            # First detach non-boot volumes
            for vol_id in detachable_volumes:
                try:
                    volume = conn.block_storage.get_volume(vol_id)
                    volume = volume.to_dict()
                    for attach in volume["attachments"]:
                        if attach["server_id"] == server_id:
                            try:
                                server = conn.compute.delete_volume_attachment(server_id, vol_id, ignore_missing=True)
                            except:
                                pass
                            
                            conn.block_storage.detach_volume(vol_id, attach["attachment_id"], force=True)
                            
                            logger.info(f"Detached volume-{vol_id} from instance-{server_name}",
                            extra=custom_log("resize_instance", user_info, org, {}))
                except Exception as e:
                    print(e)
                    raise Exception(f"{str(e)}")
            if not boot_volume_id:
                raise Exception("Boot volume not found for instance")
            while True:
                volume = conn.block_storage.get_volume(vol_id)
                if volume.status != "available":
                    print("Volume status is not avilable")
                    time.sleep(60)
                else:
                    break
            # Create new instance from the same boot volume
            new_server_name = f"{server_name}-resized"
            #Check about resize of disk storage.
            new_flavor_info =  conn.compute.get_flavor(new_flavor_id)
            new_disk_size = new_flavor_info.disk
            update_quota_resize(conn, project_id, current_vcpus, current_ram, current_disk, new_flavor_info)

            if new_disk_size > current_disk:
                conn.block_storage.extend_volume(boot_volume_id, new_disk_size)
                logger.info(f"Extended volume of server {server_name} to {new_disk_size} GB", extra=custom_log("Resize Instance", user_info, org, {"volume_id": boot_volume_id}))
            #Wait for availability
            while True:
                volume = conn.block_storage.get_volume(vol_id)
                if volume.status != "available":
                    print("Volume status is not avilable")
                    time.sleep(60)
                else:
                    break
            new_server = conn.compute.create_server(
                name=new_server_name,
                flavor_id=new_flavor_id,
                block_device_mapping_v2=[{
                    "boot_index": 0,
                    "uuid": boot_volume_id,
                    "source_type": "volume",
                    "destination_type": "volume",
                    "delete_on_termination": False
                }],
                networks=[{"uuid": net.id} for net in conn.network.networks(project_id=project_id)]
            )
            conn.compute.wait_for_server(new_server)
            if fip:
                # 3. Find the first port of the server
                ports = list(conn.network.ports(device_id=new_server.id))
                if not ports:
                    return JsonResponse(
                        {"error": "No ports found for server"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # 4. Associate floating IP with the first fixed IP of the port
                port = ports[0]
                conn.network.update_ip(
                    fip,
                    port_id=port.id,
                    fixed_ip_address=port.fixed_ips[0]["ip_address"]
                )

            logger.info(f"New instance {new_server_name} created from boot volume",
                        extra=custom_log("Resize Instance", user_info, org, {}))           
            for vol_id in detachable_volumes:
                if vol_id != boot_volume_id:
                    attachment = conn.compute.create_volume_attachment(
                        server=new_server.id,
                        volumeId=vol_id)

            #Close the old billing & Check if any balance amount have to credit        
            record = Subscription.objects.filter(
                resource_id=server_id,
                status="active"
            ).first()                    
            now = timezone.now()            
            balance_duration = record.next_billing_date - now
            hours= balance_duration.total_seconds() / 3600
            balance_hours = round(hours, 2)
            flavorprice = FlavorPricing.objects.filter(flavor_id=record.flavor_id).first()
            balance_amount = flavorprice.rate_hour * Decimal(str(balance_hours))
            record.status = "deleted"
            record.billed_upto = now
            record.save(update_fields=["status", "billed_upto"])
            logger.info("Old Subscription Record Closed.", 
                        extra=custom_log("Delete Instance", user_info, org, {}))
            org.balance_amount += balance_amount
            org.save(update_fields=["balance_amount"])
                       
            #Create New subscription for new flavor
            period_start = timezone.now()  # time the server became ACTIVE
            period_end = period_start + timedelta(days=30)  # 1-month validity  
            subscription = Subscription.objects.create(                             
                organization = org,     
                resource_type="instance",
                resource_id=new_server.id,
                resource_name = new_server.name, 
                project_id=project_id,
                project_name=user_info.get("project_name"),                  
                flavor_id = new_flavor_id,                
                status="active",
                period_start=period_start,
                billed_upto = period_end,
                next_billing_date = period_end
            )
            flavorprice = FlavorPricing.objects.filter(flavor_id=new_flavor_id).first()
            invoice = SubscriptionInvoice.objects.create(
                subscription=subscription,
                amount=flavorprice.rate_monthly,
                start_period=period_start,
                end_period=period_end,
                status="unpaid",
            )
            invoice_number = f"INV-{timezone.now().year}-{invoice.id:04d}"
            invoice.invoice_number = invoice_number
            invoice.save(update_fields=["invoice_number"])
            
            logger.info(f"Subscription record created for instance for new flavor {new_server.name}",
                extra=custom_log_celery("subscription_record", user_info, org.id, org.organization_name, {}))
            user = UserReachStack.objects.filter(email=user_info["name"]).first()
            payment_intent = charge_customer(org, user.id, invoice.amount, invoice_number, subscription.id )
            time_sleep_iteration = 10
            while time_sleep_iteration > 0:
                invoice_after_payment = SubscriptionInvoice.objects.filter(invoice_number=invoice_number).first()
                if invoice_after_payment.status == "failed":
                    logger.error(f"Payment Failed for instance {new_server.name}",
                        extra=custom_log_celery("subscription_record", user_info, org.id, org.organization_name, {})
                    )
                    break
                if invoice_after_payment.status == "paid":
                    logger.info(f"Payment successfull for instance {new_server.name}",
                        extra=custom_log_celery("subscription_record", user_info, org.id, org.organization_name, {})
                    )
                    break
                time.sleep(10)
                time_sleep_iteration -= 1            
            Instances.objects.filter(instance_id=server_id).update(                    
                    instance_id=new_server.id,
                    flavor_id = new_flavor_id
            )    
            return JsonResponse({"message": f"Instance resized safely. New server: {new_server_name}"})
        except os_exceptions.ResourceNotFound:
            logger.error("Instance not found", extra=custom_log("Resize Instance", user_info, org, {}))
            return JsonResponse({"error": "Instance not found"}, status=404)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("Resize Instance", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)

class AttachInterfaceView(APIView):
    @swagger_auto_schema(
        operation_summary="Attach Interface instance",
        tags=['Instance Management'],
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
            required=["port_id", "server_id"],
            properties={                
                "port_id": openapi.Schema(type=openapi.TYPE_STRING),
                "server_id": openapi.Schema(type=openapi.TYPE_STRING) 
            }
        ),
        responses={200: openapi.Response("Success")}
    )
    def post(self, request):
        conn, user_info, org, project_id, role = get_context(request)        
        server_id = request.data.get("server_id")
        port_id = request.data.get("port_id")  # optional: provide fixed IP or network_id instead
        #network_id = request.POST.get("network_id")
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{server_id}"
        cache.delete(cache_key)
        try:
            interface = conn.compute.create_server_interface(server=server_id, port_id=port_id)
            #fixed_ip = request.POST.get("fixed_ip")  # optional
            #interface = conn.compute.create_server_interface(
            #    server=server_id,
            #   net_id=network_id,
            #   fixed_ip=fixed_ip
            #)
            logger.info(f"interface attached {interface.name}", 
                    extra = custom_log("Attach Interface", user_info, org, {})
            )  
            return JsonResponse({"message": "interface attached", "interface_id": interface.port_id}, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", 
                    extra = custom_log("Attach Interface", user_info, org, {})
            ) 
            return JsonResponse({"error": str(e)}, status=500)
        
class DetachInterfaceView(APIView):
    @swagger_auto_schema(
        operation_summary="deattach Interface instance",
        tags=['Instance Management'],
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
            required=["port_id", "server_id"],
            properties={                
                "port_id": openapi.Schema(type=openapi.TYPE_STRING),
                "server_id": openapi.Schema(type=openapi.TYPE_STRING) 
            }
        ),
        responses={200: openapi.Response("Success")}
    )
    def post(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        server_id = request.data.get("server_id")
        port_id = request.data.get("port_id")  # the interface port ID
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{server_id}"
        cache.delete(cache_key)
        try:
            conn.compute.delete_server_interface(port_id, server=server_id)
            logger.info(f"interface deattached", 
                    extra = custom_log("interface deattached", user_info, org, {})
            ) 
            return JsonResponse({"message": "interface detached"}, status=200, safe=False)
        except Exception as e:
            logger.error(f"{str(e)}", 
                    extra = custom_log("Deattach Interface", user_info, org, {})
            ) 
            return JsonResponse({"error": str(e)}, status=500, safe=False)

class SoftRebootInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Soft Reboot instance",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.reboot_server(instance_id, reboot_type="SOFT")
            logger.info(f"Soft reboot initiated for {instance_id}", 
                    extra = custom_log("Soft Reboot", user_info, org, {})
            ) 
            return JsonResponse({"message": f"Soft reboot initiated for {instance_id}"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Soft Reboot", user_info, org, {})
            ) 
            return JsonResponse({"error": str(e)}, status=500)

class HardRebootInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Hard Reboot instance",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.reboot_server(instance_id, reboot_type="HARD")
            logger.info(f"Hard reboot initiated for {instance_id}", 
                    extra = custom_log("Hard Reboot", user_info, org, {})
            ) 
            return JsonResponse({"message": f"Hard reboot initiated for {instance_id}"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Hard Reboot", user_info, org, {})
            ) 
            return JsonResponse({"error": str(e)}, status=500)

class ShutdownInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Shutdown instance",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.stop_server(instance_id)         
            logger.info(f"Shutdown initiated for {instance_id}", 
                    extra = custom_log("Shutdown", user_info, org, {})
            ) 
            return JsonResponse({"message": f"Shutdown initiated for {instance_id}"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Shutdown", user_info, org, {})
            ) 
            return JsonResponse({"error": str(e)}, status=500)

class PowerOnInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Power ON instance",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.start_server(instance_id)
            #while True:
            server = conn.compute.get_server(instance_id)               
            logger.info(f"Power ON initiated for {instance_id}", 
                    extra = custom_log("Power ON", user_info, org, {})
            )
            return JsonResponse({"message": f"Power ON initiated for {instance_id}"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Power ON", user_info, org, {})
            ) 
            return JsonResponse({"error": str(e)}, status=500)
        
class UpdateSecurityGroupsView(APIView):
    @swagger_auto_schema(
        operation_summary="Update Security Group",
        tags=['Instance Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],  
        request_body = UpdateSecurityGroupSerializer,      
        responses={200: openapi.Response("Success")}
    )
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            group_names = request.data.get("security_groups", [])
            server = conn.compute.get_server(instance_id)

            # Remove all current groups first
            
            for sg in server["security_groups"]:  
                             
                conn.compute.remove_security_group_from_server(server, sg["name"])

            # Add new ones
            for name in group_names:
                conn.compute.add_security_group_to_server(server, name)
            logger.error(f"Update Security Group - {server.name}", 
                    extra = custom_log("Update Security Group", user_info, org, {})
            ) 
            return JsonResponse({"message": f"Updated security groups for {instance_id}"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Update Security Group", user_info, org, {})
            ) 
            return JsonResponse({"error": str(e)}, status=500)

class InstanceConsoleLogView(APIView):
    @swagger_auto_schema(
        operation_summary="Log",
        tags=['Instance Management'],
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
    def get(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        try:
            log_output = conn.compute.get_server_console_output(instance_id, length=100)
            return JsonResponse({"log": log_output})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-Log", user_info, org, {})
            ) 
            return JsonResponse({"error": str(e)}, status=500)
class RescueInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Rescue",
        tags=['Instance Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            ),        
        ], 
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["admin_pass"],
            properties={                
                "admin_pass": openapi.Schema(type=openapi.TYPE_STRING)
            }
        ),    
        responses={200: openapi.Response("Success")}
    )
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            password = request.data.get("admin_pass", None)
            result = conn.compute.rescue_server(instance_id, admin_pass=password)
            logger.info(f"Instance rescued - {instance_id}", 
                    extra = custom_log("Instance-Rescue", user_info, org, {})
            )
            return JsonResponse({"message": "Instance rescued", "details": result})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-Rescue", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)
        
class UnrescueInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="UnRescue",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.unrescue_server(instance_id)
            logger.info(f"Instance-UnRescue - {instance_id}", 
                    extra = custom_log("Instance-UnRescue", user_info, org, {})
            )
            return JsonResponse({"message": "Instance unrescued"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-UnRescue", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)

class PauseInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Pause",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.pause_server(instance_id)
            logger.info(f"Instance paused- {instance_id}", 
                    extra = custom_log("Instance-Pause", user_info, org, {})
            )
            return JsonResponse({"message": "Instance paused"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-Pause", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)

class UnpauseInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Unpause",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.unpause_server(instance_id)
            logger.info(f"Instance Unpaused- {instance_id}", 
                    extra = custom_log("Instance-Pause", user_info, org, {})
            )
            return JsonResponse({"message": "Instance unpaused"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-UnPause", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)
class SuspendInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Suspend",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.suspend_server(instance_id)
            logger.info(f"Instance Suspended - {instance_id}", 
                    extra = custom_log("Instance-Suspend", user_info, org, {})
            )
            return JsonResponse({"message": "Instance suspended"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-Suspend", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)
        
class ResumeInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Resume",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.resume_server(instance_id)
            logger.info(f"Instance Resumed- {instance_id}", 
                    extra = custom_log("Instance-Resume", user_info, org, {})
            )
            return JsonResponse({"message": "Instance resumed"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-Resume", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)
        
class ShelveInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Shelve",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.shelve_server(instance_id)
            logger.info(f"Instance shelved- {instance_id}", 
                    extra = custom_log("Instance-Shelve", user_info, org, {})
            )
            return JsonResponse({"message": "Instance shelved"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-Shelve", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)

class UnshelveInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="UnShelve",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.unshelve_server(instance_id)
            logger.info(f"Instance unshelved - {instance_id}", 
                    extra = custom_log("Instance-UnShelve", user_info, org, {})
            )
            return JsonResponse({"message": "Instance unshelved"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-UnShelve", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)

class LockInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Lock",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.lock_server(instance_id)
            logger.info(f"Instance locked - {instance_id}", 
                    extra = custom_log("Instance-lock", user_info, org, {})
            )
            return JsonResponse({"message": "Instance locked"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-lock", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)
        
class UnlockInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="UnLock",
        tags=['Instance Management'],
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
    def post(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        #Delete the Cache
        cache_key = f"instance_{project_id}"
        cache.delete(cache_key)
        cache_key = f"instanceinfo_{instance_id}"
        cache.delete(cache_key)
        try:
            conn.compute.unlock_server(instance_id)
            logger.info(f"Instance unlocked - {instance_id}", 
                    extra = custom_log("Instance-Unlock", user_info, org, {})
            )
            return JsonResponse({"message": "Instance unlocked"})
        except Exception as e:
            logger.error(f"{str(e)}- {instance_id}", 
                    extra = custom_log("Instance-Unlock", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)
        
class GetAttachedPortsInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Get Attached Ports",
        tags=['Instance Management'],
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
    def get(self, request, instance_id):
        conn, user_info, org, project_id, role = get_context(request)
        detachable_ports = []
        try:
            server = conn.compute.get_server(instance_id)
            network_info = server.addresses

            if network_info:
                all_attached_ports = []
                for ntwk_name, ntwk_list in network_info.items():
                    for ntwk in ntwk_list:
                        port = next(conn.network.ports(
                            mac_address=ntwk['OS-EXT-IPS-MAC:mac_addr']
                        ), None)
                        if port:
                            all_attached_ports.append(port)

                # Only add ports that are not the last one
                if len(all_attached_ports) > 1:
                    for port in all_attached_ports:
                        detachable_ports.append({
                            "name": port.name,
                            "id": port.id
                        })
            return JsonResponse(detachable_ports, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)} - {instance_id}",
                extra=custom_log("Get Attached Ports", user_info, org, {}))
            return JsonResponse([], safe=False, status=500)

class SnapshotsInstanceView(APIView):
    @swagger_auto_schema(
        operation_summary="Create Snapshots",
        tags=['Instance Management'],
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
            required=["server_id", "name"],
            properties={                
                "name": openapi.Schema(type=openapi.TYPE_STRING),     
                "server_id": openapi.Schema(type=openapi.TYPE_STRING)                            
            }
        ),      
        responses={200: openapi.Response("Success")}
    )
    def post(self, request):
        conn, user_info, org, project_id, role = get_context(request)        
        try:
            data = request.data
            server_id = data.get("server_id")
            #Delete the Cache
            cache_key = f"instance_{project_id}"
            cache.delete(cache_key)
            cache_key = f"instanceinfo_{server_id}"
            cache.delete(cache_key)
            snapshot_name = data.get("name")
             # Create instance snapshot
            volume_quotas = conn.block_storage.get_quota_set(project_id).to_dict()
            conn.block_storage.update_quota_set(
                project_id,
                gigabytes=volume_quotas["gigabytes"] + 50,
                volumes=volume_quotas["volumes"] + 1                           
            )
            #compute_quotas = conn.compute.get_quota_set(project_id).to_dict()
            #print(volume_quotas)           
            image = conn.compute.create_server_image(
                server=server_id,
                name=snapshot_name
            )
            logger.info(f"Snapshot creation initiated - {server_id}", 
                    extra = custom_log("Create Instance-snapshot", user_info, org, {})
            )
            return JsonResponse({
                "message": "Snapshot creation initiated",
                "snapshot_id": image.id,
                "status": image.status
            })
        except Exception as e:
            logger.error(f"{str(e)}- {server_id}", 
                    extra = custom_log("Create Instance-snapshot", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)  
        
class AllocateFloatingIPView(APIView):
    """
    Allocate a floating IP from an external network
    and associate it with a given instance (server).
    """
    @swagger_auto_schema(
        operation_summary="Allocate Floating IP",
        tags=['Instance Management'],
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
            required=["server_id", "network_id"],
            properties={                
                "server_id": openapi.Schema(type=openapi.TYPE_STRING),     
                "network_id": openapi.Schema(type=openapi.TYPE_STRING)                            
            }
        ),      
        responses={200: openapi.Response("Success")}
    )
    def post(self, request, *args, **kwargs):
        conn, user_info, org, project_id, role = get_context(request)
        server_id = request.data.get("server_id")
        network_id = request.data.get("network_id")  # external/public network

        if not server_id or not network_id:
            return JsonResponse(
                {"error": "server_id and network_id are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            try:
                # 1. Allocate a floating IP
                floating_ip = conn.network.create_ip(floating_network_id=network_id)

                # 2. Get the server
                server = conn.compute.get_server(server_id)
            except Exception as e:
                return JsonResponse(
                    {"error": "Server/Network not Found"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 3. Find the first port of the server
            ports = list(conn.network.ports(device_id=server.id))
            if not ports:
                return JsonResponse(
                    {"error": "No ports found for server"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # 4. Associate floating IP with the first fixed IP of the port
            port = ports[0]
            conn.network.update_ip(
                floating_ip,
                port_id=port.id,
                fixed_ip_address=port.fixed_ips[0]["ip_address"]
            )
            logger.info(f"Floating IP creation initiated - {server_id}", 
                    extra = custom_log("Create Floating-IP", user_info, org, {})
            )
            #verify Floating IP is allocated            
            floating_ip = conn.network.get_ip(floating_ip.id)
            if floating_ip.port_id == port.id:                
                existing = Subscription.objects.filter(resource_id=floating_ip.id, status="active", resource_type="floating_ip").first()
                if existing:
                    logger.info(f"Subscription for Floating IP already exists for {server.name} (running). Skipping create.",
                                extra=custom_log("create_subscription_floating_ip", user_info, org, {}))            
                else:
                    # Create billing record
                    from_time = timezone.now()  # time the server became ACTIVE
                    to_time = from_time + timedelta(days=30)  # 1-month validit
                    subscription = Subscription.objects.create(
                        organization = org,     
                        resource_type="floating_ip",
                        resource_id=floating_ip.id,
                        resource_name = floating_ip.floating_ip_address,
                        project_id=project_id,
                        project_name=user_info.get("project_name"),                         
                        related_instance_id = server.id,  
                        related_instance_name = server.name,   
                        period_start = from_time, # available once ACTIVE
                        billed_upto = to_time,
                        next_billing_date = to_time,
                        status="active"
                    )
                    logger.info(f"Subscription record for Floating IP created for instance {server.name}",
                        extra=custom_log("create_billing_floating_ip", user_info, org, {}))
                    
                    hours_used = (to_time - from_time).total_seconds() / 3600
                    hours_used = round(hours_used, 2)
                    price = Pricing.objects.latest("created_at")
                    amount = price.price_per_fip_hr * Decimal(str(hours_used))
                    invoice = SubscriptionInvoice.objects.create(
                        subscription=subscription,
                        amount=amount,
                        start_period=from_time,
                        end_period=to_time,
                        status="unpaid",
                    )
                    invoice_number = f"INV-{timezone.now().year}-{invoice.id:04d}"
                    invoice.invoice_number = invoice_number
                    invoice.save(update_fields=["invoice_number"])
                    user = UserReachStack.objects.filter(email=user_info["name"]).first()
                    payment_intent = charge_customer(org, user.id, invoice.amount, invoice_number, subscription.id )
                    logger.info(f"Invoice generated for Floating_ip of instance {server.name}",
                       extra=custom_log("create_billing_floating_ip", user_info, org, {}))
            else:
                logger.error(f"Subscription record for Floating IP not created for instance {server.name}",
                        extra=custom_log("create_billing_floating_ip", user_info, org, {}))
            #Delete the Cache
            cache_key = f"instance_{project_id}"
            cache.delete(cache_key)            
            cache_key = f"instanceinfo_{server_id}"
            cache.delete(cache_key)
            return JsonResponse(
                {
                    "message": "Floating IP allocated and associated successfully",
                    "server_id": server.id,
                    "floating_ip": floating_ip.floating_ip_address,
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"{str(e)} - {server_id}", 
                    extra = custom_log("Create Floating-IP", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)
        
class FloatingIPDeleteView(APIView):
    @swagger_auto_schema(
        operation_summary="Remove Floating IP",
        tags=['Instance Management'],
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
    def delete(self, request, instance_id):
        try:
            conn, user_info, org, project_id, role = get_context(request)            
            # 1. Get the server
            server = conn.compute.get_server(instance_id)
            for ntwk_name, ntwk_list in server.addresses.items():
                for ntwk in ntwk_list:
                    if ntwk.get("OS-EXT-IPS:type") == "floating":
                        floating_ip = ntwk.get("addr")                      
            
            # Fetch the floating IP
            fip = conn.network.find_ip(floating_ip, ignore_missing=True)

            if not fip:
                return JsonResponse({"error": "Floating IP not found"}, status=404)

            # If associated with a port, first disassociate
            if fip.port_id:
                conn.network.update_ip(fip, port_id=None)
            record = Subscription.objects.filter(resource_id=fip.id, status="active", related_instance_id=instance_id, resource_type="floating_ip").first()
            # Delete the floating IP
            conn.network.delete_ip(fip, ignore_missing=True)
            #Delete the Cache
            cache_key = f"instance_{project_id}"
            cache.delete(cache_key)
            cache_key = f"instanceinfo_{instance_id}"
            cache.delete(cache_key)            
            #Delete the Subscription for Floating IP
            if record:
                now = timezone.now()                
                balance_duration = record.next_billing_date - now
                hours= balance_duration.total_seconds() / 3600
                balance_hours = round(hours, 2)
                balance_amount = Decimal('0.00')
                price = Pricing.objects.filter().latest("created_at")
                balance_amount=price.price_per_fip_hr * Decimal(str(balance_hours)) 
                record.status = "deleted"
                record.billed_upto = now
                record.save(update_fields=["status", "billed_upto"])                
                org.balance_amount += balance_amount
                org.save(update_fields=["balance_amount"]) 
                logger.info("Subscription Record for this Floating IP Closed.", 
                        extra=custom_log("Delete Floating IP", user_info, org, {})) 
            else:
                logger.info("No Subscription record found for this Floating IP", 
                        extra=custom_log("Delete Floating IP", user_info, org, {})) 
            logger.info(f"Floating IP deletion initiated - {instance_id}", 
                    extra = custom_log("Remove Floating-IP", user_info, org, {})
            )
            return JsonResponse({"message": "Floating IP removed successfully"})

        except Exception as e:
            logger.error(f"{str(e)} - {instance_id}", 
                    extra = custom_log("Remove Floating-IP", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)
        
class UpdateSecurityGroupView(APIView):
    @swagger_auto_schema(
        operation_summary="Update Security Group",
        tags=['Instance Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],  
        request_body = openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["server_id", "security_group_id"],
            properties={
                "server_id": openapi.Schema(type=openapi.TYPE_STRING),
                "security_group_id": openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING)  # each element is a string
                ),
            },
        ),         
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        try:
            conn, user_info, org, project_id, role = get_context(request)             
            server_id = request.data.get("server_id")
            security_groups = request.data.get("security_group_id")    
            #Delete the Cache
            cache_key = f"instance_{project_id}"
            cache.delete(cache_key)
            cache_key = f"instanceinfo_{server_id}"
            cache.delete(cache_key)       
            # 1. Get the server
            server = conn.compute.get_server(server_id)
            current_sgs = [sg["name"] for sg in server.security_groups]

            # Remove current sg
            for sg in current_sgs:                
                conn.compute.remove_security_group_from_server(server, sg)

            # Add missing
            for sg in security_groups:            
                conn.compute.add_security_group_to_server(server, sg)
            

            logger.info(f"Updated Security Group to instance - {server.name}", 
                    extra = custom_log("Update Security Group", user_info, org, {})
            )
            return JsonResponse({"message": "Security Group Updated"})

        except Exception as e:
            logger.error(f"{str(e)} - {server_id}", 
                    extra = custom_log("Update Security group", user_info, org, {})
            )
            return JsonResponse({"error": str(e)}, status=500)