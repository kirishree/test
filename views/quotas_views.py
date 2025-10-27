# api/views/quotas.py
from rest_framework.views import APIView
from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from openstack import exceptions as os_exceptions
from rest_framework.exceptions import ValidationError
import logging
logger = logging.getLogger('cloud')
import onboarding
from custom_log_info import custom_log_data, custom_log
from django.core.cache import cache
def get_context(request):
        conn = request.keystone_conn  
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        role = request.role
        return conn, user_info, org, project_id, role

class QuotaGetView(APIView):
    @swagger_auto_schema(
        operation_summary="Current project Quota info",
        tags=['Quota Management'],
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
    def get(self, request, project_id):
        """Get quotas for a project (default: current token's project)."""
        conn = request.keystone_conn
        token_project_id = request.token_project_id 
        role = request.role
        if "admin" not in role:            
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)  
        try:
            compute_quotas = conn.compute.get_quota_set(project_id).to_dict()
            volume_quotas = conn.block_storage.get_quota_set(project_id).to_dict()
            network_quotas = conn.network.get_quota(project_id).to_dict()
            return JsonResponse({
                "project_id": project_id,
                "instances":compute_quotas["instances"],
                "cores":compute_quotas["cores"],
                "ram":compute_quotas["ram"],
                            
                "disk":volume_quotas["gigabytes"],          
                "volumes":volume_quotas["volumes"],

                "floating_ips":network_quotas["floating_ips"],
                "networks":network_quotas["networks"],                
                "routers":network_quotas["routers"],
                "security_groups":network_quotas["security_groups"]            
            }, safe=False, status=200)
        except Exception as e:
            raise ValidationError(f"Error fetching quotas: {str(e)}")
        
class UnallotedQuotaGetView(APIView):
    @swagger_auto_schema(
        operation_summary="Unalloted Quota info",
        tags=['Quota Management'],
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
        """Get quotas for a project (default: current token's project)."""
        conn = request.keystone_conn
        org = request.org
        project_id = request.token_project_id 
        role = request.role
        if "admin" not in role:            
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)  
        try:            
            subscribed_quota = {"instances":org.total_instance,
                                "vcpus": org.total_instance * 2,
                                "ram_mb": org.total_instance * 2048,
                                "volumes": org.total_instance * 2,
                                "volume_gb": org.total_instance * 100,
                                "networks": org.total_instance,
                                "routers": org.total_instance,
                                "floating_ips": org.total_instance,
                                "security_groups": org.total_instance}
                      
            response = {"subscribed_quota": subscribed_quota,
                        "unalloted_quota":{                
                                        "instances":org.unalloted_instances,
                                        "cores":org.unalloted_vcpus,
                                        "ram":org.unalloted_ram_mb,                            
                                        "disk":org.unalloted_volume_gb,                         
                                        "volumes":org.unalloted_volumes,
                                        "floating_ips":org.unalloted_floating_ips,
                                        "networks": org.unalloted_networks,                            
                                        "routers":org.unalloted_routers,
                                        "security_groups": org.unalloted_security_groups
                                    } 
                        }        
            return JsonResponse(response, safe=False, status=200)
        except Exception as e:
            raise ValidationError(f"Error fetching quotas: {str(e)}")

class CheckSubscriptionView(APIView):
    @swagger_auto_schema(
        operation_summary="Check Subscription",
        tags=['Quota Management'],
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
            properties={
                "password": openapi.Schema(type=openapi.TYPE_STRING)
            }
        ),
        responses={200: openapi.Response("Success")}
    )
    def post(self, request):
        """Get quotas for a project (default: current token's project)."""
        conn = request.keystone_conn
        org = request.org
        project_id = request.token_project_id 
        role = request.role
        user_info = request.keystone_user_info
        username = user_info.get("name")
        password = request.data.get("password")        
        if "admin" not in role:            
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)  
        try: 

            message = onboarding.check_subscription_onboarding(username, password)  
            org.refresh_from_db()
            subscribed_quota = {"instances":org.total_instance,
                                "vcpus": org.total_instance * 2,
                                "ram_mb": org.total_instance * 2048,
                                "volumes": org.total_instance * 2,
                                "volume_gb": org.total_instance * 100,
                                "networks": org.total_instance,
                                "routers": org.total_instance,
                                "floating_ips": org.total_instance,
                                "security_groups": org.total_instance}
                      
            response = {"subscribed_quota": subscribed_quota,
                        "unalloted_quota":{                
                                        "instances":org.unalloted_instances,
                                        "cores":org.unalloted_vcpus,
                                        "ram":org.unalloted_ram_mb,                            
                                        "disk":org.unalloted_volume_gb,                         
                                        "volumes":org.unalloted_volumes,
                                        "floating_ips":org.unalloted_floating_ips,
                                        "networks": org.unalloted_networks,                            
                                        "routers":org.unalloted_routers,
                                        "security_groups": org.unalloted_security_groups
                                    },
                        "message": message 
                        }        
            return JsonResponse(response, safe=False, status=200)
        except Exception as e:
            raise ValidationError(f"Error fetching subscrition: {str(e)}")

class QuotaUpdateView(APIView):
    @swagger_auto_schema(
        operation_summary="Quota update",
        tags=['Quota Management'],
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
            properties={
                "instances": openapi.Schema(type=openapi.TYPE_INTEGER, description="Max number of instances"),
                "vcpus": openapi.Schema(type=openapi.TYPE_INTEGER, description="Max number of vCPUs"),
                "ram_mb": openapi.Schema(type=openapi.TYPE_INTEGER, description="Max RAM in MB"),
                "volumes": openapi.Schema(type=openapi.TYPE_INTEGER, description="Max number of volumes"),
                "volume_gb": openapi.Schema(type=openapi.TYPE_INTEGER, description="Max total volume size in GB"),
                
                "networks": openapi.Schema(type=openapi.TYPE_INTEGER, description="Max number of networks"),
                "routers": openapi.Schema(type=openapi.TYPE_INTEGER, description="Max number of routers"),
                "floating_ips": openapi.Schema(type=openapi.TYPE_INTEGER, description="Max number of floating IPs"),
                "security_groups": openapi.Schema(type=openapi.TYPE_INTEGER, description="Max number of security groups"),
                "project_id":  openapi.Schema(type=openapi.TYPE_STRING, description="ID of the project"),
            }
        ),
        responses={200: openapi.Response("Success")}
    )
    def put(self, request):
        """Update quotas for a project."""
        conn, user_info, org, token_project_id, role = get_context(request)
        #if not project_id:
        #    project_id = request.token_project_id

        data = request.data or {}
        project_id = data.get('project_id')

        # --- Fetch current quotas ---
        try:
            compute_quotas = conn.compute.get_quota_set(project_id).to_dict()
            volume_quotas = conn.block_storage.get_quota_set(project_id).to_dict()
            network_quotas = conn.network.get_quota(project_id).to_dict()
        except Exception as e:
            raise ValidationError(f"Failed to fetch current quotas: {str(e)}")

        # --- Prepare requested values with defaults ---
        requested = {
            "instances": data.get("instances", compute_quotas["instances"]),
            "vcpus": data.get("vcpus", compute_quotas["cores"]),
            "ram_mb": data.get("ram_mb", compute_quotas["ram"]),
            "volumes": data.get("volumes", volume_quotas.get("volumes", 10)),
            "volume_gb": data.get("volume_gb", volume_quotas.get("gigabytes", 1000)),            
            "networks": data.get("networks", network_quotas.get("networks", 10)),
            "routers": data.get("routers", network_quotas.get("routers", 10)),
            "floating_ips": data.get("floating_ips", network_quotas.get("floating_ips", 50)),
            "security_groups": data.get("security_groups", network_quotas.get("security_groups", 10)),
        }

        # --- Validation against organization unallocated pools ---
        def check_limit(resource, new_val, old_val, org_field, error_msg):
            if new_val > old_val:
                needed = new_val - old_val
                if getattr(org, org_field) < needed:
                    raise ValidationError({"error": f"{error_msg} Exceeded"})
                return -needed  # decrease pool
            elif new_val < old_val:
                return (old_val - new_val)  # release pool
            return 0  # no change

        try:
            changes = {
                "instances": check_limit("instances", requested["instances"], compute_quotas["instances"], "unalloted_instances", "Instance Limits"),
                "vcpus": check_limit("vcpus", requested["vcpus"], compute_quotas["cores"], "unalloted_vcpus", "VCPU Limits"),
                "ram_mb": check_limit("ram_mb", requested["ram_mb"], compute_quotas["ram"], "unalloted_ram_mb", "RAM Limits"),
                "volumes": check_limit("volumes", requested["volumes"], volume_quotas["volumes"], "unalloted_volumes", "Volume Limits"),
                "volume_gb": check_limit("volume_gb", requested["volume_gb"], volume_quotas["gigabytes"], "unalloted_volume_gb", "Disk Limits"),
                
                "networks": check_limit("networks", requested["networks"], network_quotas["networks"], "unalloted_networks", "Network Limits"),
                "routers": check_limit("routers", requested["routers"], network_quotas["routers"], "unalloted_routers", "Router Limits"),
                "floating_ips": check_limit("floating_ips", requested["floating_ips"], network_quotas["floating_ips"], "unalloted_floating_ips", "Floating IP Limits"),
                "security_groups": check_limit("security_groups", requested["security_groups"], network_quotas["security_groups"], "unalloted_security_groups", "Security Group Limits"),
            }
            print(changes)
        except ValidationError as e:
            return JsonResponse({"error":e.detail}, status=400)

        # --- Apply changes to OpenStack ---
        try:
            # Nova (compute)
            conn.compute.update_quota_set(
                project_id,
                instances=requested["instances"],
                cores=requested["vcpus"],
                ram=requested["ram_mb"]
            )

            # Cinder (volume)
            conn.block_storage.update_quota_set(
                project_id,
                gigabytes=requested["volume_gb"],
                volumes=requested["volumes"]                
            )

            # Neutron (network)
            conn.network.update_quota(
                project_id,
                networks=requested["networks"],
                routers=requested["routers"],
                floating_ips=requested["floating_ips"],
                security_groups=requested["security_groups"]
            )
        except Exception as e:
            raise ValidationError(f"Error applying quota updates: {str(e)}")

        # --- Update organization DB pools ---        
        org.unalloted_instances += changes["instances"]

        org.unalloted_vcpus += changes["vcpus"]        
        org.unalloted_ram_mb += changes["ram_mb"]
        org.unalloted_volumes += changes["volumes"]
        org.unalloted_volume_gb += changes["volume_gb"]        
        org.unalloted_networks += changes["networks"]
        org.unalloted_routers += changes["routers"]
        org.unalloted_floating_ips += changes["floating_ips"]
        org.unalloted_security_groups += changes["security_groups"]

        org.save(update_fields=[
            "unalloted_instances", "unalloted_vcpus", "unalloted_ram_mb",
            "unalloted_volumes", "unalloted_volume_gb", 
            "unalloted_networks", "unalloted_routers",
            "unalloted_floating_ips", "unalloted_security_groups"
        ])
        #org.save()
        #org.refresh_from_db()
        #print("After save:", org.unalloted_instances, org.unalloted_vcpus)

        return JsonResponse({"message": "Quota updated successfully"}, status=200)

