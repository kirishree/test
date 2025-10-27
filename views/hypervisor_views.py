from rest_framework.views import APIView
from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
#from openstack import exceptions as os_exceptions
import logging
#from openstack import connection
logger = logging.getLogger('cloud')
from custom_log_info import custom_log_data, custom_log
from .auth_views import auth_token, system_admin_auth
import requests
from django.http import JsonResponse
from keystoneauth1.identity import v3
from keystoneauth1 import session

from api.models import RegisteredUser, Subscription, FlavorPricing
from collections import defaultdict
#Cache
from django.core.cache import cache
from decouple import config
PROJECT_OVERVIEW_CACHE_TIME = int(config('PROJECT_OVERVIEW_CACHE_TIME'))

NOVA_URL = "http://controller:8774/v2.1"  # Change to your controller's API URL
def get_context(request):
        conn = request.keystone_conn  
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        role = request.role
        return conn, user_info, org, project_id, role


class ComputeOverviewView(APIView):
    @swagger_auto_schema(
        operation_summary="Compute Overview",
        tags=['Hypervisor Management'],
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
        connuser, user_info, org, project_id, role = get_context(request)
        try:            
            servers = list(connuser.compute.servers())
            server_count = 0
            for s in servers:
                if s.project_id != project_id:
                    continue
                server_count +=1
            nova_quota = connuser.compute.get_quota_set(project_id)            
            # Network (Neutron)
            neutron_quota = connuser.network.get_quota(project_id)
            networks = list(connuser.network.networks(project_id=project_id))
            ports = list(connuser.network.ports(project_id=project_id))
            floating_ips = list(connuser.network.ips(project_id=project_id))
            sec_groups = list(connuser.network.security_groups(project_id=project_id))
            sec_group_rules = list(connuser.network.security_group_rules(project_id=project_id))
            keypairs = list(connuser.compute.keypairs(project_id=project_id))
            routers = list(connuser.network.routers(project_id = project_id))
            usage = connuser.compute.get_usage(project_id)  
            if usage.total_memory_mb_usage:      
                used_ram = usage.total_memory_mb_usage  # RAM in MB
            else:
                used_ram = 0
            if usage.total_vcpus_usage:
                used_vcpus = usage.total_vcpus_usage
            else:
                used_vcpus = 0
            used_disk = usage.total_local_gb_usage
            total_hours = usage.total_hours
            subnets = list(connuser.network.subnets(project_id=project_id))     

            #cinder block
            cinder_quota = connuser.block_storage.get_quota_set(project_id, usage=True)
            #print(cinder_quota)
            total_volumes = cinder_quota.volumes
            total_snapshots = cinder_quota.snapshots
            total_gigabytes = cinder_quota.gigabytes 
            cinder_usage = cinder_quota.usage
            used_volumes = cinder_usage["volumes"]
            used_snapshots = cinder_usage["snapshots"]
            used_gigabytes = cinder_usage["gigabytes"]            

            data = {
            "instances": {"total":nova_quota.instances, "used":server_count},
            "keypairs":{"total":nova_quota.key_pairs, "used":len(keypairs)},
            "vcpus": {"total": nova_quota.cores, "used": used_vcpus},
            "ram": {"total": nova_quota.ram, "used": used_ram},
            "networks": {"total":neutron_quota.networks, "used":len(networks)},
            "ports": {"total":neutron_quota.ports, "used":len(ports)},
            "floating_ips": {"total":neutron_quota.floating_ips, "used":len(floating_ips)},
            "security_groups": {"total":neutron_quota.security_groups, "used":len(sec_groups)},
            "security_group_rules": {"total":neutron_quota.security_group_rules, "used":len(sec_group_rules)},
            "subnets":{"total": neutron_quota.subnets, "used":len(subnets)},
            "routers":{"total":neutron_quota.routers, "used":len(routers)},
            "volumes": {"total": total_volumes, "used":used_volumes},
            "snapshots": {"total":total_snapshots, "used":used_snapshots},
            "volume_storage":{"total":total_gigabytes, "used":used_gigabytes}
            }
            rspstatus = 200
        except Exception as e:
            data = {"message":str(e)}
            if isinstance(e, (KeyError, ValueError)):
                rspstatus = 400  # Bad Request – typically for invalid input
            else:
                rspstatus = 500  # Internal Server Error – unexpected failure 
            logger.error(f"{str(e)}", 
                    extra = custom_log("Project_Overview", user_info, org, {}) 
            )
        return JsonResponse(data, safe=False, status=rspstatus)

class OrganizationDashboardView1new(APIView):
    """
    Returns overview stats for an organization's cloud usage.
    """
    @swagger_auto_schema(
        operation_summary="Dashboard Overview new",
        tags=['Hypervisor Management'],
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
    def get(self, request, *args, **kwargs):
        conn, user_info, org, project_id, role = get_context(request)
        if "admin" not in role:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)    
        try:         
            subscription_info = []
            for subs in Subscription.objects.filter(organization=org):
                if subs.resource_type == "instance":
                    subs_flavor = FlavorPricing.objects.filter(flavor_id = subs.flavor_id).first()
                    if subs_flavor:
                        subscription_info.append({"flavor_name": subs_flavor.name,
                                              "instance_name":subs.resource_name,
                                              "ram": subs_flavor.ram_mb,
                                              "vcpus":subs_flavor.vcpus,
                                              "disk":subs_flavor.disk_gb,
                                              "rate_monthly":subs_flavor.rate_monthly,
                                              "status":subs.status
                                              
                                              })                   
            
            return JsonResponse(subscription_info, safe=False, status=200)
        except Exception as e:
            print(e)
            return JsonResponse({"error": str(e)}, status=500)
        
class OrganizationDashboardView1(APIView):
    """
    Returns overview stats for an organization's cloud usage.
    """
    @swagger_auto_schema(
        operation_summary="Dashboard Overview 1",
        tags=['Hypervisor Management'],
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
    def get(self, request, *args, **kwargs):
        conn, user_info, org, project_id, role = get_context(request)
        if "admin" not in role:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)    
        try:
            projects = conn.identity.projects(domain_id=org.domain_id)
            project_list = []
            project_name_list = []
            allocated_vcpus = 0
            allocated_ram = 0
            allocated_instances = 0
            allocated_storage = 0
            # Dict to store count            
            for pro in projects:    
                quotas = conn.compute.get_quota_set(pro.id)
                allocated_vcpus += quotas.cores
                allocated_ram += quotas.ram  # MB
                allocated_instances += quotas.instances   
                # Storage Quotas (via Cinder)
                volume_quotas = conn.block_storage.get_quota_set(pro.id)
                allocated_storage += volume_quotas.gigabytes  # in GB               
                project_list.append(pro.id)
                project_name_list.append({"id":pro.id,
                                          "name":pro.name})        
            users = conn.identity.users(domain_id=org.domain_id)             
            
            data = {"allocated_instances":allocated_instances,
                    "allocated_vcpus":allocated_vcpus,
                    "allocated_ram_mb":allocated_ram,
                    "allocated_disk": allocated_storage,
                    "subscribed_instances": 0,
                    "subscribed_vcpus":0,
                    "subscribed_ram_mb":0,
                    "subscribed_disk":0,                    
                    "total_users": len(list(users)),
                    "total_projects": len(project_list)                   
                    }
            return JsonResponse(data, safe=False, status=200)
        except Exception as e:
            print(e)
            return JsonResponse({"error": str(e)}, status=500)
               
class OrganizationDashboardView2(APIView):
    """
    Returns overview stats for an organization's cloud usage.
    """
    @swagger_auto_schema(
        operation_summary="Dashboard Overview 2",
        tags=['Hypervisor Management'],
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
    def get(self, request, *args, **kwargs):
        conn, user_info, org, project_id, role = get_context(request)
        power_state_map = {
            0: "NOSTATE",
            1: "RUNNING",
            3: "PAUSED",
            4: "SHUTDOWN",
            6: "CRASHED",
            7: "SUSPENDED"
            }  
        if "admin" not in role:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)    
        try:
            projects = conn.identity.projects(domain_id=org.domain_id)
            project_list = []
            project_name_list = []            
            
            used_vcpus = 0
            used_ram = 0
            used_disk = 0
            instances = []
            server_count = 0
            # Dict to store count
            instance_count = defaultdict(int)
            # Dict to store global power state counts
            power_state_count = defaultdict(int)
            # Dict to store power state counts per project
            project_power_state_count = defaultdict(lambda: defaultdict(int))
            # Dict to store default project power state counts
            default_project_power_state = defaultdict(int)
            #admin_conn = system_admin_auth()
            for pro in projects:  
                project_list.append(pro.id)
                project_name_list.append({"id":pro.id,
                                          "name":pro.name}) 
                servers = conn.compute.servers(all_projects=True, project_id=pro.id) 
                for server in servers: 
                    #if  server.project_id not in project_list:
                    #    continue         
                    server_count +=1
                    if server.status.lower() == "active":
                        used_vcpus +=int(server.flavor["vcpus"]) 
                        used_ram +=int(server.flavor["ram"])
                        used_disk += int(server.flavor["disk"])   
                    state = power_state_map.get(server.power_state, "UNKNOWN")
                    if server.project_id == project_id:           
                        instances.append({
                            "name": server.name,
                            "id": server.id,
                            "state": state,
                            "launched_at": server.launched_at
                        }) 
                        default_project_power_state[state] += 1 
                    # Global count of instances in each state
                    power_state_count[state] += 1    
                    # Count power states per project
                    project_power_state_count[server.project_id][state] += 1          
                    instance_count[server.project_id] +=  1         
            
            # Ensure all projects exist in dict (even with 0 instances)
            project_info = []                
            for proj in project_name_list:
                if proj["id"] not in instance_count:
                    instance_count[proj["id"]] = 0
                project_info.append({"project_name": proj["name"],
                                     "project_id":proj["id"],
                                     "instance_count":instance_count[proj["id"]],
                                     "power_state": project_power_state_count[proj["id"]]
                                     })               
                         
            data = {
                    "used_instances":server_count,
                    "used_vcpus": used_vcpus,
                    "used_ram_mb":used_ram,
                    "used_disk":used_disk,                    
                    "project_info": project_info,
                    "instance_info":instances,                    
                    "total_projects": len(project_list),
                    "total_power_state": power_state_count,                    
                    "default_project_power_state": default_project_power_state          
                    }
            return JsonResponse(data, safe=False, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

class DashboardProjectView(APIView):
    """
    Returns overview stats for an organization's cloud usage.
    """
    @swagger_auto_schema(
        operation_summary="Dynamic Project Overview ",
        tags=['Hypervisor Management'],
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
        conn, user_info, org, token_project_id, role = get_context(request)
        power_state_map = {
            0: "NOSTATE",
            1: "RUNNING",
            3: "PAUSED",
            4: "SHUTDOWN",
            6: "CRASHED",
            7: "SUSPENDED"
            }  
        if "admin" not in role:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)    
        try:
            instances = [] 
            server_count = 0   
            # Dict to store default project power state counts
            default_project_power_state = defaultdict(int)
            #admin_conn = system_admin_auth()
            servers = conn.compute.servers(all_projects=True, project_id=project_id) 
            for server in servers:
                server_count +=1  
                state =  power_state_map.get(server.power_state, "UNKNOWN")  
                default_project_power_state[state] += 1                               
                instances.append({
                        "name": server.name,
                        "id": server.id,
                        "state": state,
                        "launched_at": server.launched_at
                })          
            data = {                    
                    "instance_info":instances,
                    "default_project_power_state": default_project_power_state               
                    }
            return JsonResponse(data, safe=False, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
