from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication  # Optional fallback
from rest_framework import serializers
from ipaddress import ip_network
from html import escape
from django.views.decorators.csrf import csrf_exempt
from .serializers import CreateNetworkSerializer, CreateSubnetSerializer, DeleteNetworkSerializer, DeleteSubnetSerializer, UpdateSubnetSerializer, UpdateNetworkSerializer, CreateRouterSerializer, CreatePortSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
from api.models import Organization, RegisteredUser, ProjectID, OrgGroup, OrgGroupUsers
from django.core.cache import cache
import onboarding
from custom_log_info import custom_log_data, custom_log
import logging
from .auth_views import admin_auth
import os
logger = logging.getLogger('cloud')
#from django.db import connection
from keystoneauth1 import session
from decouple import config
from datetime import timedelta
from keystoneauth1.identity import v3
from keystoneauth1.exceptions import Unauthorized
from openstack import connection as os_connection
import json
import requests
import openstack
import ipaddress
controller_ip = config('CONTROLLER_IP')
ONBOARDING_API= config('ONBOARDING_API_URL')
KEYSTONE_URL = config('KEYSTONE_URL')
ADMIN_PASSWORD = config('KEYSTONE_ADMIN_PASSWORD')
NETWORK_CACHE_TIME = int(config('NETWORK_CACHE_TIME'))
DEFAULT_DOMAIN = "Default"
ORG_ADMIN_ROLE = "org-admin"
ORG_USER_ROLE = "org-user"

def subnet_create_fn(conn, network, data, user_info, org):
    try:        
        subnet = conn.network.create_subnet(
                name=data.get('subnet_name'),
                network_id=network.id,
                ip_version=4,
                cidr=data.get('network_address'),
                gateway_ip=data.get('gateway_address'),
                enable_dhcp=data.get('enable_dhcp'),
                allocation_pools=data.get('dhcp_pools'),
                dns_nameservers=[data.get('primary_dns'), data.get('sec_dns')]                
        )
        logger.info(f"Subnet Created with name {data.get('subnet_name')} & {subnet.id}", 
                    extra = custom_log("Create_Subnet", user_info, org, {}) 
        )        
        return 200
    except Exception as e:        
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Create_Subnet", user_info, org, {}) 
        )
        return rspstatus


def network_create_fn(conn, data, user_info, org):
    try:
        project = conn.identity.find_project(data.get('project_name'))
        if not project:
            return {"error": f"Project {data.get('project_name')} is not found"}, 400
        network = conn.network.create_network(
                name=data.get('network_name'),                
                admin_state_up = data.get('admin_state_up'),                                
                project_id=project.id # optional 
                #mtu=int(data.get('mtu', '1450'))
        )

        logger.info(f"Network Created with name {network.name} & {network.id}", 
                    extra = custom_log("Create_Network", user_info, org, {}) 
            )  
        if data.get("create_subnet"):
            existing_subnets = conn.network.subnets(network_id=network.id)
            data["network_address"] = str(ipaddress.ip_network(data.get('network_address'), strict=False))
            print(data["network_address"])
            for subnet in existing_subnets:
                if ip_network(subnet.cidr).overlaps(ip_network(data["network_address"])):
                    return {"error": "Overlapping CIDR with existing subnet"}, 400
            # 2. Create Subnet
            rspstatus = subnet_create_fn(conn, network, data, user_info, org)
            if rspstatus == 200:
                response = {"message": "Network with subnet created successfully"}
            else:
                response = {"error":"Internal Server Error"}
        else:
            response = {"message": "Network Created successfully"}
            rspstatus = 200
    except Exception as e:
        response = {"error":str(e)}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Create_Network", user_info, org, {}) 
        )
    return response, rspstatus  


@swagger_auto_schema(
    method='post',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=CreateNetworkSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_network(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        #Delete the Cache
        project_id = request.token_project_id
        cache_key = f"networks_{project_id}"
        cache.delete(cache_key)
        cache_key = f"networkoverview_{project_id}"
        cache.delete(cache_key) 
        if "admin" not in role:       
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403) 
        #project_id = request.token_project_id 
        data = json.loads(request.body)
        network_name = data.get('network_name')     
        if not network_name:
            return JsonResponse({"message":"Network name is missing"}, status=400)  
        network = conn.network.find_network(data.get('network_name'))
        if network:
            return JsonResponse({"message":"Network already exist"}, status=400)  
        response, rspstatus = network_create_fn(conn, data, user_info, org)
    except Exception as e:
        response = {"error":str(e)}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Create_Network", user_info, org, {}) 
        )
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=CreateSubnetSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_subnet(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        project_id = request.token_project_id 
        data = json.loads(request.body)
        network_name = data.get('network_name') 
        #Delete cache
        cache_key = f"networks_{project_id}"
        cache.delete(cache_key) 
        cache_key = f"networkoverview_{project_id}"
        cache.delete(cache_key) 
        if "admin" not in role:       
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)     
        if not network_name:
            return JsonResponse({"error":"Network name is missing"}, status=400) 
        network = conn.network.find_network(data.get('network_name'))
        if network:
            #Check if subnets will overlap
            existing_subnets = conn.network.subnets(network_id=network.id)
            data["network_address"] = str(ipaddress.ip_network(data.get('network_address'), strict=False))
            print(data["network_address"])
            for subnet in existing_subnets:
                if ip_network(subnet.cidr).overlaps(ip_network(data["network_address"])):
                    return JsonResponse({"error": "Overlapping CIDR with existing subnet"}, status=400)
            
            rspstatus = subnet_create_fn(conn, network, data, user_info, org)
            if rspstatus == 200:
                response = {"message": f"Subnet({data.get('subnet_name')}) created successfully"}
        else:
            return JsonResponse({"error":"Network not found"}, status=400)
        
    except Exception as e:
        response = {"error":str(e)}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Create_Subnet", user_info, org, {}) 
        )
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='get',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: "Json Response"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_network(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        project_id = request.token_project_id  
        #check in cache       
        #cache_key = f"networks_{project_id}"
        #network_details = cache.get(cache_key)
        #if network_details:
        #    return JsonResponse(network_details, safe=False, status=200)      
        network_info = []   
         
        networks = conn.network.networks(project_id=project_id)         
        for net in networks:            
            network = conn.network.find_network(net.name)
            subnet_associated = []
            if network:
                for subnet_id in network.subnet_ids:
                    subnet = conn.network.get_subnet(subnet_id)               
                    subnet_associated.append(f"{subnet.name} {subnet.cidr}")
            network_info.append({
                "network_name": net.name,
                "network_id": net.id,
                "is_shared": net.is_shared,
                "is_external": net.is_router_external,   # <-- external network flag
                "status": net.status,                    # e.g., ACTIVE or DOWN
                "admin_state_up": net.is_admin_state_up, # True or False
                "availability_zones": net.availability_zones,  # list
                "subnets_associated": subnet_associated,
                "mtu":net.mtu
            })      
          
        rspstatus = 200       
    except Exception as e:        
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("List_Network", user_info, org, {}) 
        )
    # Store in cache
    #cache.set(cache_key, network_info, timeout=NETWORK_CACHE_TIME)   
    return JsonResponse(network_info, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=UpdateSubnetSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_subnet(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        project_id = request.token_project_id   
        #Delete cache
        cache_key = f"networks_{project_id}"
        cache.delete(cache_key) 
        cache_key = f"networkoverview_{project_id}"
        cache.delete(cache_key) 

        data = json.loads(request.body)  
        if "admin" not in role:
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403) 
        # Get existing subnet
        if not data.get('subnet_name'):
            return JsonResponse({"error":"Missing of Subnet Name"}, status=400)
        
        subnet = conn.network.find_subnet(data.get('subnet_id'))  # or use ID
        if not subnet:
            return JsonResponse({"error":"Subnet Not found"}, status=403)
        if subnet.name == f"shared_subnet_{org.organization_name.lower()}" or subnet.name == "public-subnet":
            return JsonResponse({"error": "Permission denied to update this subnet."}, status=403) 
        # Example: update subnet
        updated_subnet = conn.network.update_subnet(
            subnet,   
            name= data.get('subnet_name'),             
            gateway_ip=data.get('gateway_address'),
            enable_dhcp=data.get('enable_dhcp'),
            allocation_pools=data.get('dhcp_pools'),
            dns_nameservers=[data.get('primary_dns'), data.get('sec_dns')]
        )   
        response = {"message": f"Subnet - {data.get('subnet_name')} was updated successfully"}
        logger.info(f"Subnet - {data.get('subnet_name')} was updated successfully", 
                    extra = custom_log("Update_Subnet", user_info, org, {}) 
        )
        rspstatus = 200
    except Exception as e:   
        response = {"error":str(e)}     
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Update_Subnet", user_info, org, {}) 
        )
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=UpdateNetworkSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_network(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        project_id = request.token_project_id      
        data = json.loads(request.body) 
        #Delete the Cache        
        cache_key = f"networks_{project_id}"
        cache.delete(cache_key) 
        cache_key = f"networkoverview_{project_id}"
        cache.delete(cache_key) 

        if "admin" not in role:
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403) 
        # Get existing subnet
        if not data.get('network_id'):
            return JsonResponse({"error":"Network ID Missing"}, status=400)
        
        network = conn.network.find_network(data.get('network_id'))  # or use ID
        if not network:
            return JsonResponse({"error":"Network Not found"}, status=403)
        if network.name == f"shared_nw_{org.organization_name.lower()}" or network.name == "public-net":
            return JsonResponse({"error": "Permission denied to update this network"}, status=403) 
        # Example: update subnet
        updated_network = conn.network.update_network(
            network,   
            name= data.get('network_name'), 
            admin_state_up = data.get('admin_state_up')            
        )   
        response = {"message": f"Network - {data.get('network_name')} was updated successfully"}
        logger.info(f"Network - {data.get('network_name')} was updated successfully", 
                    extra = custom_log("Update_Network", user_info, org, {}) 
        )
        rspstatus = 200
    except Exception as e:   
        response = {"error":str(e)}     
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Update_Network", user_info, org, {}) 
        )
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='get',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        ),
        openapi.Parameter(
            'network_id',
            in_=openapi.IN_QUERY,
            description="Network ID",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: "Json Response"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_nw_subnet_list(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        #project_id = request.token_project_id       
        network_id = str(request.GET.get('network_id'))             
        #networks = conn.network.networks(project_id=project_id) 
        network = conn.network.find_network(network_id)
        subnet_info = []
        if not network:
            return JsonResponse({"error":"Network Not found"}, status=400)
        for subnet_id in network.subnet_ids:
            subnet = conn.network.get_subnet(subnet_id)            
            subnet_info.append({
                "subnet_name": subnet.name,
                "subnet_id": subnet.id,
                "network_address": subnet.cidr,
                "ip_version": subnet.ip_version,   
                "gateway_ip": subnet.gateway_ip                   
            })
        rspstatus = 200       
    except Exception as e:        
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Get_subnet_list", user_info, org, {}) 
        )
    return JsonResponse(subnet_info, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='get',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        ),
        openapi.Parameter(
            'subnet_id',
            in_=openapi.IN_QUERY,
            description="Subnet ID",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: "Json Response"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_subnet_info(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        subnet_info = {}
        #project_id = request.token_project_id       
        subnet_id = str(request.GET.get('subnet_id'))             
        subnet = conn.network.find_subnet(subnet_id)            
        subnet_info = {
                "subnet_name": subnet.name,
                "subnet_id": subnet.id,
                "network_address": subnet.cidr,                  
                "gateway_ip": subnet.gateway_ip,
                "allocation_pools": subnet.allocation_pools,
                "host_routes": subnet.host_routes,
                "dns_nameservers": subnet.dns_nameservers
            }
        rspstatus = 200       
    except Exception as e:        
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("subnet_info", user_info, org, {}) 
        )
    return JsonResponse(subnet_info, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],
    request_body = DeleteSubnetSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_subnet(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role 
        #Delete the Cache  
        project_id = request.token_project_id      
        cache_key = f"networks_{project_id}"
        cache.delete(cache_key) 
        cache_key = f"networkoverview_{project_id}"
        cache.delete(cache_key)    
        if "admin" not in role:
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)  
        data = json.loads(request.body)      
        subnet_ids = data.get('subnet_id')
        for subnetid in subnet_ids:          
            subnet = conn.network.find_subnet(subnetid)              
            if not subnet:
                return JsonResponse({"error":f"Subnet:{subnetid} not found"}, status=400)
            if subnet.name == f"shared_subnet_{org.organization_name.lower()}" or subnet.name == "public-subnet":
                return JsonResponse({"error":f"Subnet:{subnetid} deletion is denied"}, status=400)
            conn.network.delete_subnet(subnet.id)  
            logger.info(f"Network: {subnet.name} deleted successfully",
                        extra = custom_log("Delete_Subnet", user_info, org, {}) 
            )
        response = {"message":"Subnet deleted successfully"}       
        rspstatus = 200       
    except Exception as e:   
        response = {"error":str(e)}     
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Delete_subnet", user_info, org, {}) 
        )
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],
    request_body = DeleteNetworkSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_network(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role   
        #Delete the Cache
        project_id = request.token_project_id
        cache_key = f"networks_{project_id}"
        cache.delete(cache_key) 
        cache_key = f"networkoverview_{project_id}"
        cache.delete(cache_key) 
        if "admin" not in role:
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)  
        data = json.loads(request.body)      
        network_ids = data.get('network_id')
        for networkid in network_ids:          
            netw = conn.network.find_network(networkid)  
            if not netw:
                return JsonResponse({"message":f"Network:{networkid} not found"}, status=400)
            if netw.name == f"shared_nw_{org.organization_name.lower()}" or netw.name == "public-net":
                return JsonResponse({"error":f"Network:{netw.name} deletion is denied"}, status=400)
            for subnet_id in netw.subnet_ids:
                conn.network.delete_subnet(subnet_id)            
            conn.network.delete_network(netw.id)  
            logger.info(f"Network: {netw.name} deleted successfully",
                        extra = custom_log("Delete_Network", user_info, org, {}) 
            )
        response = {"message":"Network deleted successfully"}       
        rspstatus = 200       
    except Exception as e:   
        response = {"error":str(e)}     
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Delete_Network", user_info, org, {}) 
        )
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='get',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],    
    responses={200: "Json Response"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_port(request, network_id):
    try:
        conn = request.keystone_conn        
        user_info = request.keystone_user_info        
        org = request.org         
        ports = []
        for port in conn.network.ports(network_id=network_id):  
            #print(port) 
            ip_addr = []   
            for ips in port.fixed_ips:
                ip_addr.append(ips["ip_address"])      
            ports.append({"name": port.name,
                          "id": port.id,
                          "fixed_ip": ip_addr,
                          "mac_address": port.mac_address,
                          "status": port.status,
                          "admin_state":port.is_admin_state_up,
                          "attached_device": port.device_owner})
        rspstatus = 200
    except Exception as e:          
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("List_Ports", user_info, org, {}) 
        )
    return JsonResponse(ports, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Network Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=CreatePortSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_port(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        data = json.loads(request.body)
        network_id = data.get('network_id') 
        subnet_id = data.get('subnet_id')
        port_name = data.get('port_name')
        if "admin" not in role:       
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)     
        if not network_id or not subnet_id:
            return JsonResponse({"error":"Network or subnet id is missing"}, status=400) 
        network = conn.network.get_network(network_id)
        if network:
                port = conn.network.create_port(
                    name=port_name,
                    network_id=network_id,
                    fixed_ips=[{"subnet_id": subnet_id}]
                )            
                response = {"message": f"Port({port.name}) created successfully"}
                logger.info(f"Port({port.name}) created successfully", 
                    extra = custom_log("Create_port", user_info, org, {}) 
                )
                rspstatus = 200
        else:
            return JsonResponse({"error":"Network not found"}, status=400)
        
    except Exception as e:
        response = {"error":str(e)}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Create_port", user_info, org, {}) 
        )
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='get',
    tags=['Instance Management'],
    operation_id="get_free_ports",
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],    
    responses={200: "Json Response"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_port_forattach_interface(request):
    try:
        conn = request.keystone_conn        
        user_info = request.keystone_user_info        
        org = request.org         
        ports = []
        project_id = request.token_project_id       
        for port in conn.network.ports(project_id=project_id):  
            if port.status == "DOWN" and port.device_owner == "": 
                ports.append({"name": port.name,
                          "id": port.id,
                          })
        rspstatus = 200
    except Exception as e:          
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("List_Ports", user_info, org, {}) 
        )
    return JsonResponse(ports, safe=False, status=rspstatus)

class PortDeleteView(APIView):
    @swagger_auto_schema(
        operation_summary="Delete Port",
        tags=['Network Management'],
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
    def delete(self, request, port_id):
        try:    
            conn = request.keystone_conn        
            user_info = request.keystone_user_info        
            org = request.org                      

            # Get port details
            port = conn.network.get_port(port_id)
            if not port:
                return JsonResponse({"error": "Port not found"}, status=404)
            #print(port.to_dict())
            # Check if attached to any device
            if port.device_id or port.device_owner:                
                if port.status != "N/A":
                    return JsonResponse({
                        "error": "Port is still attached",
                        "device_id": port.device_id,
                        "device_owner": port.device_owner
                    }, status=400) 
                else:
                    if "floatingip" in port.device_owner:
                        # Fetch the floating IP
                        for ips in port.fixed_ips:
                            floating_ip = ips["ip_address"]
                        fip = conn.network.find_ip(floating_ip, ignore_missing=True)
                        if fip:                       
                            conn.network.update_ip(fip, port_id=None)
                            logger.info(
                                    f"Detached Floating IP {fip.floating_ip_address} from Port {port.id}",
                                    extra=custom_log("Detach_FIP", user_info, org, {"fip": fip.floating_ip_address})
                            )
                            # Delete the floating IP
                            conn.network.delete_ip(fip, ignore_missing=True)
                            # After detaching floating IP, try deleting
                            #conn.network.delete_port(port, ignore_missing=True)
                            logger.info(
                                f"Attached Port {port.id} deleted after detaching resources",
                                extra=custom_log("Delete_port", user_info, org, {})
                            )
                            return JsonResponse({"message": "Port detached and deleted successfully"})
                        else:
                            return JsonResponse({
                                "error": "Port is still attached",
                                "device_id": port.device_id,
                                "device_owner": port.device_owner
                            }, status=400) 


            # Safe to delete
            conn.network.delete_port(port, ignore_missing=True)
            logger.info(f"Port deleted successfully", 
                    extra = custom_log("Delete_port", user_info, org, {}) 
                )
            return JsonResponse({"message": "Port deleted successfully"})

        except Exception as e:
            logger.error(str(e), 
                    extra = custom_log("Delete_port", user_info, org, {}) 
                )
            return JsonResponse({"error": str(e)}, status=500)
        
class NetworkOverviewView(APIView):
    @swagger_auto_schema(
        operation_summary="Network Topology",
        tags=['Network Management'],
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
            conn = request.keystone_conn        
            user_info = request.keystone_user_info        
            org = request.org    
            project_id = request.token_project_id
            #check in cache       
            cache_key = f"networkoverview_{project_id}"
            network_overview_details = cache.get(cache_key)
            if network_overview_details:
                return JsonResponse(network_overview_details, safe=False, status=200)
            overview = {}

            # Get external networks (public)
            external_nets = [net for net in conn.network.networks() if net.is_router_external]
            if external_nets:
                ext_net = external_nets[0]
                overview["externalgateway"] = {
                    "name": ext_net.name,
                    "network": ext_net.cidr if hasattr(ext_net, "cidr") else None
                }

            overview["routers"] = []

            for router in conn.network.routers(project_id = project_id):
            #for router in conn.network.routers():
                router_info = {
                    router.name: {
                        "external_interface_ip": None,
                        "internal_interface_info": []
                    }
                }

                # Router ports (interfaces)
                ports = conn.network.ports(device_id=router.id)

                for port in ports:
                    fixed_ips = port.fixed_ips
                    if port.device_owner == "network:router_gateway":
                        # External interface
                        if fixed_ips:
                            router_info[router.name]["external_interface_ip"] = fixed_ips[0]["ip_address"]
                    elif port.device_owner == "network:router_interface":
                        # Internal networks
                        if fixed_ips:
                            ip_addr = fixed_ips[0]["ip_address"]
                            subnet = conn.network.get_subnet(fixed_ips[0]["subnet_id"])
                            net = conn.network.get_network(port.network_id)

                            # Instances connected to this network
                            instances = []
                            for p in conn.network.ports(network_id=net.id):
                                if p.device_owner.startswith("compute:") and p.fixed_ips:
                                    server = conn.compute.get_server(p.device_id)
                                    instances.append({
                                        "name": server.name if server else p.device_id,
                                        "ip": p.fixed_ips[0]["ip_address"]
                                    })

                            router_info[router.name]["internal_interface_info"].append({
                                "ip": ip_addr,
                                "network_info": {
                                    "name": net.name,
                                    "connected_instance": instances
                                }
                            })

                overview["routers"].append(router_info)
                # Store in cache
                cache.set(cache_key, overview, timeout=NETWORK_CACHE_TIME)   
            return JsonResponse(overview, safe=False)

        except Exception as e:
            logger.error(str(e), 
                    extra = custom_log("Network_Topology", user_info, org, {}) 
            )
            return JsonResponse({"error": str(e)}, status=500)
