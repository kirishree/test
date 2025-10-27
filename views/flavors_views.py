from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication  # Optional fallback
from rest_framework import serializers
from html import escape
from django.views.decorators.csrf import csrf_exempt
from .serializers import CreateFlavorSerializer, FlavorResponseSerializer, UpdateFlavorSerializer, DeleteFlavorSerializer, GetFlavorByIDSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
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
#Cache
from django.core.cache import cache
controller_ip = config('CONTROLLER_IP')
ONBOARDING_API= config('ONBOARDING_API_URL')
KEYSTONE_URL = config('KEYSTONE_URL')
ADMIN_PASSWORD = config('KEYSTONE_ADMIN_PASSWORD')
DEFAULT_DOMAIN = "Default"
ORG_ADMIN_ROLE = "org-admin"
ORG_USER_ROLE = "org-user"
FLAVOR_CACHE_TIME = int(config('FLAVOR_CACHE_TIME'))

from api.models import FlavorPricing, Pricing
@swagger_auto_schema(
    method='post',
    tags=['Flavor Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=CreateFlavorSerializer,
    responses={200: "JSON Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_flavor(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        project_id = request.token_project_id
        cache_key = f"flavors_{project_id}"
        cache.delete(cache_key)
        if "admin" not in role:       
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)   
        data = json.loads(request.body) 
        flavor_name = data.get('flavor_name') 
        flavor_ram = int(data.get('flavor_ram'))
        flavor_vcpus = int(data.get('flavor_vcpus'))
        flavor_disk = int(data.get('flavor_disk'))
        flavor_description = data.get('flavor_description')
        flavor_is_public = data.get('flavor_is_public')
        #os-flavor-access:is_public= True
        flavor = conn.compute.create_flavor(
            name=flavor_name,
            description=flavor_description,
            ram=flavor_ram,         # in MB
            vcpus=flavor_vcpus,
            disk=flavor_disk,       # in GB        
            is_public=flavor_is_public
        )
        price_info = Pricing.objects.filter().latest("created_at")

        price_ram = int(flavor.ram) * float(price_info.price_per_gb_ram_hr) / 1024  # MB → GB
        price_vcpu = int(flavor.vcpus) * float(price_info.price_per_vcpu_hr)
        price_volume = int(flavor.disk) * float(price_info.price_per_volume_gb_hr)

        hourly_rate = price_ram + price_vcpu + price_volume
        monthly_rate = hourly_rate * 24 * 30

        flav, created = FlavorPricing.objects.update_or_create(
                flavor_id=flavor.id,
                defaults={
                    "name": flavor.name,
                    "vcpus": flavor.vcpus,
                    "ram_mb": flavor.ram,
                    "disk_gb": flavor.disk,
                    "rate_hour": hourly_rate,
                    "rate_monthly": monthly_rate
                }
            )
        response = {"message": f"Flavor: {flavor.name} created successfully", "flavor_id": flavor.id}
        logger.info(f"Flavor: {flavor.name} created successfully", 
                    extra = custom_log("create_flavor", user_info, org, {}) 
        ) 
        rspstatus = 200
    except Exception as e:
        response = {"error": f"Internal Server Error"}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("create_flavor", user_info, org, {}) 
        )   
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='get',
    tags=['Flavor Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: FlavorResponseSerializer}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_flavors(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        project_id = request.token_project_id
        #cache_key = f"flavors_{project_id}"
        #flavor_details = cache.get(cache_key)
        #if flavor_details:
        #    return JsonResponse(flavor_details, safe=False, status=200)
        flavors = []
        #if "admin" not in role:       
        #    return JsonResponse({"error": "Permission denied. Admins only."}, status=403)   
        for flavor in conn.compute.flavors():
            flavorprice = FlavorPricing.objects.filter(flavor_id = flavor.id).first()
            if not flavorprice:
                rate_per_hr = ""
                rate_per_month = ""
            else:
                rate_per_hr = flavorprice.rate_hour
                rate_per_month = flavorprice.rate_monthly
            flavors.append({
                "flavor_name": flavor.name,
                "flavor_id": flavor.id,
                "flavor_ram": flavor.ram,
                "flavor_vcpus": flavor.vcpus,
                "flavor_disk": flavor.disk,
                "flavor_description": flavor.description,
                "flavor_is_public": flavor.is_public,
                "rate_per_hour": rate_per_hr,
                "rate_per_month": rate_per_month
            })  
        rspstatus = 200         
    except Exception as e:        
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("list_flavors", user_info, org, {}) 
        ) 
    # Store in cache
    #cache.set(cache_key, flavors, timeout=FLAVOR_CACHE_TIME)  
    return JsonResponse(flavors, safe=False, status=rspstatus)

#Update is not supported so removed form request just keep it here for refference
@swagger_auto_schema(
    method='post',
    tags=['Flavor Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],
    request_body = UpdateFlavorSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_flavorname(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        #Delete the Cache on update
        project_id = request.token_project_id
        cache_key = f"flavors_{project_id}"
        cache.delete(cache_key)
        data = json.loads(request.body)
        flavor_id = data.get('flavor_id')
        flavor_name = data.get('flavor_name')
        flavor_description = data.get('flavor_description')
        if "admin" not in role:       
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)   
        if not flavor_id:
            return JsonResponse({"error": "Flavor ID is missing"}, status=400)  
        flavor = conn.compute.update_flavor(flavor_id,
                                            name=flavor_name, 
                                            description=flavor_description)
        response = {"message":"Flavor name changed successfully"}
        rspstatus = 200         
    except Exception as e:  
        response = {"error": str(e)}      
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Update_flavorname", user_info, org, {}) 
        )   
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Flavor Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],
    request_body = DeleteFlavorSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_flavor(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        #Delete the Cache on update
        project_id = request.token_project_id
        cache_key = f"flavors_{project_id}"
        cache.delete(cache_key)
        data = json.loads(request.body)
        flavor_ids = data.get('flavor_ids')        
        if "admin" not in role:       
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)   
        for flavor_id in flavor_ids:
            conn.compute.delete_flavor(flavor_id, ignore_missing=True) 
        response = {"message":"Flavor deleted successfully"}
        rspstatus = 200         
    except Exception as e:  
        response = {"error": str(e)}      
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Delete_flavor", user_info, org, {}) 
        )   
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Flavor Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body = GetFlavorByIDSerializer,
    responses={200: FlavorResponseSerializer}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_flavor_byid(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        data = json.loads(request.body)
        flavor_id = data.get('flavor_id')
        flavors = {}
        #if "admin" not in role:       
        #    return JsonResponse({"error": "Permission denied. Admins only."}, status=403)   
        flavor = conn.compute.get_flavor(flavor_id)
        flavors = {
                "flavor_name": flavor.name,
                "flavor_id": flavor.id,
                "flavor_ram": flavor.ram,
                "flavor_vcpus": flavor.vcpus,
                "flavor_disk": flavor.disk,
                "flavor_description": flavor.description,
                "flavor_is_public": flavor.is_public
            }
        rspstatus = 200         
    except Exception as e:        
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("get_flavor_byid", user_info, org, {}) 
        )   
    return JsonResponse(flavors, safe=False, status=rspstatus)