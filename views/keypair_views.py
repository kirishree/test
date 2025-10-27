from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication  # Optional fallback
from rest_framework import serializers
from html import escape
from django.views.decorators.csrf import csrf_exempt
from .serializers import ImportPubblickeySerializer, CreatekeypairSerializer, DeleteKeypairSerializer
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
controller_ip = config('CONTROLLER_IP')
ONBOARDING_API= config('ONBOARDING_API_URL')
KEYSTONE_URL = config('KEYSTONE_URL')
ADMIN_PASSWORD = config('KEYSTONE_ADMIN_PASSWORD')
KEYPAIR_CACHE_TIME = int(config('KEYPAIR_CACHE_TIME'))
DEFAULT_DOMAIN = "Default"
ORG_ADMIN_ROLE = "org-admin"
ORG_USER_ROLE = "org-user"

@swagger_auto_schema(
    method='post',
    tags=['Keypair Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=ImportPubblickeySerializer,
    responses={200: "JSON Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def import_public_key(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        data = json.loads(request.body)
        #Delete the Cache
        project_id = request.token_project_id
        cache_key = f"keypairs_{project_id}"
        cache.delete(cache_key)

        keypair_name = data.get('keypair_name')
        keypair_public_key = data.get('keypair_public_key')
        keypair = conn.compute.create_keypair(name=keypair_name, public_key=keypair_public_key)
        response = {"message":f"keypair {keypair.name} created"}
        rspstatus = 200
    except Exception as e:
        response = {"error": str(e)}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("create_keypair", user_info, org, {}) 
        )   
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Keypair Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=CreatekeypairSerializer,
    responses={200: "JSON Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_and_download_keypair(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role

        data = json.loads(request.body)
        #Delete the Cache
        project_id = request.token_project_id
        cache_key = f"keypairs_{project_id}"
        cache.delete(cache_key)
        keypair_name = data.get('keypair_name')

        if not keypair_name:
            raise ValueError("Keypair name is required")

        keypair = conn.compute.create_keypair(name=keypair_name)

        # Prepare response with private key
        response = HttpResponse(
            keypair.private_key,
            content_type='application/x-pem-file'  # better MIME type
        )
        response['Content-Disposition'] = f'attachment; filename="{keypair_name}.pem"'

        # Optionally log or store keypair metadata (not private key)
        return response

    except Exception as e:
        response = {"error": str(e)}
        if isinstance(e, (KeyError, ValueError)):
            response["error"] = str(e)
            rspstatus = 400
        else:
            rspstatus = 500

        logger.error(f"{str(e)}", extra=custom_log("create_keypair", user_info, org, {}))
        return JsonResponse(response, safe=False, status=rspstatus)
    
@swagger_auto_schema(
    method='get',
    tags=['Keypair Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],    
    responses={200: "JSON Response"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_keypair(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info  
        project_id = request.token_project_id       
        org = request.org 
        role = request.role 
        #check in cache       
        cache_key = f"keypairs_{project_id}"
        keypair_details = cache.get(cache_key)
        if keypair_details:
            return JsonResponse(keypair_details, safe=False, status=200)
        keypair=[]
        keypairs = conn.compute.keypairs(project_id=project_id)        
        for kp in keypairs:            
            keypair.append({"keypair_name": kp.name,
                             "Fingerprint": str(kp.fingerprint)})         
        rspstatus = 200
    except Exception as e:        
        if isinstance(e, (KeyError, ValueError)):            
            rspstatus = 400
        else:
            rspstatus = 500

        logger.error(f"{str(e)}", extra=custom_log("create_keypair", user_info, org, {}))
    # Store in cache
    cache.set(cache_key, keypair, timeout=KEYPAIR_CACHE_TIME)    
    return JsonResponse(keypair, safe=False, status=rspstatus)
    
@swagger_auto_schema(
    method='post',
    tags=['Keypair Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],
    request_body = DeleteKeypairSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_keypair(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        data = json.loads(request.body)        
        #Delete the Cache
        project_id = request.token_project_id
        cache_key = f"keypairs_{project_id}"
        cache.delete(cache_key)
        keypair_names = data.get('keypair_names')        
        if "admin" not in role:       
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)   
        for keypair_name in keypair_names:
            conn.compute.delete_keypair(keypair_name, ignore_missing=True)
        response = {"message":"Key deleted successfully"}
        rspstatus = 200         
    except Exception as e:  
        response = {"error":str(e)}      
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Delete_keypair", user_info, org, {}) 
        )   
    return JsonResponse(response, safe=False, status=rspstatus)
