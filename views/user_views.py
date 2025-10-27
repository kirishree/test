# user_views.py
from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication  # Optional fallback
from rest_framework import serializers
from html import escape
from django.views.decorators.csrf import csrf_exempt
from .serializers import UserListResponseSerializer, UpdateUserInfoSerializer, GetUserInfoSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
from api.models import UserReachStack, Organization, RegisteredUser, ProjectID, OrgGroup, OrgGroupUsers
from django.core.cache import cache
import onboarding
from custom_log_info import custom_log_data, custom_log
import logging
from .auth_views import auth_token, system_admin_auth
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
DEFAULT_DOMAIN = "Default"
ORG_ADMIN_ROLE = "org-admin"
ORG_USER_ROLE = "org-user"

from django.contrib.auth.hashers import make_password

def identity_list_users(conn, domainid, user_info, org):
    try:
        user_data = []
        if domainid:
            users = conn.identity.users(domain_id=domainid)  
            #users = conn.identity.users()
        else:
            logger.error(f"Domain id is missing", extra={"function_name": "Get users"})
            return user_data
        # Serialize the user list        
        for user in users:
            if user.name == "admin":
                continue
            project_name = None
            def_project_id = getattr(user, 'default_project_id', None)
            if def_project_id != None:
                project = conn.identity.find_project(def_project_id,  domain_id=domainid)
                project_name = project.name
            user_data.append({
                    "id": user.id,
                    "name": user.name,
                    "email": getattr(user, 'email', None),
                    "enabled": getattr(user, 'is_enabled', None),
                    "domain_id": user.domain_id,
                    "default_project_id": project_name,
                    "description": getattr(user, 'description', ''),
                })
    except Exception as e:        
        logger.error(f"Error while listing users: {str(e)}",
                     extra = custom_log("Get_users", user_info, org, {})
        )
    return user_data

@swagger_auto_schema(
    method='post',
    operation_summary="Create/Add USER",
    tags=['User Management'],
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
                "email": openapi.Schema(type=openapi.TYPE_STRING),
                "username": openapi.Schema(type=openapi.TYPE_STRING),
                "password": openapi.Schema(type=openapi.TYPE_STRING)               
            }
    ),
    responses={200:  openapi.Response("Success")}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_users(request):
    try:       
        conn = request.keystone_conn
        token_project_id = request.token_project_id
        user_id = request.keystone_user_id 
        user_info = request.keystone_user_info                 
        org = request.org 
        role = request.role
        data = json.loads(request.body)
        if "admin" not in role:           
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)  
        else:
            user_rs, created = UserReachStack.objects.get_or_create(
                email=data.get("email"),
                defaults={
                    "password": make_password(data.get("password")),
                    "username": data.get("username"),
                    "role": "member",
                    "organization": org,
                    "email_verified": True,
                }
            )
            print("created", created)
            print("stripe_customer_id", user_rs.organization.stripe_customer_id)

            # Create a new user
            user = conn.identity.find_user(data.get("email"))
            if not user:
                user = conn.identity.create_user(
                    name=data.get("email"),
                    password=data.get("password"),
                    domain_id=org.domain_id,              # or custom domain_id
                    default_project_id=org.default_project_id,  # optional                
                    enabled=True,
                    email=data.get("email")
                )
                # Assign role
                role_obj = conn.identity.find_role("member")                
                project = conn.identity.get_project(org.default_project_id)
                conn.identity.assign_project_role_to_user(project=project, user=user, role=role_obj)
                user_rs.keystone_id = user.id
                user_rs.save()   
                logger.info(f"User Added", 
                    extra = custom_log("Create_user", user_info, org, {})
                    ) 
                response = {"message": f"User: {user.name} added successfully"}
                respstatus = 200
            else:
                logger.error(f"User: {user.name} already exist", 
                    extra = custom_log("Create_user", user_info, org, {})
                    ) 
                response = {"error": f"User: {user.name} already exist"}
                respstatus = 400        
        return JsonResponse(response, status=respstatus)
    except Exception as e:
        logger.error(str(e),
                     extra = custom_log("Create_user", user_info, org, {})
        )
        return JsonResponse({"error": str(e)}, status=500)      
    
@swagger_auto_schema(
    method='get',
    tags=['User Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: UserListResponseSerializer}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_users(request):
    try:       
        conn = request.keystone_conn
        token_project_id = request.token_project_id
        user_id = request.keystone_user_id 
        user_info = request.keystone_user_info                 
        org = request.org 
        role = request.role
        if "admin" not in role:  
           adm_conn = system_admin_auth() 
           user_data = identity_list_users(adm_conn, org.domain_id, user_info, org)             
           #return JsonResponse({"error": "Permission denied. Admins only."}, status=403)  
        else:
            user_data = identity_list_users(conn, org.domain_id, user_info, org)
        logger.info(f"Successfully get user's list", 
                    extra = custom_log("Get_users", user_info, org, {})
                    ) 
        return JsonResponse({"users": user_data}, status=200)
    except Exception as e:
        logger.error(str(e),
                     extra = custom_log("Get_users", user_info, org, {})
        )
        return JsonResponse({"error": str(e)}, status=500)              
    
def assign_user_role(conn, user_id, project_id, role_name="member"):
    # Get role ID by name
    role = conn.identity.find_role(role_name)
    if not role:
        raise Exception(f"Role '{role_name}' not found")
    
    # Assign role to user for project
    conn.identity.assign_project_role_to_user(
        project=project_id,
        user=user_id,
        role=role.id
    )
    print(f"Assigned role '{role.name}' to user '{user_id}' in project '{project_id}'")


@swagger_auto_schema(
    method='post',
    tags=['User Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body = UpdateUserInfoSerializer,
    responses={200: "Update Response Json"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # ✅ uses your global default
def update_user(request):
    try:
        conn = request.keystone_conn
        token_project_id = request.token_project_id
        user_id = request.keystone_user_id
        user_info = request.keystone_user_info
        data = json.loads(request.body)
        role_assignments = conn.identity.role_assignments(user_id=user_id, project_id=token_project_id)
        role_names = [conn.identity.get_role(ra.role['id']).name for ra in role_assignments]
        reg_user = RegisteredUser.objects.select_related('organization').get(keystone_userid=user_id)
        org = reg_user.organization 
        if "admin" not in role_names[0]:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)   
        else:
            # Find the user first        
            user = conn.identity.find_user(data["username"], domain_id=org.domain_id)
            project = conn.identity.find_project(data["primary_project"], domain_id=org.domain_id)
            if not user:
                return JsonResponse({"error": f"User {data['username']} not found in domain."}, status=404)
            # Update the user
            conn.identity.update_user(
                user=user,                          
                email=data.get("emailid"),               # optional
                enabled=True,                                # optional
                description=data.get('description', ""),      # optional
                default_project_id= project.id
            )
            response = {"message": "User Updated Successfully"}
            logger.info(f"User: {data['username']} Updated Successfully",
                      extra = custom_log("update_user", user_info, org, {})
            )
            rspstatus = 200
    except Exception as e:        
        response = {"error": str(e)}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(str(e),
                      extra = custom_log("update_user", user_info, org, {})
        )
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['User Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body = GetUserInfoSerializer,
    responses={200: UserListResponseSerializer}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # ✅ uses your global default
def get_userby_id(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id        
        user_info = request.keystone_user_info
        data = json.loads(request.body)      
        org = request.org 
        role = request.role
        if "admin" not in role:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)   
        else:
            # Find the user first        
            user = conn.identity.get_user(data.get("user_id"))
            projects_list = []
            assignments = conn.identity.role_assignments(user_id=user.id)
            for assignment in assignments:            
                scope = assignment.scope
                if 'project' in scope and 'id' in scope['project']:   
                    if assignment.user:  
                        if user.id == assignment.user["id"]:
                            project_id = scope['project']['id']
                            projectli = conn.identity.get_project(project_id)
                            projects_list.append(projectli.name)
            project_name = None
            def_project_id = getattr(user, 'default_project_id', None)
            if def_project_id != None:
                project = conn.identity.find_project(def_project_id,  domain_id=org.domain_id)
                project_name = project.name
            response = {
                    "id": user.id,
                    "name": user.name,
                    "email": getattr(user, 'email', None),
                    "enabled": getattr(user, 'is_enabled', None),
                    "domain_id": user.domain_id,
                    "default_project_id": project_name,
                    "description": getattr(user, 'description', ''),
                    "project_list": projects_list
                }
            rspstatus = 200
    except Exception as e:        
        response = {"error": str(e)}
        if "No User found for" in str(e):
            response = {"error": "No User found"}
            rspstatus = 403
        elif isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(str(e),
                      extra = custom_log("get_user_byid", user_info, org, {})
        )
    return JsonResponse(response, safe=False, status=rspstatus)