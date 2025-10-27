# user_views.py
from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication  # Optional fallback
from rest_framework import serializers
from html import escape
from django.views.decorators.csrf import csrf_exempt
from .serializers import CreateGroupSerializer, AddGroupSerializer, ProjectInfoResponseSerializer, UpdatGroupNameSerializer, RemoveUserGroupSerializer, DeleteGroupSerializer
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

@swagger_auto_schema(
    method='post',
    tags=['Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=CreateGroupSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_group(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        data = json.loads(request.body)
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        if "admin" not in role:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)       
        data = json.loads(request.body)
        group_obj = conn.identity.find_group(data.get('group_name'))
        reg_user = RegisteredUser.objects.select_related('organization').get(keystone_userid=user_id)
        org = reg_user.organization 
        if not group_obj:
            group = conn.identity.create_group(
                name=data.get('group_name'),
                description=data.get('group_description', ''),
                domain_id=org.domain_id
            )
        else:
            groupname = data.get('group_name')
            logger.error(f'Error: Group {groupname} already exists.', 
                         extra = custom_log("create_group", user_info, org, {}) 
            )
            return JsonResponse({"error": f'Error: Group {groupname} already exists.'}, status=409)
        OrgGroup.objects.create(
            keystone_group_id=group.id,
            group_name=data.get('group_name'),
            organization=org,
            created_by=user_id,
            description=data.get('group_description', '')
        )
        logger.info(
            f"Group Created: {data.get('group_name')} ",
            extra = custom_log("create_group", user_info, org, {})          
        ) 
        response = {"message":f"Successfully Group created {data.get('group_name')}"} 
        rspstatus = 201
    except Exception as e:
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure

        response = {"error": f"Failed to create Group: {escape(str(e))}"}
        logger.error(
            "Failed to create Group",
            extra = custom_log("create_group", user_info, org, {})   
        )
    return JsonResponse(response, safe=False, status=rspstatus)

def add_users_group(conn, data, org, user_info):
    try:
        groupname = data.get('group_name')
        groupinfo = OrgGroup.objects.get(group_name=groupname)
        response = {"message": f"Successfully User added to Group {groupname}" }
        rspstatus = 200     
        for username in data.get('users'):            
            # Get Keystone user and group IDs
            keystone_user = conn.identity.find_user(username)
            keystone_group = conn.identity.find_group(groupname)
            if keystone_user and keystone_group:
                conn.identity.add_user_to_group(user=keystone_user, group=keystone_group)
                OrgGroupUsers.objects.create(
                        group=groupinfo,
                        username=username,
                        organization=org
                    )
            else:
                response = {"message":f"User or group not found for: {username}, {groupname}"}
                logger.warning(response["message"], 
                               extra = custom_log("add_user_togroup", user_info, org, {}) 
                              
                ) 
                rspstatus = 404
                break           
        if rspstatus == 200:
                logger.info(response["message"], 
                            extra = custom_log("add_user_to_group", user_info, org, {}) 
                )  
    except Exception as e:
        response = {"message":str(e)}
        logger.error(str(e),
                      extra = custom_log("add_user_to_group", user_info, org, {})
        )
        rspstatus = 500
    return response, rspstatus

@swagger_auto_schema(
    method='post',
    tags=['Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=AddGroupSerializer,
    responses={200: ProjectInfoResponseSerializer}
)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_userto_group(request):
    try:  
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        data = json.loads(request.body)
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        if "admin" not in role:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)     
        data = json.loads(request.body)
        response, rspstatus = add_users_group(conn, data, org, user_info)        
    except Exception as e:
        response = {"error": str(e)}
        logger.error(str(e), 
                     extra = custom_log("add_user_to_group", user_info, org, {}) 
        )
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure        
    return JsonResponse(response, safe=False, status=rspstatus)     

def groupinfo_byid(conn, group, user_info, org):
    try:
        users = list(conn.identity.group_users(group=group.id)) 
        groupusers = []
        if users:                    
            for user in users:  
                groupusers.append({"user_name": user.name,
                                    "user_id": user.id,
                                    "user_enabled":getattr(user, 'is_enabled', None),
                                    "group_name":group.name})  
    except Exception as e:
        logger.error(str(e), 
                     extra = custom_log("groupinfo_byid", user_info, org, {}) 
        )
    return groupusers

def get_groups(conn, domainid, user_info, org):
    try:
        grouplist = []
        groups = list(conn.identity.groups(domain_id=domainid))
        if groups:                    
            for group in groups:    
                grouplist.append({"group_id": group.id,
                                   "group_name": group.name,
                                   "group_description": group.description
                                   })
    except Exception as e:
        logger.error(str(e), 
                     extra = custom_log("Show_groups", user_info, org, {}) 
        )
    return grouplist
                    
@swagger_auto_schema(
    method='get',
    tags=['Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],    
    responses={200: "Group Info json"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def show_group(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id     
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        if "admin" not in role:     
            adm_conn = system_admin_auth()    
            grouplist = get_groups(adm_conn, org.domain_id, user_info, org)   
            #return JsonResponse({"error": "Permission denied. Admins only."}, status=403)       
        else:
            grouplist = get_groups(conn, org.domain_id, user_info, org)   
        # Get all groups      
        rspstatus = 200             
    except Exception as e:
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure        
        logger.error(str(e), 
                     extra = custom_log("show_group", user_info, org, {}) 
        )
    return JsonResponse(grouplist, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='get',
    tags=['Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        ),
        openapi.Parameter(
            'group_name',
            in_=openapi.IN_QUERY,
            description="Group Name",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],    
    responses={200: "Group Users Info json"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_groupusers_byid(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id     
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        groupname = request.query_params.get('group_name')
        grouplist = []
        if "admin" not in role:     
            adm_conn = system_admin_auth()  
            group = adm_conn.identity.find_group(groupname, ignore_missing=False)           
            grouplist = groupinfo_byid(adm_conn, group, user_info, org)   
            #return JsonResponse({"error": "Permission denied. Admins only."}, status=403)       
        else:
            group = conn.identity.find_group(groupname, ignore_missing=False)    
            grouplist = groupinfo_byid(conn, group, user_info, org)   
        # Get all groups      
        rspstatus = 200             
    except Exception as e:
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure        
        logger.error(str(e), 
                     extra = custom_log("get_groupusers_byid", user_info, org, {}) 
        )
    return JsonResponse(grouplist, safe=False, status=rspstatus)

def update_group_name_fn(conn, current_group_name, new_group_name, new_description, user_info, org):
    group = conn.identity.find_group(current_group_name, ignore_missing=False)
    if group:
        conn.identity.update_group(group, name=new_group_name, description=new_description)
        return True
    else:
        logger.error(f"Group with ID {current_group_name} not found.", 
                    extra = custom_log("Update_group_name", user_info, org, {}) 
        )
        return False

@swagger_auto_schema(
    method='post',
    tags=['Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],  
    request_body = UpdatGroupNameSerializer,  
    responses={200: "Group Info json"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_group_name(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id     
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        if "admin" not in role:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)
        data = json.loads(request.body)      
        update_status = update_group_name_fn(conn, data.get('current_group_name'), data.get('new_group_name'), data.get('new_description'), user_info, org)
        if update_status:    
            rspstatus = 200  
            logger.info(f"Group name updated to {data.get('new_group_name')}", 
                    extra = custom_log("Update_group_name", user_info, org, {}) 
            )
            response = {"message": f"Group name updated to {data.get('new_group_name')}"}  
        else:
            rspstatus = 404           
            response = {"error": f"Group with name {data.get('current_group_name')} not found"} 
    except Exception as e:
        response = {"error": str(e)}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure        
        logger.error(str(e), 
                     extra = custom_log("Update_group_name", user_info, org, {}) 
        )
    return JsonResponse(response, safe=False, status=rspstatus)

def remove_user_from_group_fn(conn, group_name, user_names, user_info, org):
    group = conn.identity.find_group(group_name, ignore_missing=False)    
    if group:
        for username in user_names:
            user = conn.identity.find_user(username, ignore_missing=False)
            if user:
                response = {"message": f"User removed from Group {group_name}"}
                conn.identity.remove_user_from_group(user=user.id, group=group.id)
            else:
                response = {"error": f"User with name {username} not found"}
                logger.error(f"User with name {username} not found", 
                             extra = custom_log("Remove_user_fromgroup", user_info, org, {}) 
                )
                return False, response
        return True, response
    else:
        response = {"error": f"Group with name {group_name} not found"}
        logger.error(f"Group with name {group_name} not found.", 
                     extra = custom_log("Remove_user_fromgroup", user_info, org, {}) 
                    )
        return False, response
    
@swagger_auto_schema(
    method='post',
    tags=['Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],  
    request_body = RemoveUserGroupSerializer,  
    responses={200: "Response son"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def remove_user_from_group(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id     
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        if "admin" not in role:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)
        data = json.loads(request.body)      
        update_status, response = remove_user_from_group_fn(conn, data.get('group_name'), data.get('user_names'), user_info, org)
        if update_status:    
            rspstatus = 200  
            logger.info( f"User: {data.get('user_names')} removed from Group({data.get('group_name')}) ", 
                     extra = custom_log("Remove_user_fromgroup", user_info, org, {}) 
            )
        else:
            rspstatus = 404          
    except Exception as e:
        response = {"error": str(e)}
        if "not found in group " in str(e):
            response = {"error": "User Not found in Group"} 
            rspstatus = 403           
        elif isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure        
        logger.error(str(e), 
                     extra = custom_log("Remove_user_fromgroup", user_info, org, {}) 
        )
    return JsonResponse(response, safe=False, status=rspstatus)

def delete_group_fn(conn, groups, user_info, org):
    try:
        for group_name in groups:
            group = conn.identity.find_group(group_name, ignore_missing=False)
            if group:
                conn.identity.delete_group(group.id)    
        return "True"        
    except Exception as e:
        logger.error(str(e), 
                     extra = custom_log("Delete_Group", user_info, org, {}) 
        )
        return group_name
    
@swagger_auto_schema(
    method='post',
    tags=['Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],  
    request_body = DeleteGroupSerializer,  
    responses={200: "Response son"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # ✅ uses your global default
def delete_group(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id        
        user_info = request.keystone_user_info
        data = json.loads(request.body)        
        org = request.org 
        role = request.role
        if "admin" not in role:            
           return JsonResponse({"error": "Permission denied. Admins only."}, status=403)    
        data = json.loads(request.body)      
        update_status = delete_group_fn(conn, data.get('groups'), user_info, org)
        if update_status == 'True':  
            logger.info(f"Group {data['groups']} deleted successfully", 
                     extra = custom_log("Delete_Group", user_info, org, {}) 
            ) 
            response = {"message": f"Group {data['groups']} deleted successfully"} 
            rspstatus = 200  
        else:
            logger.error(f"No Group found for {update_status}", 
                     extra = custom_log("Delete_Group", user_info, org, {}) 
            )
            response = {"error": f"No Group found for {update_status}"}
            rspstatus = 404          
    except Exception as e:
        response = {"error": str(e)}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure        
        logger.error(str(e), 
                     extra = custom_log("Delete_Group", user_info, org, {}) 
        )
    return JsonResponse(response, safe=False, status=rspstatus)