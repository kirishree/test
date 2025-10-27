# views.py

from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication  # Optional fallback
from rest_framework import serializers
from html import escape
from django.views.decorators.csrf import csrf_exempt
from .serializers import AuthLoginSerializer, AuthLoginResponseSerializer, ProjectInfoResponseSerializer, CreateGroupSerializer, AddGroupSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
from api.models import Organization, RegisteredUser, ProjectID, OrgGroup, OrgGroupUsers
from django.core.cache import cache
import onboarding
import logging
import os
logger = logging.getLogger('cloud')
#from django.db import connection
from keystoneauth1 import session
from decouple import config
from datetime import timedelta
from keystoneauth1.identity import v3
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

def normalize_name(name):
    return name.strip().lower().replace(" ", "_")

@swagger_auto_schema(
    method='post',
    tags=['Authentication'],
    request_body=AuthLoginSerializer,
    responses={200: AuthLoginResponseSerializer}
)
@api_view(['POST'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def login_view(request):
    data = json.loads(request.body)
    username = data.get("username")
    password = data.get("password")
    try:
        reg_user = RegisteredUser.objects.select_related('organization').get(username=username)
        org = reg_user.organization  
            # Step 1: Try login with Keystone
        auth = v3.Password(auth_url=KEYSTONE_URL,
                           username=username,
                           password=password,
                           user_domain_name=org.domain_name)
        sess = session.Session(auth=auth)
        token = sess.get_token()
        user_id = sess.get_user_id()                 
        login_response = {
                    "status": "ok",                           
                    "token": token,
                    "username": reg_user.username,
                    "first_name": reg_user.first_name,
                    "last_name": reg_user.last_name,
                    "user_role": reg_user.user_role,
                    "organization_id": org.organization_id,
                    "organization_name": org.organization_name,
                    "subscription_from": org.subscription_from,
                    "subscription_to": org.subscription_to
                }        
        logger.info(
                    f"{username} Logged in",
                    extra={
                            "user_name": username,
                            "user_id": str(user_id),
                            "org_name": org.organization_name,
                            "org_id": org.organization_id,
                            "project_id": org.main_project_id,
                            "project_name": org.main_project_name,                            
                            "function_name": "Login",
                            "exception": ''
                        }
            ) 
        responsestatus = 200        
        return JsonResponse(login_response, status=responsestatus)
    except Exception:        
        pass  # Continue to onboarding check
    onboard_status, onboard_info = onboarding.check_login_onboarding_new(username, password)
    # Step 2: Check onboarding API
    if onboard_status != "True":
        logger.error(
                    f"New user: {username} not added due to {onboard_status}",
                    extra={                                                 
                            "function_name": "Login",
                            "exception": ''
                        }
        )  
        login_response =  {"status": onboard_status}      
        return JsonResponse(login_response, status=400)
    if onboard_info["user_role"] == "ADMIN":
        user_role = "org-admin"
        keystone_role = "admin"
    else:
        user_role = "org-user"
        keystone_role = "member"
    # OpenStack admin session
    # Enable debug logging
    #openstack.enable_logging(debug=True)
    admin_auth = v3.Password(auth_url=KEYSTONE_URL,
                             username="admin",
                             password=ADMIN_PASSWORD,
                             project_name="admin",
                             user_domain_name=DEFAULT_DOMAIN,
                             project_domain_name=DEFAULT_DOMAIN)
    admin_sess = session.Session(auth=admin_auth)
    conn = os_connection.Connection(session=admin_sess)
    conn.authorize()   
    # Create domain if not exists
    org_name = normalize_name(onboard_info["organization_name"])
    org_domain_name = f"{normalize_name(org_name)}_domain"
    project_name = f"{normalize_name(org_name)}_project"
    orgdomain = conn.identity.find_domain(org_domain_name)
    if not orgdomain:
        orgdomain = conn.identity.create_domain(
            name=org_domain_name,
            description=f"{org_name} domain",
            enabled=True
        )
    # Create project if not exists
    project = conn.identity.find_project(project_name,  domain_id=orgdomain.id)
    if not project:
        project = conn.identity.create_project( name=project_name, 
                                                domain_id=orgdomain.id,
                                                description=f"Project for {org_name}"
                                                )
        try:
            org = Organization.objects.get(organization_id=onboard_info["organization_id"])
        except Organization.DoesNotExist:                                
            Organization.objects.create(
                organization_id = onboard_info["organization_id"],
                organization_name = onboard_info["organization_name"],
                subscription_from = onboard_info["subscription_from"],
                subscription_to = onboard_info["subscription_to"], 
                total_instance = onboard_info["total_instance"],
                remaining_instance = onboard_info["remaining_instance"],
                domain_name = orgdomain.name,
                domain_id = orgdomain.id,
                main_project_name = project_name,
                main_project_id = project.id
                )
    # Create user
    user = conn.identity.find_user(username)
    if not user:
        user = conn.identity.create_user(
            name=username,
            domain_id=orgdomain.id,
            default_project_id=project.id,
            password=password
        )

    # Assign role
    role_obj = conn.identity.find_role(keystone_role )
    #if not role_obj:
    #    role_obj = conn.identity.create_role(name=user_role)
    conn.identity.assign_project_role_to_user(project=project, user=user, role=role_obj)
    # Log onboarding info to custom DB        
    try:
        org = Organization.objects.get(organization_id=onboard_info["organization_id"])
        reg_user = RegisteredUser.objects.create(
                        organization=org,
                        username=username,
                        userid=onboard_info["user_id"],
                        first_name=onboard_info["first_name"],
                        last_name=onboard_info["last_name"],
                        user_role=user_role,
                        keystone_userid = str(user.id)
                    )        
    except Organization.DoesNotExist: 
        logger.error(
                    f"Organization Not exist in DB",
                    extra={
                            "user_name": username,
                            "user_id": "Not created",
                            "org_name": org_name,
                            "org_id": onboard_info["organization_id"],
                            "project_id": str(project.id),
                            "project_name": project_name,                            
                            "function_name": "Login",
                            "exception": ''
                        }
        )
        login_response = {"status": "Organization not exist in DB"}
        return JsonResponse(login_response, status=500)        
    # Step 4: Re-authenticate
    new_auth = v3.Password(auth_url=KEYSTONE_URL,
                           username=username,
                           password=password,
                           user_domain_name=orgdomain.name)
    new_sess = session.Session(auth=new_auth)
    new_token = new_sess.get_token()
    login_response = {
                "status": "ok",                           
                "token": new_token,
                "username": username,
                "first_name": onboard_info["first_name"],
                "last_name": onboard_info["last_name"],
                "user_role": user_role,
                "organization_id": onboard_info["organization_id"],
                "organization_name": org_name,
                "subscription_from": org.subscription_from,
                "subscription_to": org.subscription_to                
            }   
    logger.info(
                    f"New User added to cloud ",
                    extra={
                            "user_name": username,
                            "user_id": str(user.id),
                            "org_name": org_name,
                            "org_id": onboard_info["organization_id"],
                            "project_id": str(project.id),
                            "project_name": org_name,                            
                            "function_name": "Login",
                            "exception": ''
                        }
        )
    return JsonResponse(login_response, status=200)

def get_openstack_connection(token):
    auth = v3.Token(auth_url=KEYSTONE_URL, token=token)
    sess = session.Session(auth=auth)
    return os_connection.Connection(session=sess)

@swagger_auto_schema(
    method='get',
    tags=['Project Info'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: ProjectInfoResponseSerializer}
)
@api_view(['GET'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def project_info(request):
    try:
        user_info = []
        token = request.headers.get("X-Auth-Token")
        if not token:
            return JsonResponse({"detail": "Missing token ID"}, status=400)
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token)
        sess = session.Session(auth=auth)
        # Trigger token validation and get access info
        access_info = sess.auth.get_access(sess)
        project_id = access_info.project_id
        conn = os_connection.Connection(session=sess)
        # Extract values
        user_id = access_info.user_id
        
        try:
            reg_user = RegisteredUser.objects.select_related('organization').get(keystone_userid=user_id)
            org = reg_user.organization 
        except RegisteredUser.DoesNotExist:
            logger.error(f"User not exist in Onboarding DB ", extra={                            
                            "user_id": user_id,                            
                            "project_id": project_id,                                                       
                            "function_name": "Project Info",
                            "exception": ''
                        }) 
            return JsonResponse(user_info, safe=False, status=400)      
        # Get all role assignments for this project
        assignments = conn.identity.role_assignments()
        # Collect user-role mapping 
        for assignment in assignments:
            scope = assignment.scope
            if 'project' in scope and 'id' in scope['project']:
                assignment_project_id = scope['project']['id']
                if assignment_project_id == project_id:
                    user_id = assignment.user["id"]
                    role_id = assignment.role["id"]
                    # Get user and role names
                    user = conn.identity.get_user(user_id)                
                    role = conn.identity.get_role(role_id) 
                    project = conn.identity.get_project(project_id)              
                    if user:                   
                        user_info.append({"user_name":user.name,
                                      "user_role": role.name,
                                      "project_name": project.name
                                      })
        respstatus = 200
        logger.info(f" Get Project info ",
                    extra={
                            "user_name": reg_user.username,
                            "user_id": user_id,
                            "org_name": org.organization_name,
                            "org_id": org.organization_id,
                            "project_id": project_id,
                            "project_name": project.name,                            
                            "function_name": "Project Info",
                            "exception": ""
                        })
    except Exception as e:
        respstatus = 500
        logger.error(
            f"Error in Get Project info ",
                    extra={
                            "user_name": reg_user.username,
                            "user_id": user_id,
                            "org_name": org.organization_name,
                            "org_id": org.organization_id,
                            "project_id": project_id,
                            "project_name": "",                            
                            "function_name": "Project Info",
                            "exception": str(e)
                        }
        )        
    return JsonResponse(user_info, safe=False, status=respstatus)

@swagger_auto_schema(
    method='post',
    tags=['Group'],
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
    responses={200: ProjectInfoResponseSerializer}
)
@api_view(['POST'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def create_group(request):
    try:        
        token = request.headers.get("X-Auth-Token")
        if not token:
            return JsonResponse({"detail": "Missing token ID"}, status=400)
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token)
        sess = session.Session(auth=auth)
        # Trigger token validation and get access info
        access_info = sess.auth.get_access(sess)
        conn = os_connection.Connection(session=sess)
        # Extract values
        user_id = access_info.user_id     
        try:
            reg_user = RegisteredUser.objects.select_related('organization').get(keystone_userid=user_id)
            org = reg_user.organization            
            user_role = reg_user.user_role
            if user_role != "org-admin":
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)
        except RegisteredUser.DoesNotExist:
            return JsonResponse({"error": "User not found in registered users."}, status=404)
        #project_id = access_info.project_id
        data = json.loads(request.body)
        group_obj = conn.identity.find_group(data.get('group_name'))
        if not group_obj:
            group = conn.identity.create_group(
                name=data.get('group_name'),
                description=data.get('group_description', '')
            )
        else:
            groupname = data.get('group_name')
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
                    extra={
                            "user_name": reg_user.username,
                            "user_id": user_id,
                            "org_name": org.organization_name,
                            "org_id": org.organization_id,
                            "project_id": str(access_info.project_id),                                               
                            "function_name": "Create Group"                           
                        }
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
            extra={
            "user_name": reg_user.username if 'reg_user' in locals() else None,
            "user_id": user_id if 'user_id' in locals() else None,
            "org_name": org.organization_name if 'org' in locals() else None,
            "org_id": org.organization_id if 'org' in locals() else None,
            "project_id": str(access_info.project_id) if 'access_info' in locals() else None,
            "function_name": "Create Group",
            "exception": str(e)
            }
        )
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='get',
    tags=['Group'],
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
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def show_group(request):
    try:
        userlist = []
        projectlist = []
        grouplist = []
        show_all = {}
        token = request.headers.get("X-Auth-Token")
        if not token:
            return JsonResponse({"detail": "Missing token ID"}, status=400)
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token)
        sess = session.Session(auth=auth)
        # Trigger token validation and get access info
        access_info = sess.auth.get_access(sess)
        conn = os_connection.Connection(session=sess)
        # Extract values
        user_id = access_info.user_id    
        #project_id = access_info.project_id
        reg_user = RegisteredUser.objects.select_related('organization').get(keystone_userid=user_id)
        org = reg_user.organization 
        groups_db = OrgGroup.objects.filter(organization_id=org.organization_id)
        if "admin" not in reg_user.user_role:
            users_in_org = RegisteredUser.objects.filter(organization=org)
            for userindb in users_in_org:
                userlist.append({"username": userindb.username,
                             "user_id": userindb.userid
                             })             
            projects_in_org = ProjectID.objects.filter(registereduser=reg_user)
            projectlist.append({"project_name": org.main_project_name,
                                "project_id": org.main_project_id})
            for projectindb in projects_in_org:
                projectlist.append({"project_name": projectindb.projectname,
                                "project_id": projectindb.projectid})
            groups_in_org = OrgGroup.objects.filter(organization=org)
            for group in groups_in_org:
                group_users = OrgGroupUsers.objects.filter(group=group)
                print(f"Group: {group.group_name}")
                groupusers = []
                for gu in group_users:                    
                    groupusers.append(gu.username)
                grouplist.append({group.group_name:groupusers})
            show_all = {"users":userlist, "projects":projectlist, "groups":grouplist}
        else:
            # List users in the domain
            users = list(conn.identity.users(domain_id=org.domain_id))
            for user in users:
                userlist.append({"username": user.name,
                             "user_id": user.id})
            # List projects in the domain
            projects = list(conn.identity.projects(domain_id=org.domain_id))
            for pro in projects:
                projectlist.append({"project_name": pro.name,
                                "project_id": pro.id})

            # Get all groups
            groups = list(conn.identity.groups())        
            for group in groups:            
                for dgroup in groups_db:
                    if dgroup.keystone_group_id == group.id:
                        grouplist.append({"group_id": group.id,
                                   "group_name": group.name,
                                   "group_description": group.description})
                        break
            show_all = {"users":userlist, "projects":projectlist, "groups":grouplist}
        logger.error(
            "Show Groups",
            extra={
            "user_name": reg_user.username if 'reg_user' in locals() else None,
            "user_id": user_id if 'user_id' in locals() else None,
            "org_name": org.organization_name if 'org' in locals() else None,
            "org_id": org.organization_id if 'org' in locals() else None,
            "project_id": str(access_info.project_id) if 'access_info' in locals() else None,
            "function_name": "Show Group",
            "exception": ""
            }
        )
        rspstatus = 200                
    except Exception as e:
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure        
        logger.error(
            "Failed to show Groups",
            extra={
            "user_name": reg_user.username if 'reg_user' in locals() else None,
            "user_id": user_id if 'user_id' in locals() else None,
            "org_name": org.organization_name if 'org' in locals() else None,
            "org_id": org.organization_id if 'org' in locals() else None,
            "project_id": str(access_info.project_id) if 'access_info' in locals() else None,
            "function_name": "Show Group",
            "exception": str(e)
            }
        )
    return JsonResponse(show_all, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Group'],
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
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def add_userto_group(request):
    try:  
        log_extra = {"function_name": "Add User to Group"}  
        data = json.loads(request.body)
        groupname = data.get('group_name')
        token = request.headers.get("X-Auth-Token")
        if not token:
            return JsonResponse({"detail": "Missing token ID"}, status=400)
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token)
        sess = session.Session(auth=auth)
        # Trigger token validation and get access info
        access_info = sess.auth.get_access(sess)
        conn = os_connection.Connection(session=sess)
        # Extract values
        user_id = access_info.user_id     
        try:
            reg_user = RegisteredUser.objects.select_related('organization').get(keystone_userid=user_id)
            org = reg_user.organization            
            user_role = reg_user.user_role
            if user_role != "org-admin":
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)
        except RegisteredUser.DoesNotExist:
            return JsonResponse({"error": "User not found in registered users."}, status=404)
        # Add user to group
        org_info = OrgGroup.objects.select_related('organization').get(group_name=groupname)
        groupinfo = OrgGroup.objects.get(group_name=groupname)
        rspstatus = 200
        log_extra={
                "user_name": reg_user.username,
                "user_id": user_id,
                "org_name": org.organization_name,
                "org_id": org.organization_id,
                "project_id": str(access_info.project_id),
                "function_name": "Add User to Group",
                "exception": ""
             }
        # Ensure group belongs to the requesting user's org
        if org_info.organization.organization_id == org.organization_id:
            response = {"message": f"Successfully User added to Group {groupname}" }
            rspstatus = 200            
            for username in data.get('users'):
                try:
                    user_obj = RegisteredUser.objects.select_related('organization').get(username=username)
                    if user_obj.organization.organization_id == org.organization_id:
                        # Get Keystone user and group IDs
                        keystone_user = conn.identity.find_user(username)
                        keystone_group = conn.identity.find_group(groupname)

                        if keystone_user and keystone_group:
                            conn.identity.add_user_to_group(user=keystone_user, group=keystone_group)
                            OrgGroupUsers.objects.create(
                                group=groupinfo,
                                username=username
                            )
                        else:
                            response = {"message":f"User or group not found for: {username}, {groupname}"}
                            logger.warning(response["message"], extra=log_extra)
                            rspstatus = 404
                            break
                    else:
                        response = {"message":f"User '{username}' does not belong to organization '{org.organization_name}'"}
                        logger.warning(response["message"], extra=log_extra)
                        rspstatus = 403
                        break
                except RegisteredUser.DoesNotExist:   
                    response = {"message": f"User '{username}' not found in RegisteredUser table."}                 
                    logger.warning(response["message"], extra=log_extra)
                    rspstatus = 404   
            if rspstatus == 200:
                logger.info(response["message"], extra=log_extra)         
        else:
            rspstatus = 403
            response = {"message":f"Group '{groupname}' does not belong to organization '{org.organization_name}'"}
            logger.warning(response["message"], extra=log_extra)        
    except Exception as e:
        response = {"message": "Internal Server Error"}
        log_extra["exception"] = str(e)
        logger.error(response["message"], extra=log_extra)
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure        
    return JsonResponse(response, safe=False, status=rspstatus)        
        
@swagger_auto_schema(
    method='get', 
    tags=['Log'],
    responses={200: "Log info JSON"}
) 
@api_view(['GET'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def logfile_content(request):
    logfile_content = ["No Log configured yet"]
    log_file_path = "/opt/cloud/log/cloud_custom.log"

    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as file:
            logfile_content = file.readlines()

    logfile_content.reverse()
    return JsonResponse({'log': logfile_content})