# project_views.py
from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication  # Optional fallback
from rest_framework import serializers
from html import escape
from django.views.decorators.csrf import csrf_exempt
from .serializers import ProjectInfoResponseSerializer, CreateProjectSerializer, DeleteProjectSerializer, GetProjectInfoSerializer, UpdateProjectSerializer
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


def create_project_fn(conn, orgdomain, project_name, project_description, org, user_info):
    project = conn.identity.find_project(project_name,  domain_id=orgdomain.id)
    if not project:
        project = conn.identity.create_project( name=project_name, 
                                                domain_id=orgdomain.id,
                                                description=project_description
                                                )
        try:
            # Nova (compute)
            conn.compute.update_quota_set(
                project.id,
                instances=0,
                cores=0,
                ram=0
            )

            # Cinder (volume)
            conn.block_storage.update_quota_set(
                project.id,
                gigabytes=0,
                volumes=0                
            )

            # Neutron (network)
            conn.network.update_quota(
                project.id,
                networks=0,
                routers=0,
                floating_ips=0,
                security_groups=0
            )
        except Exception as e:
            logger.error(f"Error applying quota updates: {str(e)}",
                     extra = custom_log("Create Project", user_info, org, {}) 
            )
            
        ProjectID.objects.create(
            organization = org,
            projectname = project_name,
            projectid = project.id,
            projectdescription = project_description
        )
        logger.info(f"Project name {project_name} created successfully",
                    extra = custom_log("Create Project", user_info, org, {}) 
        )
        return project
    else:
        logger.error(f"Project name {project_name} already available",
                     extra = custom_log("Create Project", user_info, org, {}) 
        )
        return False

def add_user_toproject(conn, project, project_users):
    for prouser in project_users:
        user = conn.identity.find_user(prouser["username"])
        # Assign role
        role_obj = conn.identity.find_role(prouser["role"])
        if not role_obj:
            return False
        if not user:
            return False
        conn.identity.assign_project_role_to_user(project=project, user=user, role=role_obj) 
    return True 

def add_group_toproject(conn, project, groups):
    for gro in groups:
        group_obj = conn.identity.find_group(gro["groupname"])        
        role_obj = conn.identity.find_role(gro["role"])  # Or 'admin', 'member', etc.
        if not role_obj:
            return False
        if not group_obj:
            return False
        conn.identity.assign_project_role_to_group(
                group=group_obj.id,
                role=role_obj.id,
                project=project.id
            )
    return True
              
@swagger_auto_schema(
    method='post',
    tags=['Project Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],  
    request_body = CreateProjectSerializer,  
    responses={200: "Response son"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_project(request):
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
        orgdomain = conn.identity.find_domain(org.domain_id)
        if not orgdomain: 
            response = {"error": f"Failed to get Domain ID"}
            logger.error(f"Failed to get Domain ID", 
                                 extra={"organization_id":org.id,
                                        "user_id": user_id,
                                        "function_name":"Create Project"})
            return JsonResponse(response, safe=False, status=500)
        project_name = data.get('project_name')   
        project_description = data.get('project_description', "")
        if project_name:     
            # Create project if not exists
            project = create_project_fn(conn, orgdomain, project_name, project_description, org, user_info)
        else:
            response = {"error": f"project name is  missing"}
            logger.error(f"project name is missing", 
                                 extra = custom_log("Create_Project", user_info, org, {}) 
            )
            return JsonResponse(response, safe=False, status=404)
        if project:
            project_users = data.get('project_users')
            if project_users:
                adduserstatus = add_user_toproject(conn, project, project_users)
                if not adduserstatus:
                    response = {"error": f"Either User or Role is not exist"}
                    logger.error(f"Either User or Role is not exist", 
                                 extra = custom_log("Create Project", user_info, org, {}) 
                    )
                    return JsonResponse(response, safe=False, status=404)
            groups = data.get('groups')
            if groups:
                addgroupstatus = add_group_toproject(conn, project, groups)
                if not addgroupstatus:
                    logger.error(f"Either Group or Role is not exist", 
                                 extra = custom_log("Create Project", user_info, org, {}) 
                    )
                    response = {"error": f"Either Group or Role is not exist"}
                    return JsonResponse(response, safe=False, status=404)
        else:            
            response = {"error": f"Project with the name already exists"}
            logger.error(f"Project with the name already exists", 
                        extra = custom_log("Create Project", user_info, org, {}) 
            )
            return JsonResponse(response, safe=False, status=500)
        response = {"message": f"Project: {project_name} created successfully"}
        logger.info(f"Project: {project_name} created successfully", 
                                extra = custom_log("Create Project", user_info, org, {}) 
        )
        rspstatus = 200
    except Exception as e:
        response = {"error": str(e)}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Create Project", user_info, org, {}) 
        )   
    return JsonResponse(response, safe=False, status=rspstatus)

def get_project_info_fn_old(conn, domainid):
    # Get all role assignments for this project
    projectlist = conn.identity.projects(domain_id=domainid)    
    project_info = []    
    for project in projectlist:   
        assignments = conn.identity.role_assignments(project_id=project.id)
        user_info = []
        group_info = []
        # Collect user-role mapping 
        for assignment in assignments:            
            scope = assignment.scope
            if 'project' in scope and 'id' in scope['project']:       
                if scope['project']['id'] == project.id:   
                    if assignment.user:      
                        user_id = assignment.user["id"]
                        role_id = assignment.role["id"]
                        # Get user and role names
                        user = conn.identity.get_user(user_id)                
                        role = conn.identity.get_role(role_id)                                
                        if user:                   
                            user_info.append({"user_name":user.name,
                                      "user_role": role.name,
                                      "project_name": project.name
                                      })
                    if assignment.group:#assignment.group["id"]:         
                        user_id = assignment.group["id"]
                        role_id = assignment.role["id"]
                        # Get user and role names
                        group = conn.identity.get_group(user_id)                
                        role = conn.identity.get_role(role_id)                                
                        if user:                   
                            group_info.append({"group_name":group.name,
                                      "group_role": role.name,
                                      "project_name": project.name
                                      })
        project_info.append({
            "project_id":project.id,
            "project_name":project.name,
            "project_description": project.description,
            "project_domain_name": project.domain_id,
            "project_status":project.is_enabled,
            "user_info":user_info,
            "group_info":group_info
            })
    return project_info

def get_project_info_fn(conn, domainid):
    # Get all role assignments for this project
    projectlist = conn.identity.projects(domain_id=domainid)    
    project_info = []    
    for project in projectlist:
        project_info.append({
            "project_id":project.id,
            "project_name":project.name,
            "project_description": project.description,
            "project_domain_name": project.domain_id,
            "project_status":project.is_enabled            
            })
    return project_info

def get_project_list_fn(conn, domainid):    
    projectlist = conn.identity.projects(domain_id=domainid)    
    project_info = []    
    for project in projectlist:         
        project_info.append( project.name)
    return project_info


def get_parti_project_info_fn(conn, project):
    assignments = conn.identity.role_assignments(project_id=project.id)
    user_info = []
    group_info = []
    project_info = {}
    # Collect user-role mapping 
    for assignment in assignments:            
        scope = assignment.scope
        if 'project' in scope and 'id' in scope['project']:       
            if scope['project']['id'] == project.id:   
                if assignment.user:      
                    user_id = assignment.user["id"]
                    role_id = assignment.role["id"]
                    # Get user and role names
                    user = conn.identity.get_user(user_id)                
                    role = conn.identity.get_role(role_id)                                
                    if user:                   
                        user_info.append({"user_name":user.name,
                                      "user_role": role.name,
                                      "project_name": project.name
                                      })
                if assignment.group:#assignment.group["id"]:         
                    user_id = assignment.group["id"]
                    role_id = assignment.role["id"]
                    # Get user and role names
                    group = conn.identity.get_group(user_id)                
                    role = conn.identity.get_role(role_id)                                
                    if user:                   
                        group_info.append({"group_name":group.name,
                                      "group_role": role.name,
                                      "project_name": project.name
                                      })
    project_info = {
            "project_id":project.id,
            "project_name":project.name,
            "project_description": project.description,
            "project_domain_name": project.domain_id,
            "project_status":project.is_enabled,
            "user_info":user_info,
            "group_info":group_info
        }
    return project_info
                
@swagger_auto_schema(
    method='get',
    tags=['Project Management'],
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
@permission_classes([IsAuthenticated])
def show_project(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        if "admin" not in role:           
            adm_conn = system_admin_auth()  
            project_info = get_project_info_fn(adm_conn, org.domain_id)
        else:
            project_info = get_project_info_fn(conn, org.domain_id)
        rspstatus = 200
    except Exception as e:        
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("show_project", user_info, org, {}) 
        )   
    return JsonResponse(project_info, safe=False, status=rspstatus)


@swagger_auto_schema(
    method='post',
    tags=['Project Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body = GetProjectInfoSerializer,
    responses={200: ProjectInfoResponseSerializer}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def get_projectinfo_byid(request):
    try:
        project_info = {}
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        data = json.loads(request.body)
        if "admin" not in role:           
            adm_conn = system_admin_auth()  
            project = adm_conn.identity.get_project(data.get('project_id'))
            project_info = get_parti_project_info_fn(adm_conn, project)
        else:
            project = conn.identity.get_project(data.get('project_id'))
            project_info = get_parti_project_info_fn(conn, project)
        rspstatus = 200
    except Exception as e:        
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("get_project_info_byid", user_info, org, {}) 
        )   
    return JsonResponse(project_info, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='post',
    tags=['Project Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=DeleteProjectSerializer,
    responses={200: "JSON Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_project(request):
    try:        
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        if "admin" not in role:       
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)   
        data = json.loads(request.body)  
        delete_projects = data.get("projects")
        # Find the project first (safe way)
        for pro in delete_projects:
            if pro == org.main_project_name:
                response = {"message": f"Not able to delete this default Project-{pro}" }
                logger.info(f"Not able to delete this default Project-{pro}",
                            extra = custom_log("Delete_project", user_info, org, {}) 
                )
                rspstatus = 403
                break
            project = conn.identity.find_project(pro, domain_id=org.domain_id)
            if project:
                try:
                    compute_quotas = conn.compute.get_quota_set(project.id).to_dict()                    
                    volume_quotas = conn.block_storage.get_quota_set(project.id).to_dict()                    
                    network_quotas = conn.network.get_quota(project.id).to_dict()                    
                except Exception as e:
                    response = {"error": str(e)}
                    logger.error(f"{str(e)}", 
                    extra = custom_log("Delete_project", user_info, org, {}) 
                    )   
                    return JsonResponse(response, safe=False, status=rspstatus)

                # --- Update organization DB pools ---        
                org.unalloted_instances += compute_quotas["instances"]
                org.unalloted_vcpus += compute_quotas["cores"]
                org.unalloted_ram_mb += compute_quotas["ram"]
                org.unalloted_volumes += volume_quotas.get("volumes")
                org.unalloted_volume_gb += volume_quotas.get("gigabytes")       
                org.unalloted_networks += network_quotas.get("networks")
                org.unalloted_routers += network_quotas.get("routers")
                org.unalloted_floating_ips += network_quotas.get("floating_ips")
                org.unalloted_security_groups += network_quotas.get("security_groups")       

                #Delete Project
                conn.identity.delete_project(project.id)  

                #Save the updated unallocated Pool
                org.save(update_fields=[
                    "unalloted_instances", "unalloted_vcpus", "unalloted_ram_mb",
                    "unalloted_volumes", "unalloted_volume_gb", 
                    "unalloted_networks", "unalloted_routers",
                    "unalloted_floating_ips", "unalloted_security_groups"
                ])              
                logger.info(f"Project '{project.name}' deleted.", 
                        extra = custom_log("Delete_project", user_info, org, {}) 
                )
                rspstatus = 200
            else:
                response = {"error": f"Project '{pro}' not found."}
                logger.error(f"Project '{pro}' not found.",
                         extra = custom_log("Delete_project", user_info, org, {}) 
                )
                rspstatus = 400
                break
        if rspstatus == 200:
            response = {"message": f"Project {delete_projects} deleted." }
    except Exception as e:     
        response = {"error": str(e)}   
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Delete_project", user_info, org, {}) 
        )   
    return JsonResponse(response, safe=False, status=rspstatus)

def unassign_user_role(conn, project, user_name, user_role):
    user_obj = conn.identity.find_user(user_name, ignore_missing=False)
    role_obj = conn.identity.find_role(user_role, ignore_missing=False)
    if not user_obj:
        return False
    if not role_obj:
        return False
    conn.identity.unassign_project_role_from_user(
        project=project,
        user=user_obj.id,
        role=role_obj.id
    )
    return True

def unassign_group_fromproject(conn, project, groupname, grouprole):    
    group_obj = conn.identity.find_group(groupname)        
    role_obj = conn.identity.find_role(grouprole)  # Or 'admin', 'member', etc.
    if not role_obj:
        return False
    if not group_obj:
        return False
    conn.identity.unassign_project_role_from_group(
                group=group_obj.id,
                role=role_obj.id,
                project=project.id
            )
    return True
@swagger_auto_schema(
    method='post',
    tags=['Project Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],  
    request_body = UpdateProjectSerializer,  
    responses={200: "Response Json"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # ✅ uses your global default
def update_project(request):
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
        orgdomain = conn.identity.find_domain(org.domain_id)
        if not orgdomain: 
            response = {"error": f"Failed to get Domain ID"}
            logger.error(f"Failed to get Domain ID", 
                        extra = custom_log("Update_project", user_info, org, {}) 
            )
            return JsonResponse(response, safe=False, status=500)
        project_id = data.get('project_id')
        project_name = data.get('project_name')   
        project_description = data.get('project_description', "")
        if not project_id:
            response = {"error": f"project name is missing"}
            logger.error(f"project name is  mssing", 
                        extra = custom_log("Update_project", user_info, org, {}) 
            )
            return JsonResponse(response, safe=False, status=404)
        
        # Create project if not exists
        project = conn.identity.find_project(project_id,  domain_id=orgdomain.id)
        if not project:
            response = {"error": f"project: {project_id} is not exists"}
            logger.error(f"project: {project_id} is not exists", 
                        extra = custom_log("Update_project", user_info, org, {}) 
            )
            return JsonResponse(response, safe=False, status=404)
        project = conn.identity.update_project(
                project_id,
                name=project_name,                # ✅ new name
                description=project_description   # ✅ new description
        )
        project_info = get_parti_project_info_fn(conn, project)
        project_users = data.get('project_users')
        if project_users:
            adduserstatus = add_user_toproject(conn, project, project_users)
            if not adduserstatus:
                    response = {"error": f"Either User or Role is not exist"}
                    logger.error(f"Either User or Role is not exist", 
                                 extra = custom_log("Update_project", user_info, org, {}) 
                    )
                    return JsonResponse(response, safe=False, status=404)
            old_users = project_info.get("user_info") 
            usrstatus = True 
            grstatus = True          
            for old_user in old_users:                          
                useravailable = False
                for upuser in project_users:  
                    if old_user["user_name"] == upuser["username"]:
                        useravailable = True
                        if old_user["user_role"] == upuser["role"]:
                            continue
                        else:
                            #unassign the old role
                            usrstatus = unassign_user_role(conn, project, old_user["user_name"], old_user["user_role"])                            
                if not useravailable:                    
                    #unassign the deleted user from project
                    usrstatus = unassign_user_role(conn, project, old_user["user_name"], old_user["user_role"])    
        groups = data.get('groups')
        if groups:
            addgroupstatus = add_group_toproject(conn, project, groups)
            if not addgroupstatus:
                logger.error(f"Either Group or Role is not exist", 
                                extra = custom_log("Update_project", user_info, org, {}) 
                )
                response = {"error": f"Either Group or Role is not exist"}
                return JsonResponse(response, safe=False, status=404)
            old_groups = project_info.get("group_info")
            for old_group in old_groups:
                groupavailable = False
                for upgroup in groups:  
                    if old_group["group_name"] == upgroup["groupname"]:
                        groupavailable = True
                        if old_group["group_role"] == upgroup["role"]:
                            continue
                        else:
                            print("old_group", old_group)
                            #unassign the old group because of role mismatch
                            grstatus = unassign_group_fromproject(conn, project, old_group['group_name'], old_group["group_role"])
                if not groupavailable:
                    #unassign the old group because removed currently by update
                    grstatus = unassign_group_fromproject(conn, project, old_group['group_name'], old_group["group_role"])
        if not usrstatus or not grstatus:
            logger.error(f"Either user/Group or Role is not exist", 
                            extra = custom_log("Update_project", user_info, org, {}) 
            )
            response = {"error": f"Either User/Group or Role is not exist"}
            return JsonResponse(response, safe=False, status=404)
        response = {"message": f"Project: {project_name} updated successfully"}
        logger.info(f"Project: {project_name} updated successfully", 
                    extra = custom_log("Update_project", user_info, org, {}) 
        )
        rspstatus = 200
    except Exception as e:
        response = {"error": str(e)}
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                        extra = custom_log("Update_project", user_info, org, {})
        )   
    return JsonResponse(response, safe=False, status=rspstatus)

@swagger_auto_schema(
    method='get',
    tags=['Project Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: "List of Projects"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])  # ✅ uses your global default
def get_project_list(request):
    try:
        conn = request.keystone_conn
        user_id = request.keystone_user_id    
        user_info = request.keystone_user_info             
        org = request.org 
        role = request.role
        if "admin" not in role:   
            conn = system_admin_auth()         
        #   return JsonResponse({"error": "Permission denied. Admins only."}, status=403)
            
        #project_info = get_project_list_fn(conn, org.domain_id)
        project_list = []
        assignments = conn.identity.role_assignments(user_id=user_id)
        for assignment in assignments:            
            scope = assignment.scope
            if 'project' in scope and 'id' in scope['project']:   
                if assignment.user:  
                    if user_id == assignment.user["id"]:
                        project_id = scope['project']['id']
                        projectli = conn.identity.get_project(project_id)
                        project_list.append(projectli.name)
        rspstatus = 200
    except Exception as e:        
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("Get Project List", user_info, org, {})
        )   
    return JsonResponse(project_list, safe=False, status=rspstatus)
