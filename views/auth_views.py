# views.py

from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication  # Optional fallback
from rest_framework import serializers
from html import escape
from django.views.decorators.csrf import csrf_exempt
from .serializers import AuthLoginSerializer, AuthLoginResponseSerializer, SwitchProSerializer, switchProResponseSerializer, UserInfoResponseSerializer, ProjectInfoResponseSerializer, CreateGroupSerializer, AddGroupSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
from api.models import Organization, RegisteredUser, ProjectID, OrgGroup, OrgGroupUsers
from api.models import OrganizationReachStack, UserReachStack, Subscription
from django.core.cache import cache
from custom_log_info import custom_log_data, custom_log
import logging
import os
logger = logging.getLogger('cloud')
#from django.db import connection
from keystoneauth1 import session
from keystoneauth1.identity import v3
from openstack import connection
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
LOGIN_CACHE_TIME = int(config('LOGIN_CACHE_TIME'))
DEFAULT_DOMAIN = "Default"
ORG_ADMIN_ROLE = "org-admin"
ORG_USER_ROLE = "org-user"
SECURITY_RULES_PER_INSTANCE = int(config('SECURITY_RULES_PER_INSTANCE'))
PORTS_PER_INSTANCE = int(config('PORTS_PER_INSTANCE'))
from django.contrib.auth.hashers import check_password


def admin_auth():
    admin_auth = v3.Password(auth_url=KEYSTONE_URL,
                             username="admin",
                             password=ADMIN_PASSWORD,
                             project_name="admin",
                             user_domain_name=DEFAULT_DOMAIN,
                             project_domain_name=DEFAULT_DOMAIN)
    admin_sess = session.Session(auth=admin_auth)
    conn = os_connection.Connection(session=admin_sess)
    conn.authorize()   
    return conn

def system_admin_auth():
    system_admin_auth = v3.Password(
        auth_url=KEYSTONE_URL,
        username="admin",
        password=ADMIN_PASSWORD,        
        user_domain_name=DEFAULT_DOMAIN,
        system_scope="all"
        )
    admin_sess = session.Session(auth=system_admin_auth)
    conn = os_connection.Connection(session=admin_sess)
    conn.authorize()   
    return conn

def system_admin_token():
    system_admin_auth = v3.Password(
        auth_url=KEYSTONE_URL,
        username="admin",
        password=ADMIN_PASSWORD,        
        user_domain_name=DEFAULT_DOMAIN,
        system_scope="all"
    )
    sess = session.Session(auth=system_admin_auth)   
    conn = os_connection.Connection(session=sess)
    conn.authorize()  
    token = sess.get_token()      
    return token, conn

def create_domain(conn, org_name, org_domain_name):
    orgdomain = conn.identity.find_domain(org_domain_name)
    if not orgdomain:
        orgdomain = conn.identity.create_domain(
            name=org_domain_name,
            description=f"{org_name} domain",
            enabled=True
        )
    return orgdomain

def create_project(conn, orgdomain, project_name, org_name):
    project = conn.identity.find_project(project_name,  domain_id=orgdomain.id)
    if not project:
        project = conn.identity.create_project( name=project_name, 
                                                domain_id=orgdomain.id,
                                                description=f"Project for {org_name}"
                                                )
        subscribed_users = 0
        compute_data = {"instances": subscribed_users,
                "cores":subscribed_users ,
                "ram":subscribed_users 
                }
        volume_data = {"gigabytes":subscribed_users,
                       "volumes": subscribed_users,
                        "snapshots": 0 }       


        network_data = {"floating_ips":subscribed_users,
                        "networks": 1,                        
                        "routers": 1,
                        "security_groups": 1,
                        "security_group_rules":SECURITY_RULES_PER_INSTANCE,
                        "ports":PORTS_PER_INSTANCE
                        }
        update_compute = conn.compute.update_quota_set(project.id, **compute_data)
        update_volume = conn.block_storage.update_quota_set(project.id, **volume_data)
        update_newtork = conn.network.update_quota(project.id, **network_data)              
    return project

def user_auth(username, password, domain_name, project_name, domain_id1):
    #print("project_name", project_name)
    try:
        auth = v3.Password(
            auth_url=KEYSTONE_URL,
            username=username,
            password=password,
            user_domain_id=domain_id1,                    
            project_id=project_name,
            project_domain_id=domain_id1
        )
        sess = session.Session(auth=auth)
        token = sess.get_token()
        return token
    except Exception as e:
        print("Authentication failed:", str(e))
        raise

def create_shared_nw(conn, project, network_name, subnet_name, router_name):
    try:
        network = conn.network.find_network(network_name)
        if not network:
            network = conn.network.create_network(
                name=network_name,                
                admin_state_up = True,   
                is_shared = True,                             
                project_id=project.id, # optional 
                mtu=1450
            )
        subnet = conn.network.find_subnet(subnet_name)
        if not subnet:
            subnet = conn.network.create_subnet(
                name=subnet_name,
                network_id=network.id,
                ip_version=4,
                cidr="192.168.66.0/24",
                gateway_ip="192.168.66.1",
                enable_dhcp=True,
                allocation_pools=[
                    {
                        "start": "192.168.66.100",
                        "end": "192.168.66.200"
                    }
                ],
                dns_nameservers=["8.8.8.8", "8.8.4.4"]                
            )
        #Find Router
        router  = conn.network.find_router(router_name)
        if not router:
            # Step 1: Create Router
            router = conn.network.create_router(name=router_name, admin_state_up=True)
            # Step 2: Set External Gateway                   
            external_net = conn.network.find_network("public-net")
            if external_net:            
                conn.network.update_router(
                    router,
                    external_gateway_info={"network_id": external_net.id,
                                   "enable_snat": True}
                )
                conn.network.add_interface_to_router(router, subnet_id=subnet.id)
        return True, network.id, subnet.id
    except Exception as e:
        logger.error(f"Network creation error - {str(e)}")
        return False, None, None

@swagger_auto_schema(
    method='post',
    tags=['Authentication & Token Management'],
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
    user = UserReachStack.objects.filter(email=data.get('username')).first()
    if username == "admin":
        try:        
            system_admin_auth = v3.Password(
                auth_url=KEYSTONE_URL,
                username=username,
                password=password,        
                user_domain_name=DEFAULT_DOMAIN,
                system_scope="all"
            )
            sess = session.Session(auth=system_admin_auth)
            token = sess.get_token()    
            org = user.organization        
            login_response = {
                    "status": "ok",                           
                    "token": token,
                    "username": username,                    
                    "user_role": "admin",                    
                    "default_project_name":org.default_project_name,
                    "default_project_id":org.default_project_id                    
                }
            return JsonResponse(login_response, safe=False, status=200) 
        except Exception as e:
            print("Authentication failed:", str(e))
            return JsonResponse({"error": "Authentication failed"})        
    try:        
        if not user:
            return JsonResponse({"status": "User not registered"}, safe=False, status=400)
        if user.organization.default_project_id:
            org = user.organization
            # Step 1: Try login with Keystone
            token = user_auth(username, password, org.domain_name, org.default_project_id, org.domain_id)
            if user.role == "admin":
                role = "org-admin"
            elif user.role == "member":
                role = "org-user"
            elif user.role == "reader":
                role = "org-reader"
            org = user.organization
            subs = Subscription.objects.filter(organization=org, status="active").first()
            if subs:
                subscrition_taken = True
            else:
                subscrition_taken = False
            login_response = {
                    "status": "ok",                           
                    "token": token,
                    "username": user.username,                    
                    "user_role": role,                    
                    "default_project_name":org.default_project_name,
                    "default_project_id":org.default_project_id,
                    "subscription_taken": subscrition_taken
                }
            logger.info(
                    f"{username} Logged in",
                    extra=custom_log_data(username, user.keystone_id, org.organization_name, org.id, org.default_project_id, org.default_project_name, "Login", "")
                    ) 
            responsestatus = 200        
            return JsonResponse(login_response, safe=False, status=responsestatus) 
        else:  
            if check_password(data.get('password'), user.password):
                org = user.organization
                if org.stripe_payment_method_id:
                    #openstack.enable_logging(debug=True)
                    conn = admin_auth()   
                    org_name, org_domain_name, project_name = normalize_name(user.username)
                    # Create domain if not exists
                    orgdomain = create_domain(conn, org_name, org_domain_name)
                    # Create project if not exists
                    project = create_project(conn, orgdomain, project_name, org_name)
                    #create Shared Network if not exist
                    network_name = f"network_{org_name.lower()}"
                    subnet_name = f"subnet_{org_name.lower()}"   
                    router_name = f"router_{org_name.lower()}" 
                    #create user if not exist
                    keystone_user = create_user(conn, username, orgdomain, project, password, user.role)
                    conn.close()
                    org.default_project_id = project.id
                    org.default_project_name = project.name
                    org.domain_id = orgdomain.id
                    org.domain_name = orgdomain.name
                    user.keystone_id = keystone_user.id
                    user.save()
                    org.save()
                    # Step 4: Re-authenticate
                    new_token = user_auth(username, password, orgdomain.name, project.id, orgdomain.id)
                    if user.role == "admin":
                        role = "org-admin"
                    elif user.role == "member":
                        role = "org-user"
                    elif user.role == "reader":
                        role = "org-reader"
                    subs = Subscription.objects.filter(organization=org, status="active").first()
                    if subs:
                        subscrition_taken = True
                    else:
                        subscrition_taken = False
                    login_response = {
                            "status": "ok",                           
                            "token": new_token,
                            "username": user.username,                                                        
                            "user_role": role,                    
                            "default_project_name":project.name,
                            "default_project_id":project.id,
                            "subscription_taken": subscrition_taken
                    }     
                    logger.info(f"New User added to cloud ",
                        extra= custom_log_data(username, str(user.id), org_name, org.id, str(project.id), project_name, "Login", "")
                    )                    
                    #create new conncection with new credentials
                    auth = v3.Token(auth_url=KEYSTONE_URL, token=new_token, project_id=project.id)
                    sess = session.Session(auth=auth)
                    user_conn = connection.Connection(session=sess)
                    ntwk_status, network_id, subnet_id = create_shared_nw(user_conn, project, network_name, subnet_name, router_name)
                    user_conn.close()
                    return JsonResponse(login_response, safe=False, status=200)
                else:
                    return JsonResponse({"error": "Payment Method not added"})
            else:
                return JsonResponse({"error":"Invalid Credentials"})
    except Exception as e:
        print("auth error", str(e))
        return JsonResponse({"error": f"{str(e)}"})
      
def auth_token(token, function_name):
    try:
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token)
        sess = session.Session(auth=auth)
        access_info = sess.auth.get_access(sess)
        project_id = access_info.project_id
        user_id = access_info.user_id
        conn = os_connection.Connection(session=sess)
        return conn, project_id, user_id
    except Unauthorized as e:
        logger.warning("Invalid token: %s", str(e), extra={"function_name":function_name})
        return None, None, None
    except Exception as e:
        # Handle other unexpected errors
        return None, None, None
    
def auth_token_info(token, function_name):
    try:
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token)
        sess = session.Session(auth=auth)
        access_info = sess.auth.get_access(sess)
        project_id = access_info.project_id
        user_id = access_info.user_id
        # 🔹 Get domain ID of the user
        user_domain_id = access_info.user_domain_id  # <- This is your answer for domain ID

        # 🔹 Get roles assigned in this token scope
        roles = access_info.role_names  # List of role names (e.g., ['admin', 'member'])

        # Optional: Get domain scoped project info (if token is domain-scoped)
        project_domain_id = access_info.project_domain_id
        conn = os_connection.Connection(session=sess)
        # Step 4: Fetch human-readable names
        user = conn.identity.get_user(user_id)
        project = conn.identity.get_project(project_id)
        user_domain = conn.identity.get_domain(user_domain_id)
        project_domain = conn.identity.get_domain(project_domain_id)
        #conn = os_connection.Connection(session=sess)
        token_info = {"user_id": user_id,
                        "user_name": user.name,
                        "user_domain_id": user_domain_id,
                        "user_domain_name": user_domain.name,
                        "project_id": project_id,
                        "project_name": project.name,
                        "project_domain_id": project_domain_id,
                        "project_domain_name": project_domain.name,
                        "roles": roles,}
        return token_info
    except Unauthorized as e:
        logger.warning("Invalid token: %s", str(e), extra={"function_name":function_name})
        return None
    except Exception as e:
        logger.error(f"{str(e)}", extra = {"function_name": "token_info"})
        # Handle other unexpected errors
        return None
        
@swagger_auto_schema(
    method='post',
    tags=['Authentication & Token Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    request_body=SwitchProSerializer,
    responses={200: switchProResponseSerializer}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def switch_project(request):
    try:
        old_token = request.headers.get("X-Auth-Token")
        if not old_token:
            return JsonResponse({"error": "Missing X-Auth-Token header"}, status=401)

        # Parse project name from request body
        try:
            data = json.loads(request.body)
            target_project_name = data.get("project_name")
            if not target_project_name:
                return JsonResponse({"error": "Missing 'project_name'"}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)

        conn = request.keystone_conn
        user_info = request.keystone_user_info
        domain_id = user_info.get("domain_id", "default")  # safe fallback
        adm_conn = system_admin_auth() 
        # Find project under the user's domain
        target_project = next(
            (p for p in adm_conn.identity.projects() if p.name == target_project_name and p.domain_id == domain_id),
            None
        )
        if not target_project:
            return JsonResponse({"error": "Project not found or not accessible"}, status=404)

        # Issue project-scoped token using existing unscoped token
        try:
            auth = v3.Token(
                auth_url=KEYSTONE_URL,
                token=old_token,
                project_id=target_project.id
            )
            sess = session.Session(auth=auth)
            new_token = sess.get_token()

            return JsonResponse({
                "token": new_token,
                "project_id": target_project.id,
                "project_name": target_project.name
            })

        except Exception as e:
            logger.error(str(e), extra={"function_name": "switch_project_token"})
            return JsonResponse({"error": "Token switch failed", "details": str(e)}, status=500)

    except Exception as e:
        logger.error(str(e), extra={"function_name": "switch_project"})
        return JsonResponse({"error": "Unexpected error", "details": str(e)}, status=500)
    
@swagger_auto_schema(
    method='get',
    tags=['Authentication & Token Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: UserInfoResponseSerializer}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def token_info(request):
    email = request.keystone_user_info["name"]
    user = UserReachStack.objects.filter(email=email).first()
    org = user.organization
    subs = Subscription.objects.filter(organization = org).first()
    if subs:
        subscrition_taken = True
    else:
        subscrition_taken = False
    return JsonResponse({
        "user_id": request.keystone_user_id,
        "project_id": request.token_project_id,
        "username": request.keystone_user_info["name"],
        "domain_id": request.keystone_user_info["domain_id"],
        "subscription_taken":subscrition_taken
    })

def token_info_checked(request):
    try:
        token = request.headers.get("X-Auth-Token")
        if not token:
            return JsonResponse({"error": "Missing token"}, status=401)

        # Inspect the token using Keystone API directly
        headers = {
            "X-Auth-Token": token,
            "X-Subject-Token": token
        }
        url = f"{KEYSTONE_URL}/auth/tokens"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            return JsonResponse({"error": "Invalid token"}, status=401)

        token_data = resp.json().get("token", {})
        project = token_data.get("project", {})
        user = token_data.get("user", {})

        return JsonResponse({
            "user_id": user.get("id"),
            "username": user.get("name"),
            "project_id": project.get("id"),
            "project_name": project.get("name"),
            "domain_id": user.get("domain", {}).get("id"),
            "roles": token_data.get("roles", [])
        })
    except Exception as e:
        return JsonResponse({"error": "Failed to get token info", "details": str(e)}, status=500)
    
def token_info_old(request):
    try:       
        old_token = request.headers.get("X-Auth-Token")
        if not old_token:
            return JsonResponse({"detail": "Missing token ID"}, status=400)
        token_info = auth_token_info(old_token, "token_info")
        if token_info:
            return JsonResponse(token_info, status=200, safe=False)
        else:
            return JsonResponse({"error": "Failed to get token info"}, status=500)
    except Exception as e:
        return JsonResponse({"error": "Failed to get token info", "details": str(e)}, status=500)
    
@swagger_auto_schema(
    method='get', 
    tags=['Log'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: "Log info JSON"}
) 
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def logfile_content(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id     
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role           
        logfile_content = ["No Log configured yet"]
        log_file_path = "/opt/cloud/log/cloud_custom.log"

        if os.path.exists(log_file_path):
            with open(log_file_path, "r") as file:
                logfile_content = file.readlines()
        logfile_content.reverse()
        filtered_log = []
        if "admin" not in role: 
            for logline in logfile_content:
                if f"[user_id: {user_id}]" in logline:
                    filtered_log.append(logline)  
        else:
            for logline in logfile_content:
                if f"[org_id: {org.id}]" in logline:
                    filtered_log.append(logline) 
    except Exception as e:
        logger.error(str(e), 
                     extra = custom_log("log", user_info, org, {}) 
        )
    return JsonResponse({'log': filtered_log})