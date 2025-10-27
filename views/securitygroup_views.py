from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication 
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
import logging
logger = logging.getLogger('cloud')
from custom_log_info import custom_log
from .serializers import CreateSecGroupSerializer, AddRuleSerializer, DeleteSGSerilaizer, DeleteRulesSerializer, DeleteRuleIDSSerializer
import json

@swagger_auto_schema(
    method='post',
    operation_id="create_security_group",
    tags=['Security Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],    
    request_body = CreateSecGroupSerializer,
    responses={200: "Json response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_security_group(request):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        data = json.loads(request.body)
        name = data.get("name")
        description = data.get("description", "")

        if not name:
            return JsonResponse({'error': 'Security group name is required'}, status=400)
        sec_groups = conn.network.security_groups(project_id=project_id)
        for sg in sec_groups:
            if sg.name == name:
                return JsonResponse({'error': f'Security group name({name}) already exists'}, status=400)

        secgroup = conn.network.create_security_group(
            name=name,
            description=description
        )

        logger.info(f"Security group created: {secgroup.id}",
                    extra=custom_log("create_security_group", user_info, org, data))
        return JsonResponse({'message': 'Security group created', 'id': secgroup.id}, status=201)

    except Exception as e:
        logger.error(str(e), extra=custom_log("create_security_group", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='post',
    operation_id="add_rule",
    tags=['Security Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],    
    request_body = AddRuleSerializer,
    responses={200: "Json Response"}
)    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_security_group_rule(request):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info
        org = request.org
        data = request.data
        secgroup_id = data.get("security_group_id")
        direction = data.get("direction")  # ingress/egress
        protocol = data.get("protocol")  # e.g., tcp/udp/icmp
        if not protocol:
            protocol = None
        port_min = data.get("port_range_min")
        port_max = data.get("port_range_max")
        remote_ip_prefix = data.get("remote_ip_prefix", "0.0.0.0/0")
        if not port_min:
            port_min = int(port_min)
        else:
            port_min = None
        if not port_max:
            port_max = int(port_max)
        else:
            port_max = None

        if not secgroup_id:
            return JsonResponse({'error': 'security_group_id and protocol are required'}, status=400)

        rule = conn.network.create_security_group_rule(
            security_group_id=secgroup_id,
            direction=direction,
            protocol=protocol,
            port_range_min=port_min,
            port_range_max=port_max,
            remote_ip_prefix=remote_ip_prefix,
            ethertype='IPv4'
        )

        logger.info(f"Rule added to security group: {rule.id}",
                    extra=custom_log("add_secgroup_rule", user_info, org, data))
        return JsonResponse({'message': 'Rule added', 'id': rule.id}, status=201)

    except Exception as e:
        logger.error(str(e), extra=custom_log("add_secgroup_rule", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='delete',
    operation_id="delete_rule",
    tags=['Security Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ], 
    responses={200: "Json response"}
)       
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_security_group_rule(request, rule_id):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info
        org = request.org

        rule = conn.network.find_security_group_rule(rule_id)
        if not rule:
            return JsonResponse({'error': 'Rule not found'}, status=404)

        conn.network.delete_security_group_rule(rule)

        logger.info(f"Security group rule deleted: {rule.id}",
                    extra=custom_log("delete_secgroup_rule", user_info, org, {}))
        return JsonResponse({'message': 'Rule deleted'}, status=200)

    except Exception as e:
        logger.error(str(e), extra=custom_log("delete_secgroup_rule", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='delete',
    operation_id="delete_multiple_rule",
    tags=['Security Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ], 
    request_body = DeleteRuleIDSSerializer,
    responses={200: "Json response"}
)       
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_security_group_multiple_rule(request):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info
        org = request.org
        rule_ids = request.data.get("rule_ids")
        for rule_id in rule_ids:
            rule = conn.network.find_security_group_rule(rule_id)
            if not rule:
                return JsonResponse({'error': 'Rule not found'}, status=404)

            conn.network.delete_security_group_rule(rule)

            logger.info(f"Security group rule deleted: {rule.id}",
                    extra=custom_log("delete_secgroup_rule", user_info, org, {}))
        return JsonResponse({'message': 'Selected Rules deleted'}, status=200)

    except Exception as e:
        logger.error(str(e), extra=custom_log("delete_secgroup_rule_multiple", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)
    
@swagger_auto_schema(
    method='post',
    operation_id="delete_multiple_rule",
    tags=['Security Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ], 
    request_body = DeleteRulesSerializer,
    responses={200: "Json response"}
)       
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_multiple_rule(request, rule_id):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info
        org = request.org
        data = request.data
        for rule_id in data.get('rule_ids'):
            rule = conn.network.find_security_group_rule(rule_id)
            if not rule:
                return JsonResponse({'error': 'Rule not found'}, status=404)

            conn.network.delete_security_group_rule(rule)

            logger.info(f"Security group rule deleted: {rule.id}",
                    extra=custom_log("delete_secgroup_rule", user_info, org, {}))
        return JsonResponse({'message': 'Rule deleted'}, status=200)

    except Exception as e:
        logger.error(str(e), extra=custom_log("delete_secgroup_rule", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)


@swagger_auto_schema(
    method='get',
    operation_id="get_security_group",
    tags=['Security Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ], 
    responses={200: "Security Groups in List"}
)          
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_security_groups(request):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        sec_groups = conn.network.security_groups(project_id=project_id)
        result = []
        for sg in sec_groups:
            result.append({
                'id': sg.id,
                'name': sg.name,
                'description': sg.description,
                'project_id': sg.project_id
            })

        return JsonResponse({'security_groups': result}, status=200)

    except Exception as e:
        logger.error(str(e), extra=custom_log("List_secgroups", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='get',
    operation_id="Get_Rule_from_securityGroup",
    tags=['Security Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ], 
    responses={200: "Rules in Security Group"}
)        
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_security_group_rules(request, secgroup_id):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        sg = conn.network.get_security_group(secgroup_id)
        if not sg:
            return JsonResponse({'error': 'Security group not found'}, status=404)

        rules = []
        for rule in sg.security_group_rules:
            port_min = rule.get('port_range_min')
            if not rule.get('port_range_min'):
                port_min = "Any"
            port_max = rule.get('port_range_max')
            if not rule.get('port_range_max'):
                port_max = "Any"
            proto = rule['protocol']
            if not rule['protocol']:
                proto = "Any"
            rules.append({
                'id': rule['id'],
                'direction': rule['direction'],
                'protocol': proto,
                'port_range_min': port_min,
                'port_range_max': port_max,
                'remote_ip_prefix': rule.get('remote_ip_prefix'),
                'ethertype': rule.get('ethertype')
            })

        return JsonResponse({'rules': rules}, status=200)

    except Exception as e:
        logger.error(str(e), extra=custom_log("List_secgroup_rules", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='post',
    operation_id="Delete_securityGroup",
    tags=['Security Group Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ], 
    request_body = DeleteSGSerilaizer,
    responses={200: "Rules in Security Group"}
)      
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_multiple_security_groups(request):
    try:
        conn = request.keystone_conn
        data = request.data
        ids = data.get("security_group_ids", [])
        user_info = request.keystone_user_info
        org = request.org

        if not ids:
            return JsonResponse({'error': 'No security group IDs provided'}, status=400)

        for sg_id in ids:
            sg = conn.network.find_security_group(sg_id)
            if sg:
                conn.network.delete_security_group(sg)
                logger.info(f'Security group({sg.name}) deleted successfully', extra=custom_log("delete_secgroup_rule", user_info, org, {}))
        return JsonResponse({'message': 'Security groups deleted successfully'}, status=200)

    except Exception as e:
        logger.error(str(e), extra=custom_log("delete_secgroup_rule", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)