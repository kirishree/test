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
from custom_log_info import custom_log_data, custom_log
from .serializers import CreateRouterSerializer, AddInterfaceSerializer, SetGatewaySerializer, DeleteRouterSerializer, DeleteInterfacesSerializer
import json
from .decorators import custom_schema
@swagger_auto_schema(
    method='get',
    operation_id="get_external_network",
    tags=['Router Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],    
    responses={200: "External network name in List"}
)
@api_view(['get'])
@permission_classes([IsAuthenticated])
def get_external_network(request): 
    try:
        conn = request.keystone_conn        
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role   
        public_networks = []
        networks = conn.network.networks()         
        for net in networks: 
            if net.is_router_external:
                public_networks.append({"name":net.name,
                                        "id":net.id})
    except Exception as e:
        logger.error(f"{str(e)}",
                     extra=custom_log("get_external_network", user_info, org, {}))
    return JsonResponse(public_networks, safe=False, status=200)
################
@swagger_auto_schema(
    method='get',
    operation_id="get_internal_subnet",
    tags=['Router Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],    
    responses={200: "Internal Network List"}
)
@api_view(['get'])
@permission_classes([IsAuthenticated])
def get_internal_subnet(request): 
    try:
        conn = request.keystone_conn        
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role           
        project_id = request.token_project_id      
        unassigned_subnets_name = []  
        #print("Internal subnet")
        # Get all subnets
        all_subnets = list(conn.network.subnets(project_id=project_id)) 
        shared_subnet = conn.network.find_subnet(f"shared_subnet_{org.organization_name}") 
        if shared_subnet:
            all_subnets.append(shared_subnet)      
        # Get all ports with device_owner as router interface
        router_ports = conn.network.ports(device_owner='network:router_interface')

        # Collect all subnet_ids attached to routers
        assigned_subnet_ids = set()
        for port in router_ports:
            for ip in port.fixed_ips:
                assigned_subnet_ids.add(ip['subnet_id'])

        # Filter subnets that are NOT assigned
        unassigned_subnets = [subnet for subnet in all_subnets if subnet.id not in assigned_subnet_ids]             
        for ubsubnet in unassigned_subnets:
            unassigned_subnets_name.append(f"{ubsubnet.name}")
    except Exception as e:
        logger.error(f"{str(e)}",
                     extra=custom_log("get_internal_subnet", user_info, org, {}))    
    return JsonResponse(unassigned_subnets_name, safe=False, status=200)  

@swagger_auto_schema(
    method='post',
    operation_id="create_router",
    tags=['Router Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],
    request_body = CreateRouterSerializer,
    responses={200: "Json Response"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_router(request): 
    try:
        conn = request.keystone_conn        
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role     

        if "admin" not in role:
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403) 

        data = json.loads(request.body)
        router_name = data.get("router_name")
        external_net_name = data.get("external_network")
        internal_subnet_name = data.get("internal_subnet")

        if not (router_name):
            return JsonResponse({"error": "Missing required fields."}, status=400)

        router = conn.network.find_router(router_name)
        if router:
            return JsonResponse({"message": f"Router '{router_name}' already exists."})

        # Step 1: Create Router
        router = conn.network.create_router(name=router_name, admin_state_up=True)
        # Step 2: Set External Gateway
        if external_net_name:           
            external_net = conn.network.find_network(external_net_name)
            if not external_net:
                return JsonResponse({"error": f"External network '{external_net_name}' not found."}, status=404)
            conn.network.update_router(
                router,
                external_gateway_info={"network_id": external_net.id,
                                   "enable_snat": data.get('enable_snat', True)}
            )
        # Step 3: Attach Internal Subnet
        if internal_subnet_name:
            subnet = conn.network.find_subnet(internal_subnet_name)
            if not subnet:
                return JsonResponse({"error": f"Internal subnet '{internal_subnet_name}' not found."}, status=404)

            conn.network.add_interface_to_router(router, subnet_id=subnet.id)
            logger.info(f"Router {router.name} configured successfully.",
                    extra=custom_log("create_router", user_info, org, {})
            )
        return JsonResponse({"message": "Router created successfully"}, status=200)
    except Exception as e:
        logger.error(f"{str(e)}",
                     extra=custom_log("create_router", user_info, org, {}))
        return JsonResponse({"error": str(e)}, status=500)
    
@swagger_auto_schema(
    method='get',
    tags=['Router Management'],
    operation_id="get_router_list",
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],    
    responses={200: "Router List"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_router(request): 
    try:        
        conn = request.keystone_conn
        project_id = request.token_project_id
        org = request.org         
        user_info = request.keystone_user_info       
        router_list = []
        project_routers = conn.network.routers(project_id = project_id)
        #project_routers = [router for router in routers if router.project_id == project_id]
        for r in project_routers:
            external_network = "-"
            if r.external_gateway_info:
                network = conn.network.get_network(r.external_gateway_info["network_id"])
                external_network = network.name
            router_list.append({
                'id': r.id,
                'name': r.name,
                'status': r.status,
                'admin_state_up': r.is_admin_state_up,
                'external_gateway_info': external_network,
                'availability_zones': r.availability_zones,                
            })
            
        return JsonResponse({'routers': router_list}, safe=False,  status=200)
    except Exception as e:        
        logger.error(f"{str(e)}",
                     extra=custom_log("get_router_list", user_info, org, {}))
        return JsonResponse(router_list, safe=False, status=500)

@swagger_auto_schema(
    method='get',
    tags=['Router Management'],
    operation_id="router_overview",
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )   
    ],    
    responses={200: "Router info "}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_router_overview(request, router_id): 
    try:        
        conn = request.keystone_conn
        project_id = request.token_project_id        
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role           
        router = conn.network.find_router(router_id)
        if not router:
            return JsonResponse({'error': 'Router not found'}, status=404)

        external_network = {}
        if router.external_gateway_info:
            network = conn.network.get_network(router.external_gateway_info["network_id"])
            external_network = {"network_name":network.name,
                                "network_id":network.id,
                                "external_fixed_ips":router.external_gateway_info["external_fixed_ips"],
                                "snat":router.external_gateway_info["enable_snat"]
                                }
        router_overview = {
                'id': router.id,
                'name': router.name,
                'status': router.status,
                'project_id': router.project_id,
                'admin_state_up': router.is_admin_state_up,
                'external_gateway_info': external_network,
                'availability_zones': router.availability_zones,
                'routes': router.routes,
            }
        return JsonResponse(router_overview, safe=False,  status=200)
    except Exception as e:        
        logger.error(f"{str(e)}",
                     extra=custom_log("get_router_overview", user_info, org, {}))
        return JsonResponse({}, status=500)

@swagger_auto_schema(
    method='get',
    operation_id="get_router_interface",
    tags=['Router Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )  
    ],    
    responses={200: "Router Interface info "}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_router_interfaces(request, router_id):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info        
        org = request.org         
        # Get router first (optional sanity check)
        router = conn.network.find_router(router_id)
        if not router:
            return JsonResponse({'error': 'Router not found'}, status=404)

        # Get router interface ports
        interfaces = conn.network.ports(device_id=router_id)

        interface_list = []
        for iface in interfaces:
            device_type = "Internal Interface"
            if iface.device_owner == "network:router_gateway":
                device_type = "External Gateway"
            iface_ip = []
            for fixedip in iface.fixed_ips:  # includes subnet_id & IP address
                iface_ip.append(fixedip["ip_address"])
            interface_list.append({
                'id': iface.id,               
                'fixed_ips': iface_ip,  
                'network_id': iface.network_id,
                'status': iface.status,
                'admin_state_up': iface.is_admin_state_up,
                'type': device_type
            })
        return JsonResponse({'interfaces': interface_list}, safe=False, status=200)
    except Exception as e:
        logger.error(f"{str(e)}",
                     extra=custom_log("get_router_interfaces", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='delete',
    tags=['Router Management'],
    operation_id="delete_interface",
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )          
    ],    
    responses={200: "Json Response "}
)   
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_router_interface(request, router_id, port_id):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info        
        org = request.org 
        router = conn.network.get_router(router_id)
        port = conn.network.find_port(port_id)
        if not port:
            return JsonResponse({'error': 'Port not found'}, status=404)

        if port.device_id != router_id or port.device_owner != 'network:router_interface':
            return JsonResponse({'error': 'Port is not a router interface for this router'}, status=400)

        # Proper way to remove router interface
        conn.network.remove_interface_from_router(router, port_id=port.id)
        logger.info(f"Router interface deleted successfully. Port {port.id}",
                     extra=custom_log("delete_router_interfaces", user_info, org, {})
        )
        return JsonResponse({'message': 'Router interface deleted successfully'}, status=200)

    except Exception as e:
        logger.error(f"{str(e)}",
                     extra=custom_log("delete_router_interfaces", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='post',
    tags=['Router Management'],
    operation_id="delete_multiple_interface",
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )          
    ],  
    request_body=DeleteInterfacesSerializer,  
    responses={200: "Json Response "}
)   
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_router_interfaces(request, router_id):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info        
        org = request.org 
        data = request.data
        port_ids = data.get("interface_ids")
        router = conn.network.get_router(router_id)
        for port_id in port_ids:
            port = conn.network.find_port(port_id)
            if not port:
                return JsonResponse({'error': 'Port not found'}, status=404)

            if port.device_id != router_id or port.device_owner != 'network:router_interface':
                return JsonResponse({'error': 'Port is not a router interface for this router'}, status=400)

            # Proper way to remove router interface
            conn.network.remove_interface_from_router(router, port_id=port.id)
            logger.info(f"Router interface deleted successfully. Port {port.id}",
                     extra=custom_log("delete_router_interfaces", user_info, org, {})
            )
        return JsonResponse({'message': 'Router interface deleted successfully'}, status=200)

    except Exception as e:
        logger.error(f"{str(e)}",
                     extra=custom_log("delete_router_interfaces", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)
    
@swagger_auto_schema(
    method='post',
    operation_id="add_interface",
    tags=['Router Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )          
    ],   
    request_body=AddInterfaceSerializer, 
    responses={200: "Json Response"}
)   
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_router_interface(request):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info        
        org = request.org 
        data = json.loads(request.body)
        router = conn.network.find_router(data.get("router_id"))
        if not router:
            return JsonResponse({'error': 'Router not found'}, status=404)
        
        subnet = conn.network.find_subnet(data.get("subnet_id"))
        if not subnet:
            return JsonResponse({'error': 'Subnet not found'}, status=404)

        conn.network.add_interface_to_router(router, subnet_id=subnet.id)        
        logger.info(f"Interface added successfully Router:{router.name}",
                     extra=custom_log("add_router_interfaces", user_info, org, {})
        )
        return JsonResponse({'message': 'Interface added successfully'}, status=200)

    except Exception as e:
        logger.error(f"{str(e)}",
                     extra=custom_log("add_router_interfaces", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)
    
@swagger_auto_schema(
    method='delete',
    operation_id="clear_router_gateway",
    tags=['Router Management'],
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
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_router_gateway(request, router_id):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role        
        if "admin" not in role:
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403) 
        router = conn.network.find_router(router_id)
        if not router:
            return JsonResponse({'error': 'Router not found'}, status=404)
        
        # Remove external gateway
        conn.network.update_router(router, external_gateway_info=None)
                
        logger.info(f"Gateway cleared for Router {router.name} successfully",
                     extra=custom_log("delete_router_gateway", user_info, org, {})
        )
        return JsonResponse({'message': 'Gateway removed successfully'}, status=200)

    except Exception as e:
        logger.error(f"{str(e)}",
                     extra=custom_log("delete_router_gateway", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='post',
    tags=['Router Management'],
    operation_id="set_router_gateway",
    operation_description="Set external gateway for a router using an external network",
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )          
    ],    
    request_body=SetGatewaySerializer,
    responses={200: "Json Response"}
)      
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def set_router_gateway(request, router_id):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info        
        org = request.org 

        network_id = request.data.get('network_id')
        enable_snat = request.data.get('enable_snat', True)

        if not network_id:
            return JsonResponse({'error': 'network_id is required'}, status=400)

        # Validate router and network
        router = conn.network.get_router(router_id)
        if not router:
            return JsonResponse({'error': 'Router not found'}, status=404)

        network = conn.network.find_network(network_id)
        if not network or not network.is_router_external:
            return JsonResponse({'error': 'Invalid external network'}, status=400)

        # Set gateway
        conn.network.update_router(
            router,
            external_gateway_info={
                "network_id": network.id,
                "enable_snat": enable_snat
            }
        )

        logger.info(f"Set external gateway for router {router_id} to network {network_id}",
                    extra=custom_log("set_router_gateway", user_info, org, {}))

        return JsonResponse({'message': 'Router gateway set successfully'}, status=200)

    except Exception as e:
        logger.error(f"{str(e)}", extra=custom_log("set_router_gateway", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)

@swagger_auto_schema(
    method='post',
    tags=['Router Management'],
    operation_id="delete_router",
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )          
    ],    
    request_body=DeleteRouterSerializer,
    responses={200: "Json Response"}
)        
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_router(request):
    try:
        conn = request.keystone_conn
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role        
        if "admin" not in role:
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403) 
        data = json.loads(request.body)        
        router_ids = data.get("router_ids")
        for routerid in router_ids:
            router = conn.network.find_router(routerid)
            if not router:
                return JsonResponse({'error': f'Router:{routerid} not found'}, status=404)

            # Step 1: Remove interfaces
            ports = list(conn.network.ports(device_id=router.id))
            for port in ports:
                if port.device_owner == 'network:router_interface':
                    conn.network.remove_interface_from_router(router, port_id=port.id)

            # Step 2: Remove external gateway (if any)
            if router.external_gateway_info:
                conn.network.update_router(router, external_gateway_info=None)

            # Step 3: Delete the router
            conn.network.delete_router(router)

        logger.info(f"Router {router_ids} deleted safely.",
                    extra=custom_log("delete_router", user_info, org, {}))

        return JsonResponse({'message': 'Router deleted successfully'}, status=200)
    except Exception as e:
        logger.error(f"{str(e)}", extra=custom_log("delete_router", user_info, org, {}))
        return JsonResponse({'error': str(e)}, status=500)