# views.py
from django.http import JsonResponse
from django.views import View
from rest_framework.views import APIView
from openstack import connection
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from openstack import exceptions as os_exceptions
from datetime import datetime, timedelta
import logging
import statistics
logger = logging.getLogger('cloud')
from custom_log_info import custom_log_data, custom_log

import requests
def get_openstack_conn(token, project_id):
    """Reuse Keystone token & project scope from your login/session."""
    return connection.Connection(
        auth_url="http://controller:5000/v3",
        token=token,
        project_id=project_id,
        compute_api_version="2",
        identity_interface="public",
    )

def get_context(request):
        conn = request.keystone_conn  
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        role = request.role
        return conn, user_info, org, project_id, role

class CPUMetricsView(APIView):
    """
    Returns CPU utilization & network stats for a given instance.
    Example: /metrics/<instance_id>/
    """
    @swagger_auto_schema(
        operation_summary="CPU Info",
        tags=['Telemetry Management'],
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
            required=["instance_id", "from_date", "to_date"],
            properties={
                "instance_id": openapi.Schema(type=openapi.TYPE_STRING),
                "from_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Start datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
                "to_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="End datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
            }
        ),
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        #conn, user_info, org, project_id, role = get_context(request)
        try:
            conn, user_info, org, project_id, role = get_context(request)
            token = request.headers.get("X-Auth-Token")
            headers = {"X-Auth-Token": token}
            data = request.data
            instance_id = data.get("instance_id")
            # ✅ Parse input datetimes safely
            try:
                start = datetime.fromisoformat(data.get("from_date"))
                end = datetime.fromisoformat(data.get("to_date"))
            except Exception:
                return JsonResponse({"error": "Invalid date format. Use ISO8601 (YYYY-MM-DDTHH:MM:SS)"}, status=400)

            params = {
                "start": start.isoformat(),
                "end": end.isoformat()                
            }

            # Step 1: Get instance resource in Gnocchi
            url = f"http://controller:8041/v1/resource/instance/{instance_id}"
            resp = requests.get(url, headers=headers)
            resource = resp.json()

            # Step 2: Get metric ID for CPU
            cpu_metric_id = resource["metrics"]["cpu"]
            vcpu_metric = resource["metrics"].get("vcpus")

            # Step 3: Get vCPUs value (last point)
            vcpus = 1  # default fallback
            if vcpu_metric:
                url = f"http://controller:8041/v1/metric/{vcpu_metric}/measures"
                resp = requests.get(url, headers=headers, params=params)
                vcpu_measures = resp.json()
                if vcpu_measures:
                    # Each measure: [timestamp, granularity, value]
                    vcpus = vcpu_measures[-1][2]  

            # Step 4: Get measures for last 24 hours (granularity 5 min = 300s)
            url = f"http://controller:8041/v1/metric/{cpu_metric_id}/measures"
            #params = {"start": "-1d", "granularity": 300}
            resp = requests.get(url, headers=headers, params=params)
            measures = resp.json()   # [[timestamp, granularity, value], ...]

           
            usage = []
            usage_list = []
            for i in range(1, len(measures)):
                t1, g1, v1 = measures[i-1]
                t2, g2, v2 = measures[i]

                delta_cpu = v2 - v1   # nanoseconds
                delta_time = g2       # should be 300s from granularity
                cpu_percent = (delta_cpu / (delta_time * 1e9 * vcpus)) * 100
                if start > datetime.fromisoformat(t2.replace("Z", "+00:00")):
                    continue
                if start <= datetime.fromisoformat(t2.replace("Z", "+00:00")) <= end:
                    usage.append({
                        "timestamp": t2,
                        "cpu_percent": round(cpu_percent, 2),
                        "vcpus": vcpus
                    })
                    usage_list.append(round(cpu_percent, 2))
                else:
                    break

            return JsonResponse({
                "server_id": instance_id,
                "vcpus": vcpus,
                "cpu_usage_24h": usage,
                "max_cpu_usage":max(usage_list) if usage_list else 0,
                "min_cpu_usage": min(usage_list) if usage_list else 0,
                "avg_cpu_usage": statistics.mean(usage_list) if usage_list else 0
            }, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}",
                     extra=custom_log("CPU_Monitor", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)

class MemoryUsageView(APIView):
    @swagger_auto_schema(
        operation_summary="RAM Info",
        tags=['Telemetry Management'],
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
            required=["instance_id", "from_date", "to_date"],
            properties={
                "instance_id": openapi.Schema(type=openapi.TYPE_STRING),
                "from_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Start datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
                "to_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="End datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
            }
        ),
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        #conn, user_info, org, project_id, role = get_context(request)
        try:
            conn, user_info, org, project_id, role = get_context(request)
            token = request.headers.get("X-Auth-Token")
            data = request.data
            instance_id = data.get("instance_id")

            # ✅ Parse input datetimes safely
            try:
                start = datetime.fromisoformat(data.get("from_date"))
                end = datetime.fromisoformat(data.get("to_date"))
            except Exception:
                return JsonResponse({"error": "Invalid date format. Use ISO8601 (YYYY-MM-DDTHH:MM:SS)"}, status=400)

            params = {
                "start": start.isoformat(),
                "end": end.isoformat()
            }

            # Step 1: Get resource (instance) from Gnocchi
            resource_url = f"http://controller:8041/v1/resource/instance/{instance_id}"
            headers = {"X-Auth-Token": token}
            resource_resp = requests.get(resource_url, headers=headers)
            resource_resp.raise_for_status()
            resource = resource_resp.json()

            # Step 2: Extract flavor memory (static) and memory.usage metric ID
            flavor_memory = resource["metrics"].get("memory")  # in MB            
            memory_usage_metric = resource["metrics"].get("memory.usage")

            if not memory_usage_metric or not flavor_memory:
                return JsonResponse({"error": "Memory metrics not available"}, status=404)
            
            # Step 3: Get alloted Memory value (last point)
            memory_measures = 1  # default fallback
            memory_alloted = 1024
            if flavor_memory:
                url = f"http://controller:8041/v1/metric/{flavor_memory}/measures"
                resp = requests.get(url, headers=headers, params=params)
                memory_measures = resp.json()
                #print("##########", memory_measures)
                if memory_measures:
                    # Each measure: [timestamp, granularity, value]
                    memory_alloted = memory_measures [-1][2]  

            # Step 4: Query measures for last 24 hours
            
            measures_url = f"http://controller:8041/v1/metric/{memory_usage_metric}/measures"            
            
            measures_resp = requests.get(measures_url, headers=headers, params=params)
            measures_resp.raise_for_status()
            measures = measures_resp.json()  # [[timestamp, granularity, value], ...]

            if not measures:
                return JsonResponse({"server_id": instance_id, "memory_usage_percent": 0, "data_points": []})

            # Step 4: Calculate average memory usage % over last 24h
            #values = [m[2] for m in measures]  # memory.usage values in MB
            values = []
            memory_usage = []
            for t, g, m in measures:                  
                if start > datetime.fromisoformat(t.replace("Z", "+00:00")):
                    continue
                if start <= datetime.fromisoformat(t.replace("Z", "+00:00")) <= end:                       
                    memory_usage.append({
                        "timestamp": t,
                        "memory_usage": round(m, 2)                    
                    })
                    values.append(m)                    
                else:
                    break
            if len(values) > 0:
                avg_usage = sum(values) / len(values)
                usage_percent = (avg_usage / memory_alloted) * 100
            else:
                avg_usage = 0
                usage_percent = 0
            return JsonResponse({
                "server_id": instance_id,
                "memory_mb_alloted": memory_alloted,
                "avg_memory_usage_mb": round(avg_usage, 2),
                "memory_usage_percent": round(usage_percent, 2),
                "data_points": memory_usage,  # optional, for charting,
                "max_memory_usage_mb":max(values) if values else 0,
                "min_memory_usage_mb": min(values) if values else 0

            }, safe=False, status=200)

        except Exception as e:
            logger.error(f"{str(e)}",
                     extra=custom_log("memory_Monitor", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)
        
class InstanceNetworkBytesStatsView(APIView):
    """
    Get network stats (incoming/outgoing bytes & packets) for an instance.
    """

    GNOCCHI_BASE_URL = "http://controller:8041/v1"
    @swagger_auto_schema(
        operation_summary="Network Bytes Info",
        tags=['Telemetry Management'],
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
            required=["instance_id", "from_date", "to_date"],
            properties={
                "instance_id": openapi.Schema(type=openapi.TYPE_STRING),
                "from_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Start datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
                "to_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="End datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
            }
        ),
        responses={200: openapi.Response("Success")}
    ) 
    def post(self, request):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            token = request.headers.get("X-Auth-Token")
            headers = {"X-Auth-Token": token}
            data = request.data
            instance_id = data.get("instance_id")

            # ✅ Parse input datetimes safely
            try:
                start = datetime.fromisoformat(data.get("from_date"))
                end = datetime.fromisoformat(data.get("to_date"))
            except Exception:
                return JsonResponse({"error": "Invalid date format. Use ISO8601 (YYYY-MM-DDTHH:MM:SS)"}, status=400)

            params = {
                "start": start.isoformat(),
                "end": end.isoformat()
            }
            # 1. Get all NIC resources
            url = f"{self.GNOCCHI_BASE_URL}/resource/instance_network_interface"
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            nic_resources = resp.json()

            # 2. Find NIC(s) belonging to this instance
            instance_nics = [
                r for r in nic_resources
                if r.get("instance_id") == instance_id
            ]
            if not instance_nics:
                return JsonResponse({"error": "No NIC resources found"}, status=404)
            ports = list(conn.network.ports(device_id=instance_id))            
            network_info = []
            for nic in instance_nics:
                # 3. Get NIC details to extract metric IDs
                url = f"{self.GNOCCHI_BASE_URL}/resource/instance_network_interface/{nic['id']}"
                resp = requests.get(url, headers=headers)
                resp.raise_for_status()
                nic_detail = resp.json()
                tap_intfc_id = nic_detail.get('original_resource_id').split("tap")[1]
                metrics = nic_detail.get("metrics", {})
                network_name = ""
                if tap_intfc_id:
                    for port in ports:
                        if port.id.startswith(tap_intfc_id):                                            
                            network = conn.network.get_network(port.network_id)                            
                            network_name = network.name
                results = {}
                for metric_name in [
                    "network.incoming.bytes",
                    "network.outgoing.bytes",                
                ]:
                    metric_id = metrics.get(metric_name)
                    if metric_id:
                        measures_url = f"{self.GNOCCHI_BASE_URL}/metric/{metric_id}/measures"
                        m_resp = requests.get(measures_url, headers=headers, params=params)
                        m_resp.raise_for_status()
                        measures = m_resp.json()
                        if measures:
                            network_usage = []
                            usage_values = []
                            for i in range(1, len(measures)):
                                t1, g1, v1 = measures[i-1]
                                t2, g2, v2 = measures[i]
                                if start > datetime.fromisoformat(t2.replace("Z", "+00:00")):
                                    continue
                                if start <= datetime.fromisoformat(t2.replace("Z", "+00:00")) <= end:   
                                    delta_bytes = v2 - v1
                                    delta_time = g2   # usually 300s
                                    kbps = (delta_bytes / delta_time) / 1024

                                    network_usage.append({
                                        "timestamp": t2,
                                        "rate_KB/s": round(kbps, 2)
                                    })
                                    usage_values.append(round(kbps, 2))                            
                                else:
                                    break                           
                            results[metric_name] = {"values": network_usage,
                                                "max_network_speed":max(usage_values) if usage_values else 0,
                                                "min_network_speed": min(usage_values) if usage_values else 0,
                                                "avg_network_speed": statistics.mean(usage_values) if usage_values else 0
                                                
                                            }
                            
                        #else:
                        #    results[metric_name] = {"values": [],
                        #                        "max_network_speed": 0,
                        #                        "min_network_speed":  0,
                        #                        "avg_network_speed": 0                                                
                        #                    }
                    else:
                        results[metric_name] = None
                if results:
                    network_info.append({network_name:results})
            return JsonResponse({
                "instance_id": instance_id,
                "network_interface_id": nic["id"],
                "metrics": network_info
            }, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}",
                     extra=custom_log("Network_Bytes_Monitor", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)
        
class InstanceNetworkPackStatsView(APIView):
    """
    Get network stats (incoming/outgoing bytes & packets) for an instance.
    """

    GNOCCHI_BASE_URL = "http://controller:8041/v1"
    @swagger_auto_schema(
        operation_summary="Network Packets Info",
        tags=['Telemetry Management'],
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
            required=["instance_id", "from_date", "to_date"],
            properties={
                "instance_id": openapi.Schema(type=openapi.TYPE_STRING),
                "from_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Start datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
                "to_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="End datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
            }
        ),
        responses={200: openapi.Response("Success")}
    ) 
    def post(self, request):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            token = request.headers.get("X-Auth-Token")
            headers = {"X-Auth-Token": token}
            data = request.data
            instance_id = data.get("instance_id")

            # ✅ Parse input datetimes safely
            try:
                start = datetime.fromisoformat(data.get("from_date"))
                end = datetime.fromisoformat(data.get("to_date"))
            except Exception:
                return JsonResponse({"error": "Invalid date format. Use ISO8601 (YYYY-MM-DDTHH:MM:SS)"}, status=400)

            params = {
                "start": start.isoformat(),
                "end": end.isoformat()
            }
            # 1. Get all NIC resources
            url = f"{self.GNOCCHI_BASE_URL}/resource/instance_network_interface"
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            nic_resources = resp.json()

            # 2. Find NIC(s) belonging to this instance
            instance_nics = [
                r for r in nic_resources
                if r.get("instance_id") == instance_id
            ]
            if not instance_nics:
                return JsonResponse({"error": "No NIC resources found"}, status=404)
            ports = list(conn.network.ports(device_id=instance_id))            
            network_info = []
            for nic in instance_nics:
                # 3. Get NIC details to extract metric IDs
                url = f"{self.GNOCCHI_BASE_URL}/resource/instance_network_interface/{nic['id']}"
                resp = requests.get(url, headers=headers)
                resp.raise_for_status()
                nic_detail = resp.json()
                tap_intfc_id = nic_detail.get('original_resource_id').split("tap")[1]
                metrics = nic_detail.get("metrics", {})
                network_name = ""
                if tap_intfc_id:
                    for port in ports:
                        if port.id.startswith(tap_intfc_id):                                            
                            network = conn.network.get_network(port.network_id)                            
                            network_name = network.name
                results = {}
                for metric_name in [
                    "network.incoming.packets",
                    "network.outgoing.packets",           
                ]:
                    metric_id = metrics.get(metric_name)
                    if metric_id:
                        measures_url = f"{self.GNOCCHI_BASE_URL}/metric/{metric_id}/measures"
                        m_resp = requests.get(measures_url, headers=headers, params=params)
                        m_resp.raise_for_status()
                        measures = m_resp.json()
                        if measures:
                            network_usage = []
                            usage_values = []
                            for i in range(1, len(measures)):
                                t1, g1, v1 = measures[i-1]
                                t2, g2, v2 = measures[i]
                                if start > datetime.fromisoformat(t2.replace("Z", "+00:00")):
                                    continue
                                if start <= datetime.fromisoformat(t2.replace("Z", "+00:00")) <= end:   
                                    delta_bytes = v2 - v1
                                    delta_time = g2   # usually 300s
                                    pps = (delta_bytes / delta_time)

                                    network_usage.append({
                                        "timestamp": t2,
                                        "rate_pps": round(pps, 2)
                                    })
                                    usage_values.append(round(pps, 2))                            
                                else:
                                    break                           
                            results[metric_name] = {"values": network_usage,
                                                "max_network_speed":max(usage_values) if usage_values else 0,
                                                "min_network_speed": min(usage_values) if usage_values else 0,
                                                "avg_network_speed": statistics.mean(usage_values) if usage_values else 0
                                                
                                            }
                            
                        #else:
                        #    results[metric_name] = {"values": [],
                        #                        "max_network_speed": 0,
                        #                        "min_network_speed":  0,
                        #                        "avg_network_speed": 0                                                
                        #                    }
                    else:
                        results[metric_name] = None
                if results:
                    network_info.append({network_name:results})
            return JsonResponse({
                "instance_id": instance_id,
                "network_interface_id": nic["id"],
                "metrics": network_info
            }, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}",
                     extra=custom_log("Network_Bytes_Monitor", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)
                
class InstanceDiskBytesStatsView(APIView):
    """
    Get Insatnce Disk stats (read/write bytes & requests) for an instance.
    """

    GNOCCHI_BASE_URL = "http://controller:8041/v1"
    @swagger_auto_schema(
        operation_summary="Disk I/O Bytes Info",
        tags=['Telemetry Management'],
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
            required=["instance_id", "from_date", "to_date"],
            properties={
                "instance_id": openapi.Schema(type=openapi.TYPE_STRING),
                "from_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Start datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
                "to_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="End datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
            }
        ),
        responses={200: openapi.Response("Success")}
    ) 
    def post(self, request):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            token = request.headers.get("X-Auth-Token")
            headers = {"X-Auth-Token": token}
            data = request.data
            instance_id = data.get("instance_id")

            # ✅ Parse input datetimes safely
            try:
                start = datetime.fromisoformat(data.get("from_date"))
                end = datetime.fromisoformat(data.get("to_date"))
            except Exception:
                return JsonResponse({"error": "Invalid date format. Use ISO8601 (YYYY-MM-DDTHH:MM:SS)"}, status=400)

            params = {
                "start": start.isoformat(),
                "end": end.isoformat()
            }
            # 1. Get all NIC resources
            url = f"{self.GNOCCHI_BASE_URL}/resource/instance_disk"
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            disk_resources = resp.json()

            # 2. Find NIC(s) belonging to this instance
            instance_disk = [
                r for r in disk_resources
                if r.get("instance_id") == instance_id
            ]
            if not instance_disk:
                return JsonResponse({"error": "No NIC resources found"}, status=404)

            # For demo: pick first NIC (extend if multiple)
            disk = instance_disk[-1]

            # 3. Get NIC details to extract metric IDs
            url = f"{self.GNOCCHI_BASE_URL}/resource/instance_disk/{disk['id']}"
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            disk_detail = resp.json()

            metrics = disk_detail.get("metrics", {})

            results = {}
            for metric_name in [
                "disk.device.read.bytes",                
                "disk.device.write.bytes",                
            ]:
                metric_id = metrics.get(metric_name)
                if metric_id:
                    measures_url = f"{self.GNOCCHI_BASE_URL}/metric/{metric_id}/measures"
                    m_resp = requests.get(measures_url, headers=headers, params=params)
                    m_resp.raise_for_status()
                    measures = m_resp.json()                    
                    if measures:
                        # take latest value
                        current_rate = []
                        usage_values = []
                        for i in range(1, len(measures)):
                            t1, g1, r1 = measures[i-1]
                            t2, g2, r2 = measures[i] 
                            
                            if start > datetime.fromisoformat(t2.replace("Z", "+00:00")):                                
                                continue
                            if start <= datetime.fromisoformat(t2.replace("Z", "+00:00")) <= end:       
                                disk_rate = (r2 - r1) / g2
                                usage_values.append(round(disk_rate, 2) )
                                current_rate.append({
                                    "timestamp": t2,
                                    "rate": round(disk_rate, 2)                                
                                })                                
                            else:                               
                                break
                        results[metric_name] = {"values":current_rate,
                                                "min_rate":min(usage_values) if usage_values else 0,
                                                "max_rate":max(usage_values) if usage_values else 0,
                                                "avg_rate": statistics.mean(usage_values) if usage_values else 0,
                                                }
                    else:
                        results[metric_name] = {"values": [],
                                                "min_rate": 0,
                                                "max_rate": 0,
                                                "avg_rate": 0                                                
                                                }
                else:
                    results[metric_name] = None

            return JsonResponse({
                "instance_id": instance_id,
                "network_interface_id": disk["id"],
                "metrics": results
            }, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}",
                     extra=custom_log("Disk_Bytes_Monitor", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)
        
class InstanceDiskReqStatsView(APIView):
    """
    Get Insatnce Disk stats (read/write bytes & requests) for an instance.
    """

    GNOCCHI_BASE_URL = "http://controller:8041/v1"
    @swagger_auto_schema(
        operation_summary="Disk I/O Requests Info",
        tags=['Telemetry Management'],
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
            required=["instance_id", "from_date", "to_date"],
            properties={
                "instance_id": openapi.Schema(type=openapi.TYPE_STRING),
                "from_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Start datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
                "to_date": openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="End datetime (ISO8601: YYYY-MM-DDTHH:MM:SS)"
                ),
            }
        ),
        responses={200: openapi.Response("Success")}
    ) 
    def post(self, request):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            token = request.headers.get("X-Auth-Token")
            headers = {"X-Auth-Token": token}
            data = request.data
            instance_id = data.get("instance_id")

            # ✅ Parse input datetimes safely
            try:
                start = datetime.fromisoformat(data.get("from_date"))
                end = datetime.fromisoformat(data.get("to_date"))
            except Exception:
                return JsonResponse({"error": "Invalid date format. Use ISO8601 (YYYY-MM-DDTHH:MM:SS)"}, status=400)

            params = {
                "start": start.isoformat(),
                "end": end.isoformat()
            }
            # 1. Get all NIC resources
            url = f"{self.GNOCCHI_BASE_URL}/resource/instance_disk"
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            disk_resources = resp.json()

            # 2. Find NIC(s) belonging to this instance
            instance_disk = [
                r for r in disk_resources
                if r.get("instance_id") == instance_id
            ]
            if not instance_disk:
                return JsonResponse({"error": "No NIC resources found"}, status=404)

            # For demo: pick first NIC (extend if multiple)
            disk = instance_disk[-1]

            # 3. Get NIC details to extract metric IDs
            url = f"{self.GNOCCHI_BASE_URL}/resource/instance_disk/{disk['id']}"
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            disk_detail = resp.json()

            metrics = disk_detail.get("metrics", {})

            results = {}
            for metric_name in [                
                "disk.device.read.requests",                
                "disk.device.write.requests",
            ]:
                metric_id = metrics.get(metric_name)
                if metric_id:
                    measures_url = f"{self.GNOCCHI_BASE_URL}/metric/{metric_id}/measures"
                    m_resp = requests.get(measures_url, headers=headers, params=params)
                    m_resp.raise_for_status()
                    measures = m_resp.json()
                    if measures:
                        # take latest value
                        current_rate = []
                        usage_values = []
                        for i in range(1, len(measures)):
                            t1, g1, r1 = measures[i-1]
                            t2, g2, r2 = measures[i] 
                            if start > datetime.fromisoformat(t2.replace("Z", "+00:00")):
                                continue
                            if start <= datetime.fromisoformat(t2.replace("Z", "+00:00")) <= end:    

                                disk_rate = (r2 - r1) / g2
                                usage_values.append(round(disk_rate, 2) )
                                current_rate.append({
                                    "timestamp": t2,
                                    "rate": round(disk_rate, 2)                                
                                })
                            else:
                                break
                        results[metric_name] = {"values":current_rate,
                                                "min_rate":min(usage_values) if usage_values else 0,
                                                "max_rate":max(usage_values) if usage_values else 0,
                                                "avg_rate": statistics.mean(usage_values) if usage_values else 0
                                                }
                    else:
                        results[metric_name] = {"values": [],
                                                "min_rate": 0,
                                                "max_rate": 0,
                                                "avg_rate": 0
                                                }
                else:
                    results[metric_name] = None
            return JsonResponse({
                "instance_id": instance_id,
                "network_interface_id": disk["id"],
                "metrics": results
            }, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}",
                     extra=custom_log("Disk_Request_Monitor", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)