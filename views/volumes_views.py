from rest_framework.views import APIView
from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from openstack import exceptions as os_exceptions
from django.http import StreamingHttpResponse, Http404
from django.views import View
from openstack import connection
import time
import yaml, base64
import datetime
import logging
import crypt
import random
import string
from .serializers import UpdateSecurityGroupSerializer
logger = logging.getLogger('cloud')
from custom_log_info import custom_log_data, custom_log
from api.models import (                       
                        FlavorPricing, 
                        SubscriptionInvoice,
                        Subscription,
                        Pricing,
                        Instances, 
                        UserReachStack  
                        )
from .tasks import wait_for_volume_deletion
from datetime import datetime, timedelta
from decimal import Decimal
from .payment_views import charge_customer
from django.utils import timezone
def get_context(request):
        conn = request.keystone_conn  
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        role = request.role
        return conn, user_info, org, project_id, role

def volume_subscription_create(volume_name, volume_size, org, project_id, user_info):
    try:
        period_start = timezone.now()  # time the server became ACTIVE
        period_end = period_start + timedelta(days=30)  # 1-month validity  
        subscription = Subscription.objects.create(                             
                organization = org, 
                resource_name = volume_name,
                resource_type="volume",                
                project_id=project_id,
                project_name=user_info.get("project_name"),                        
                status="active",
                volume_gb = volume_size,
                period_start=period_start,
                billed_upto = period_end,
                next_billing_date = period_end
        )
        
        logger.info(f"Subscription record for Volume {volume_name}",
                        extra=custom_log("create_volume", user_info, org, {}))                    
        hours_used = (period_end - period_start).total_seconds() / 3600
        hours_used = round(hours_used, 2)
        price = Pricing.objects.latest("created_at")
        amount = price.price_per_volume_gb_hr * Decimal(str(hours_used))
        invoice = SubscriptionInvoice.objects.create(
                subscription=subscription,
                amount=amount,
                start_period=period_start,
                end_period=period_end,
                status="unpaid",
        )
        invoice_number = f"INV-{timezone.now().year}-{invoice.id:04d}"
        invoice.invoice_number = invoice_number
        invoice.save(update_fields=["invoice_number"])
            
        logger.info(f"Invoice record created for volume {volume_name}",
                extra=custom_log("create_volume", user_info, org, {})
        )
        user = UserReachStack.objects.filter(email=user_info["name"]).first()
        if not user:
            logger.error(f"User not found with email {user_info['name']}")
            return None   # Or raise an exception intentionally
        payment_intent = charge_customer(org, user.id, invoice.amount, invoice_number, subscription.id )
        #print("PAYMENT_INTENT", payment_intent)
        time_sleep_iteration = 10
        while time_sleep_iteration > 0:
            invoice_after_payment = SubscriptionInvoice.objects.filter(invoice_number=invoice_number).first()
            if invoice_after_payment.status == "failed":
                logger.error(f"Payment Failed for volume {volume_name}",
                        extra=custom_log("create_volume", user_info, org, {})
                )
                return None             
            if invoice_after_payment.status == "paid":
                logger.info(f"Payment successfull for flavor {volume_name}",
                        extra=custom_log("create_volume", user_info, org, {})
                )
                return subscription.id
            time.sleep(10)
            time_sleep_iteration -= 1
    except Exception as e:
        print("volume subscription exception", e)
    return None
# -------------------------------
# List Volume
# -------------------------------
class VolumeListCreateView(APIView):
    @swagger_auto_schema(
        operation_summary="List all volumes",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        try: 
            volumes = []             
            for v in conn.block_storage.volumes(all_projects=False):
                v =  v.to_dict()                
                if v["project_id"] != project_id:
                    continue
                attached_info = []
                for attach in v["attachments"]:
                    try:
                        server = conn.compute.get_server(attach["server_id"])
                        attached_info.append(f"{attach['device']} on {server.name}")    
                    except:
                        attached_info.append(f"{attach['device']} ")                     
                volumes.append({"name": v["name"],
                                "status":v["status"],
                                "size":v["size"],
                                "attached":attached_info,
                                "bootable":v["is_bootable"],
                                "encrypted":v["is_encrypted"],
                                "description":v["description"],
                                "group_id":v['group_id'],
                                "availability_zone": v["availability_zone"],
                                "id":v["id"]
                                })            
            logger.info("Listed volumes", extra=custom_log("list_volumes", user_info, org, {}))
            return JsonResponse({"volumes": volumes}, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("list_volumes", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)

    @swagger_auto_schema(
        operation_summary="Create volumes",
        tags=['Volume Management'],
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
            required=["size", "name"],
            properties={
                "size": openapi.Schema(type=openapi.TYPE_STRING),
                "name": openapi.Schema(type=openapi.TYPE_STRING),
                "description": openapi.Schema(type=openapi.TYPE_STRING),
                "image":openapi.Schema(type=openapi.TYPE_STRING),         
            }
        ),
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        try:
            if "admin" not in role:            
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)  
            data = request.data
            image_name = data.get("image")
            #Initiate Payment
            subscription_id = volume_subscription_create(data.get('name'), int(data.get('size')), org, project_id, user_info)
            if subscription_id:
                #Update the quota
                volume_quotas = conn.block_storage.get_quota_set(project_id).to_dict()
                conn.block_storage.update_quota_set(
                    project_id,
                    gigabytes=volume_quotas["gigabytes"] + int(data.get('size')),
                    volumes=volume_quotas["volumes"] + 1                           
                )
                if not image_name:                 
                    volume = conn.block_storage.create_volume(
                        name=data.get('name'),
                        size=int(data.get('size')),  # GB
                        description=data.get('description', "")
                    )
                else:
                    image = conn.image.find_image(image_name)
                    volume = conn.block_storage.create_volume(
                        size=int(data.get('size')),
                        name=data['name'],
                        image_id=image.id,                    
                        description=data.get('description', "")                    
                    )
                Subscription.objects.filter(id=subscription_id).update(
                    resource_id=volume.id,
                    resource_name=volume.name
                )                 
                logger.info(f"Created volume {volume.id}", extra=custom_log("create_volume", user_info, org, {"volume_id": volume.id}))
                return JsonResponse({"message":f"Created volume {volume.name}"}, status=200)
            else:
                logger.error(f"Payment Failed for Volume", 
                            extra=custom_log("create_volume", user_info, org, {}))
                return JsonResponse({"error":f"Payment failed check Billing for error info"}, status=500)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("create_volume", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)

class VolumeListView(APIView):
    @swagger_auto_schema(
        operation_summary="Available bootable volumes",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        try: 
            volumes = []      
            for v in conn.block_storage.volumes():
                v =  v.to_dict() 
                if v["status"] == "available" and v["is_bootable"] == True:  
                    if "volume_image_metadata"in v:    
                        if v["volume_image_metadata"]["image_id"]:           
                            volumes.append({"name": v["name"],                             
                                "id":v["id"],
                                "image_name": v["volume_image_metadata"]["image_name"],
                                "min_disk":v["volume_image_metadata"]["min_disk"],
                                "min_ram": v["volume_image_metadata"]["min_ram"],
                                "min_cpu": v["volume_image_metadata"]["hw_vcpu_min"]
                                })            
            logger.info("Listed volumes", extra=custom_log("list_volumes", user_info, org, {}))
            return JsonResponse(volumes, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("list_volumes", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)

# -------------------------------
# Volume Detail
# -------------------------------
class VolumeDetailView(APIView):
    @swagger_auto_schema(
        operation_summary="Volume Detail",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request, volume_id):
        conn, user_info, org, project_id, role = get_context(request)
        try:            
            volume = conn.block_storage.get_volume(volume_id)
            logger.info(f"Fetched details for {volume_id}", extra=custom_log("volume_detail", user_info, org, {"volume_id": volume_id}))
            volume = volume.to_dict()
            attached_info = []
            for attach in volume["attachments"]:
                server = conn.compute.get_server(attach["server_id"])
                attached_info.append(f"{attach['device']} on {server.name}")  
            image_name = ""
            if "volume_image_metadata" in volume:
                if "image_name" in volume["volume_image_metadata"]:
                    image_name = volume["volume_image_metadata"]["image_name"]
            volumeinfo = {"name": volume["name"],
                          "id": volume["id"],
                          "project_id": volume["project_id"],
                          "status":volume["status"],
                          "group": volume["group_id"],
                          "specs":{
                                   "size":volume["size"],
                                   "type":volume["volume_type"],
                                   "bootable": volume["is_bootable"],
                                   "encrypted": volume["is_encrypted"],
                                   "created": volume["created_at"]
                                   },
                            "attachments":attached_info,
                            "image": image_name,
                            "metadata": volume["metadata"] }
            return JsonResponse(volumeinfo, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("volume_detail", user_info, org, {"volume_id": volume_id}))
            return JsonResponse({"error": str(e)}, status=500)

# -------------------------------
# Extend Volume
# -------------------------------
class VolumeExtendView(APIView):
    @swagger_auto_schema(
        operation_summary="Volume Extend",
        tags=['Volume Management'],
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
            required=["new_size"],
            properties={
                "new_size": openapi.Schema(type=openapi.TYPE_STRING)                            
            }
        ),
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request, volume_id):
        conn, user_info, org, project_id, role = get_context(request)
        if "admin" not in role:            
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)  
        data = request.data
        new_size = int(data.get("new_size"))      
        try:            
            conn.block_storage.extend_volume(volume_id, new_size)
            logger.info(f"Extended volume {volume_id} to {new_size} GB", extra=custom_log("extend_volume", user_info, org, {"volume_id": volume_id}))
            return JsonResponse({"message": "extending"}, status=202)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("extend_volume", user_info, org, {"volume_id": volume_id}))
            return JsonResponse({"error": str(e)}, status=500)

# -------------------------------
# Delete Volume
# -------------------------------
class VolumeDeleteView(APIView):
    @swagger_auto_schema(
        operation_summary="Volume Delete",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],
        responses={200: openapi.Response("Success")}
    )    
    def delete(self, request, volume_id):
        conn, user_info, org, project_id, role = get_context(request)

        if "admin" not in role:
            return JsonResponse({"error": "Permission denied. Admins only."}, status=403)

        try:
            volume = conn.block_storage.get_volume(volume_id)
            if not volume:
                return JsonResponse({"error": "Volume not found"}, status=404)

            volume_dict = volume.to_dict()
            status_ = volume_dict.get("status", "").lower()

            # Check if volume is in use
            if status_ == "in-use":
                logger.error(f"Volume is attached to an instance. Detach first.", extra=custom_log("delete_volume", user_info, org, {"volume_id": volume_id}))
                return JsonResponse({"error": "Volume is attached to an instance. Detach first."}, status=400)

            # Check for snapshots
            snapshots = list(conn.block_storage.snapshots(details=True, volume_id=volume_id))
            if snapshots:
                return JsonResponse({"error": f"Volume has {len(snapshots)} snapshots. Delete them first."}, status=400)
            
                
            # Allow deletion only if status is safe
            if status_ not in ["available", "error", "error_deleting", "reserved"]:
                return JsonResponse({"error": f"Volume is in '{status_}' state, cannot delete now."}, status=400)

            # Proceed with deletion
            conn.block_storage.delete_volume(volume_id, ignore_missing=True, force=(status_ != "available"))
            #Remove the Quota allocation
            volume_size = volume.size
            token = request.headers.get("X-Auth-Token")
            wait_for_volume_deletion.apply_async(args=[token, project_id, volume_id, volume_size, user_info, org.id, org.organization_name,], countdown=6)
            return JsonResponse({"message": "deleted"}, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("delete_volume", user_info, org, {"volume_id": volume_id}))
            return JsonResponse({"error": str(e)}, status=500)

# -------------------------------
# Attach Volume
# -------------------------------
class VolumeAttachView(APIView):
    @swagger_auto_schema(
        operation_summary="Volume Attach",
        tags=['Volume Management'],
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
            required=["server_id", "volume_id"],
            properties={
                "server_id": openapi.Schema(type=openapi.TYPE_STRING),
                "volume_id": openapi.Schema(type=openapi.TYPE_STRING),                
            }
        ),
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        data = request.data
        server_id = data.get("server_id")
        volume_id = data.get("volume_id")   
        if "admin" not in role:            
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)     
        try:            
            attachment = conn.compute.create_volume_attachment(
                server=server_id,
                volumeId=volume_id
            )
            attachment = attachment.to_dict()  
            server = conn.compute.get_server(server_id)
            Subscription.objects.filter(resource_id=volume_id).update(
                related_instance_id =server_id,
                related_instance_name =server.name
            )           
            logger.info(f"Attached volume {volume_id} to {server_id}", extra=custom_log("attach_volume", user_info, org, {"volume_id": volume_id, "server_id": server_id}))
            return JsonResponse({"message":f"Attached volume on to {attachment['device']}"}, status=202)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("attach_volume", user_info, org, {"volume_id": volume_id, "server_id": server_id}))
            return JsonResponse({"error": str(e)}, status=500)

# -------------------------------
# Detach Volume
# -------------------------------
class VolumeDetachView(APIView):
    @swagger_auto_schema(
        operation_summary="Volume Detach",
        tags=['Volume Management'],
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
            required=["server_id", "attachment_id"],
            properties={
                "server_id": openapi.Schema(type=openapi.TYPE_STRING),
                "attachment_id": openapi.Schema(type=openapi.TYPE_STRING),                
            }
        ),
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        data = request.data
        server_id = data.get("server_id")
        attachment_id = data.get("attachment_id")
        if "admin" not in role:            
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)
        try:             
            conn.compute.delete_volume_attachment(server_id, attachment_id, ignore_missing=True)
            #conn.block_storage.detach_volume(vol_id, attachment_id, force=True)
            Subscription.objects.filter(resource_type="volume", related_instance_id = server_id).update(
                related_instance_id =" ",
                related_instance_name =" "
            )  
            logger.info(f"Detached volume attachment {attachment_id} from {server_id}", extra=custom_log("detach_volume", user_info, org, {"attachment_id": attachment_id, "server_id": server_id}))
            return JsonResponse({"message": "detached"}, status=202)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("detach_volume", user_info, org, {"attachment_id": attachment_id, "server_id": server_id}))
            return JsonResponse({"error": str(e)}, status=500)

class ManageAtachmentView(APIView):  
    @swagger_auto_schema(
        operation_summary="Manage Attachment",
        tags=['Volume Management'],
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
            required=["volume_id"],
            properties={
                "volume_id": openapi.Schema(type=openapi.TYPE_STRING)                         
            }
        ),
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        data = request.data
        volume_id = data.get("volume_id")        
        if "admin" not in role:            
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)
        try: 
            volume = conn.block_storage.get_volume(volume_id)
            volume = volume.to_dict()
            attachments = []
            for attach in volume["attachments"]:
                try:
                    server = conn.compute.get_server(attach["server_id"])
                    server_name = server.name 
                except:
                    server_name = ""

                attachments.append({"server_name":server_name,
                                    "attachment_id":attach["attachment_id"],
                                    "volume_id":attach["volume_id"],
                                    "device":attach["device"],
                                    "server_id":attach["server_id"]
                                    })        
            logger.info(f"Manage volume attachment ", extra=custom_log("manage_attachments", user_info, org, {}))
            return JsonResponse(attachments, safe=False, status=202)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("manage_attachments", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)
        

class DetachVolumeView(APIView):  
    @swagger_auto_schema(
        operation_summary="Detach Volume from server - Volume section",
        tags=['Volume Management'],
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
            required=["server_id", "attachment_id"],
            properties={
                "volume_id": openapi.Schema(type=openapi.TYPE_STRING),               
                "attachment_id": openapi.Schema(type=openapi.TYPE_STRING),
                "server_id":openapi.Schema(type=openapi.TYPE_STRING)             
            }
        ),
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        data = request.data
        volume_id = data.get("volume_id")
        attachment_id = data.get("attachment_id")
        server_id = data.get("server_id")
        if "admin" not in role:            
                return JsonResponse({"error": "Permission denied. Admins only."}, status=403)
        try:  
            try:
                server = conn.compute.get_server(server_id)             
                if server:
                    volume_info = conn.block_storage.get_volume(volume_id) 
                    for vol in volume_info.attachments:                  
                        if vol['device'] == server.root_device_name:                        
                            logger.warning(f"Bootable Volume for server  {server.name}", extra=custom_log("detach_volume", user_info, org, {}))
                            return JsonResponse({"error": f"Detach prohibited for bootable volume"}, status=400)
            except:
                pass
            try:
                server = conn.compute.delete_volume_attachment(server_id, volume_id, ignore_missing=True)
            except:
                pass
            conn.block_storage.detach_volume(volume_id, attachment_id, force=True)
            logger.info(f"Detached volume attachment {attachment_id} from {volume_id}", extra=custom_log("detach_volume", user_info, org, {}))
            return JsonResponse({"message": "detached"}, status=202)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("detach_volume", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)
        
    

# -------------------------------
# List & Create Snapshots
# -------------------------------      
class SnapshotListCreateView(APIView):
    @swagger_auto_schema(
        operation_summary="List Snapshots",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],        
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request):
        conn, user_info, org, project_id, role = get_context(request)        
        snapshots = list(conn.block_storage.snapshots())
        snapshots_list = []
        for s in snapshots:
            volume = conn.block_storage.get_volume(s.volume_id)
            snapshots_list.append({"id": s.id,
                         "name":s.name,
                         "status": s.status,
                         "description":s.description,
                         "size":s.size,
                         "linked_volume":volume.name,
                         "group_snapshot_id": s.group_snapshot_id
                         })
            
        return JsonResponse(snapshots_list, safe=False, status=200)

    @swagger_auto_schema(
        operation_summary="Create Snapshot",
        tags=['Volume Management'],
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
            required=["volume_id", "attachment_id"],
            properties={
                "volume_id": openapi.Schema(type=openapi.TYPE_STRING),
                "name": openapi.Schema(type=openapi.TYPE_STRING),     
                "description": openapi.Schema(type=openapi.TYPE_STRING)   
            }
        ),      
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            snapshot = conn.block_storage.create_snapshot(
                volume_id=request.data.get("volume_id"),
                name=request.data.get("name"),
                description=request.data.get("description", "")
            )
            logger.info(f"Volume snapshot created", extra=custom_log("create_snapshot", user_info, org, {} ))
            return JsonResponse(snapshot.to_dict(), safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("create_snapshot", user_info, org, {} ))
            return JsonResponse({"error": str(e)}, status=500)

class VolumeSnapshotListView(APIView):
    @swagger_auto_schema(
        operation_summary="Available bootable snapshots",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        try: 
            snapshots = []      
            for snapshot in conn.block_storage.snapshots(): 
                #print(snapshot)               
                if snapshot.status == "available":
                    # Check the source volume
                    source_volume = conn.block_storage.get_volume(snapshot.volume_id)
                    v=source_volume.to_dict()
                    # Bootability depends on source volume
                    if v["is_bootable"] == True:                  
                        snapshots.append({"name": snapshot.name,                             
                                "id":snapshot.id ,
                                "min_disk":v["volume_image_metadata"]["min_disk"],
                                "min_ram": v["volume_image_metadata"]["min_ram"],
                                "min_cpu": v["volume_image_metadata"]["hw_vcpu_min"]                              
                                })            
            logger.info("Listed available bootable snapshots", extra=custom_log("list_volumes", user_info, org, {}))
            return JsonResponse(snapshots, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("list_volumes", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)
            
class DeleteVolumeSnapshotView(APIView):
    @swagger_auto_schema(
        operation_summary="Delete Snapshots",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],        
        responses={200: openapi.Response("Success")}
    )    
    def delete(self, request, snapshot_id):
        try:
            conn, user_info, org, project_id, role = get_context(request)

            snapshot = conn.block_storage.get_snapshot(snapshot_id)
            if not snapshot:
                return JsonResponse({"error": "Snapshot not found"}, status=404)

            # Optional: check status before deletion
            if snapshot.status not in ["available", "error"]:
                return JsonResponse({"error": f"Snapshot status '{snapshot.status}' cannot be deleted"}, status=400)

            conn.block_storage.delete_snapshot(snapshot, ignore_missing=True, force=True)
            logger.info(
                f"Deleted snapshot {snapshot_id}",
                extra=custom_log("delete_snapshot", user_info, org, {"snapshot_id": snapshot_id})
            )

            return JsonResponse({"message": f"Snapshot {snapshot_id} deleted"}, status=200)

        except Exception as e:
            logger.error(
                f"Failed to delete snapshot {snapshot_id}: {str(e)}",
                extra=custom_log("delete_snapshot", user_info, org, {"snapshot_id": snapshot_id})
            )
            return JsonResponse({"error": str(e)}, status=500)
# -------------------------------
# List & Create Group
# -------------------------------          
class GroupListCreateView(APIView):
    @swagger_auto_schema(
        operation_summary="List Group",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],   
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request):        
        conn, user_info, org, project_id, role = get_context(request) 
        group_info = []       
        groups = list(conn.block_storage.groups())
        for group in groups:
            group_info.append({"name": group.name,
                               "description":group.description,
                               "group_snapshot_id": group.group_snapshot_id,
                               "volumes":group.volumes,
                               "status":group.status,
                               "id":group.id
                               })

        return JsonResponse(group_info, safe=False, status=200)

    @swagger_auto_schema(
        operation_summary="Create Group",
        tags=['Volume Management'],
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
            required=["name"],
            properties={                
                "name": openapi.Schema(type=openapi.TYPE_STRING),     
                "description": openapi.Schema(type=openapi.TYPE_STRING)
                
            }
        ),      
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            group = conn.block_storage.create_group(
                name=request.data.get("name"),
                description=request.data.get("description", ""),
                group_type="test-group-type",  # <-- add this
                volume_types=["__DEFAULT__"],
                availability_zone="nova"
            )
            logger.info(f"Volume Group created", extra=custom_log("create_Volume Group", user_info, org, {} ))
            return JsonResponse(group.to_dict(), safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("create_Volume Group", user_info, org, {} ))
            return JsonResponse({"error": str(e)}, status=500)

class AddVolumeToGroup(APIView): 
    @swagger_auto_schema(
        operation_summary="Add Volume to Group",
        tags=['Volume Management'],
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
            required=["group_id", "volume_id"],
            properties={                
                "group_id": openapi.Schema(type=openapi.TYPE_STRING),     
                "volume_id": openapi.Schema(type=openapi.TYPE_STRING)
                
            }
        ),      
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            data = request.data
            volume_id = data.get("volume_id")
            #group = conn.block_storage.update_volume(volume_id,
            #   group_id=data.get("group_id")                
            #)
            group = conn.block_storage.update_group(
                data["group_id"],
                add_volumes=[data["volume_id"]]
            )
            #print(group)
            #volume = conn.block_storage.get_volume(volume_id)
            #print(volume)
            #group = conn.block_storage.get_group(group.id)
            #print(group)
            logger.info(f"Volume added to the group", extra=custom_log("Add_Volume Group", user_info, org, {} ))
            return JsonResponse({"message": "Volume added successfully to group"}, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("Add Volume to Group", user_info, org, {} ))
            return JsonResponse({"error": str(e)}, status=500)

class DeleteVolumeGroupView(APIView):
    @swagger_auto_schema(
        operation_summary="Delete Group",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],        
        responses={200: openapi.Response("Success")}
    )    
    def delete(self, request, group_id):
        try:
            conn, user_info, org, project_id, role = get_context(request)

            group = conn.block_storage.get_group(group_id)
            if not group:
                return JsonResponse({"error": "Volume group not found"}, status=404)
            
            if group.volumes:
                return JsonResponse({"error": "Volume is attached to Group. First remove volumes"}, status=404)

            # Optional: check status to prevent deleting groups in-progress
            if group.status not in ["available", "error"]:
                return JsonResponse({"error": f"Group status '{group.status}' cannot be deleted"}, status=400)

            conn.block_storage.delete_group(group)
            logger.info(
                f"Deleted volume group {group_id}",
                extra=custom_log("delete_volume_group", user_info, org, {"group_id": group_id})
            )

            return JsonResponse({"message": f"Volume group {group_id} deleted"}, status=200)

        except Exception as e:
            logger.error(
                f"Failed to delete volume group {group_id}: {str(e)}",
                extra=custom_log("delete_volume_group", user_info, org, {"group_id": group_id})
            )
            return JsonResponse({"error": str(e)}, status=500)
# -------------------------------
# List & Create Group Snapshots
# -------------------------------     
class GroupSnapshotListCreateView(APIView):
    @swagger_auto_schema(
        operation_summary="List Group Snapshot",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],   
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        g_snapshots = list(conn.block_storage.group_snapshots())
        return JsonResponse([gs.to_dict() for gs in g_snapshots], safe=False, status=200)

    @swagger_auto_schema(
        operation_summary="Create Group Snapshot",
        tags=['Volume Management'],
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
            required=["group_id", "name"],
            properties={                
                "name": openapi.Schema(type=openapi.TYPE_STRING),     
                "description": openapi.Schema(type=openapi.TYPE_STRING),
                "group_id": openapi.Schema(type=openapi.TYPE_STRING)                
            }
        ),      
        responses={200: openapi.Response("Success")}
    )    
    def post(self, request):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            g_snapshot = conn.block_storage.create_group_snapshot(
                group_id=request.data.get("group_id"),
                name=request.data.get("name"),
                description=request.data.get("description", "")
            )
            logger.info(f"Group snapshot created", extra=custom_log("create_Group_Snapshot", user_info, org, {} ))
            return JsonResponse(g_snapshot.to_dict(), safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("create_Group_Snapshot", user_info, org, {} ))
            return JsonResponse({"error": str(e)}, status=500)

# -------------------------------
# List Attached volumes with server
# -------------------------------     
class GetAttachedVolumeByServerid(APIView):
    @swagger_auto_schema(
        operation_summary="Attached volumes",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],   
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request, server_id):
        try:
            conn, user_info, org, project_id, role = get_context(request)
            server = conn.compute.get_server(server_id)            
            serverdict = server.to_dict()
            detachable_volumes = []            
            attached_volume = serverdict.get("attached_volumes", [])
            if len(attached_volume) <= 1:
                return JsonResponse([], safe=False, status=200)
            attached_volume = attached_volume[1:]
            for attachment in attached_volume:
                detachable_volumes.append(attachment["id"])
            return JsonResponse(detachable_volumes, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("get_attached_volumes", user_info, org, {} ))
            return JsonResponse({"error": str(e)}, status=500)
# -------------------------------
# List Available Volumes
# -------------------------------             
class VolumeListAvaialbleView(APIView):
    @swagger_auto_schema(
        operation_summary="List available volumes",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request):
        conn, user_info, org, project_id, role = get_context(request)
        try: 
            volumes = []      
            for v in conn.block_storage.volumes():
                if v.status == "available" and v.is_bootable == False:      
                    volumes.append({"id":v.id,
                                    "name":v.name})            
            logger.info("Listed volumes", extra=custom_log("list avaialble volumes", user_info, org, {}))
            return JsonResponse( volumes, safe=False, status=200)
        except Exception as e:
            logger.error(f"{str(e)}", extra=custom_log("list avaialble volumes", user_info, org, {}))
            return JsonResponse({"error": str(e)}, status=500)

class VolumeDownloadView1(APIView):
    @swagger_auto_schema(
        operation_summary="Download volume",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request, volume_id):
        conn, user_info, org, project_id, role = get_context(request)
        try:
            # Create a backup first (Cinder required)
            #backup = conn.block_storage.create_backup(
            #    volume_id=volume_id,
            #    name=f"backup-{volume_id}"
            #)
            #conn.block_storage.wait_for_status(backup, status="available", failures=["error"])

            # Download the backup
            data_stream = conn.block_storage.download_volume(volume_id, stream=True)
        except Exception as e:
            raise Http404(f"Volume not found or download failed: {e}")

        response = StreamingHttpResponse(
            data_stream,
            content_type="application/octet-stream"
        )
        response["Content-Disposition"] = f'attachment; filename="volume-{volume_id}.backup"'
        return response
    
class VolumeDownloadView(APIView):
    @swagger_auto_schema(
        operation_summary="Download volume",
        tags=['Volume Management'],
        manual_parameters=[
            openapi.Parameter(
                'X-Auth-Token',
                in_=openapi.IN_HEADER,
                description="Keystone Auth Token",
                type=openapi.TYPE_STRING,
                required=True
            )        
        ],
        responses={200: openapi.Response("Success")}
    )    
    def get(self, request, volume_id):
        conn, user_info, org, project_id, role = get_context(request)

        # Create a backup first (Cinder required)
        backup = conn.block_storage.create_backup(
                volume_id=volume_id,
                name=f"backup-{volume_id}"
        )
        conn.block_storage.wait_for_status(backup, status="available", failures=["error"])

        # Download the backup
        volume_data = conn.block_storage.download_backup(backup.id, stream=True)

        def file_iterator():
            for chunk in volume_data.iter_content(chunk_size=1024*1024):
                if chunk:
                    yield chunk

        response = StreamingHttpResponse(file_iterator(),
                                         content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{volume_id}.backup"'
        return response