from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication  # Optional fallback
from rest_framework import serializers
from html import escape
from django.views.decorators.csrf import csrf_exempt
from .serializers import ImagesListSerializer, CreateImageSerializer, UpdateImageSerializer, DeleteImageSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
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
from django.http import StreamingHttpResponse, Http404
from django.views import View
from openstack import connection
#Cache
from django.core.cache import cache
controller_ip = config('CONTROLLER_IP')
ONBOARDING_API= config('ONBOARDING_API_URL')
KEYSTONE_URL = config('KEYSTONE_URL')
ADMIN_PASSWORD = config('KEYSTONE_ADMIN_PASSWORD')
DEFAULT_DOMAIN = "Default"
ORG_ADMIN_ROLE = "org-admin"
ORG_USER_ROLE = "org-user"
IMAGE_CACHE_TIME = int(config('IMAGE_CACHE_TIME'))
@swagger_auto_schema(
    method='get',
    tags=['Image Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: ImagesListSerializer}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def show_images(request):
    try:
        conn = request.keystone_conn        
        user_id = request.keystone_user_id       
        user_info = request.keystone_user_info 
        org = request.org 
        role = request.role
        images_new = []
        project_id = request.token_project_id   
        cache_key = f"images_{project_id}"
        image_details = cache.get(cache_key)
        #cache.delete(cache_key)
        if image_details:
            return JsonResponse(image_details, safe=False, status=200)
        admin_conn = admin_auth() 
        #images = admin_conn.image.images()  
        for image in admin_conn.image.images():     

            #image_info = admin_conn.image.get_image(image.id)
            #if "Wnidows-11-Desktop" in image.name:
            #    print(image.to_dict())
            images_new.append({
                    "image_name": image.name,
                    "image_id": image.id, 
                    "image_status": image.status,
                    "image_visibility": image.visibility,                    
                    "image_disk_format": image.disk_format,
                    'min_disk': image.min_disk, 
                    'min_ram': image.min_ram,
                    'min_cpu': image.properties.get("hw_vcpu_min"),
                    "os_type":image.os_type
                    })
        rspstatus = 200
    except Exception as e:
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("show_Images", user_info, org, {}) 
        ) 
    # Store in cache
    cache.set(cache_key, images_new, timeout=IMAGE_CACHE_TIME)    
    return JsonResponse(images_new, safe=False, status=rspstatus)


@swagger_auto_schema(
    method='get',
    tags=['Image Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        ),
        openapi.Parameter(
            'image_name',
            in_=openapi.IN_QUERY,
            description="Image Name",
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={200: "Images Info Response Json"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_imageinfo_byid(request):
    try:     
        user_info = request.keystone_user_info        
        org = request.org 
        role = request.role
        imageinfo = {}
        imagename = request.query_params.get('image_name')        
        admin_conn = admin_auth()        
        image_info = admin_conn.image.find_image(imagename)
        props = image_info.get('properties', {})        
        imageinfo = {
                    "image_name": image_info.name,
                    "image_id": image_info.id,
                    "image_status": image_info.status,
                    "image_visibility": image_info.visibility,
                    "image_size": image_info.size,
                    "image_disk_format": image_info.disk_format,
                    "min_ram": image_info.min_ram,
                    "min_disk": image_info.min_disk,
                    "hw_vcpu_min": props.get("hw_vcpu_min"),
                    "os_type": image_info.os_type,
                    "architecture": image_info.architecture,
                    "image_description": props.get("description"),
                    }
        rspstatus = 200
    except Exception as e:
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"{str(e)}", 
                    extra = custom_log("get_imageinfo_byid", user_info, org, {}) 
        )   
    return JsonResponse(imageinfo, safe=False, status=rspstatus)

def upload_image_data(conn, image_id, image_file_path):
    with open(image_file_path, 'rb') as image_data:
        conn.image.upload_image(image_id, data=image_data)
    print(f"[+] Uploaded image data for ID: {image_id}")

@swagger_auto_schema(
    method='post',
    tags=['Image Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        ),
        openapi.Parameter(
            'file',
            in_=openapi.IN_FORM,
            description="Image file",
            type=openapi.TYPE_FILE,
            required=True
        )
    ],
    request_body = CreateImageSerializer,
    consumes=["multipart/form-data"],
    responses={200: "Response JSON"}
)
@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser]) 
@permission_classes([IsAuthenticated])
def create_image(request):
    try:
        user_info = request.keystone_user_info        
        org = request.org 
        admin_conn = admin_auth()        
        data = request.data        
        image_name = data.get('image_name')
        image_format = data.get('image_format')        
        image_file = request.FILES.get("file")  # This is already a file-like object
        #Delete the Cache
        project_id = request.token_project_id
        cache_key = f"images_{project_id}"
        cache.delete(cache_key)
        if not image_name or not image_file:
            return JsonResponse({"error": "Missing image_name or file"}, status=400)
        
        # Check if image already exists
        existing_image = admin_conn.image.find_image(image_name)
        if existing_image:
            logger.error("Image with the name already exists",
                         extra=custom_log("Create_Images", user_info, org, {}))
            return JsonResponse({"error": "Image with the name already exists"}, status=400)

        # Reset pointer to start
        image_file.seek(0)
        min_ram = data.get('min_ram', 1024)
        min_disk = data.get('min_disk', 10)
        hw_vcpu_min = data.get('hw_vcpu_min', "2")
        min_ram = int(min_ram) 
        min_disk = int(min_disk) 
        
        # Upload the image directly
        image = admin_conn.image.upload_image(
            name=image_name,
            data=image_file,
            disk_format=image_format, 
            container_format="bare",
            visibility=data.get("image_visibility"),
            min_ram=min_ram,
            min_disk=min_disk,
            os_type=data.get("os_type"),             
            architecture=data.get("architecture"),   
            properties={"description": data.get('image_description'),
                        "hw_vcpu_min": str(hw_vcpu_min)
                        }
        )
        logger.info(f"Uploaded image with ID: {image.id}",
            extra=custom_log("Create_Images", user_info, org, {})
        )
        return JsonResponse({
            "message": "Image created and uploaded",
            "image_id": str(image.id),
            "image_status": image.status
        }, status=200)

    except Exception as e:
        #print(e)
        response = {"error": str(e)}   
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"Image creation failed {str(e)}", exc_info=True,
                     extra=custom_log("Create_Images", user_info, org, {})
        )
        return JsonResponse(response, safe=False, status=rspstatus)
    
@swagger_auto_schema(
    method='post',
    tags=['Image Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],
    request_body = UpdateImageSerializer,
    responses={200: "Response JSON"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_image(request):
    try:
        user_info = request.keystone_user_info        
        org = request.org 
        admin_conn = admin_auth() 
        data = json.loads(request.body)
        #Delete the Cache
        project_id = request.token_project_id
        cache_key = f"images_{project_id}"
        cache.delete(cache_key)
        image_id = data.get('image_id')
        image_name = data.get('image_name')
        min_ram = data.get('min_ram', 1024)
        min_disk = data.get('min_disk', 10)
        hw_vcpu_min = data.get('hw_vcpu_min', '2')        
        # Check if image already exists
        existing_image = admin_conn.image.find_image(image_id)
        if not existing_image:
            logger.error(f"Image with the name {image_id} not found",
                         extra=custom_log("Update_Image", user_info, org, {})
            )
            return JsonResponse({"error": f"Image with the name {image_id} not found"}, status=400)

        # Upload the image directly
        image = admin_conn.image.update_image(
            existing_image ,
            name=data.get('image_name'),            
            visibility=data.get("image_visibility"),
            min_ram=int(min_ram),
            min_disk=int(min_disk),
            os_type=data.get("os_type"),            
            architecture=data.get("architecture"),   
            properties={"description": data.get('image_description'),
                        "hw_vcpu_min": str(hw_vcpu_min)
                        }
        )
        logger.info(f"Updated the image: {image_name}",
            extra=custom_log("Update_Image", user_info, org, {})
        )
        return JsonResponse({
            "message": f"Updated the image: {image_name}",
            "image_id": str(image.id),
            "image_status": image.status
        }, status=200)

    except Exception as e:
        response = {"error": str(e)}   
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"Image updation failed: {str(e)}", exc_info=True,
                     extra=custom_log("Update_Image", user_info, org, {})
                     )
        return JsonResponse(response, safe=False, status=rspstatus)
    
@swagger_auto_schema(
    method='post',
    tags=['Image Management'],
    manual_parameters=[
        openapi.Parameter(
            'X-Auth-Token',
            in_=openapi.IN_HEADER,
            description="Keystone Auth Token",
            type=openapi.TYPE_STRING,
            required=True
        )        
    ],
    request_body = DeleteImageSerializer,
    responses={200: "Response JSON"}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_image(request):
    try:
        user_info = request.keystone_user_info        
        org = request.org 
        admin_conn = admin_auth() 
        data = json.loads(request.body)
        #Delete the Cache
        project_id = request.token_project_id
        cache_key = f"images_{project_id}"
        cache.delete(cache_key)

        delete_images = data.get('images')         
        for delimage in delete_images:
            image = admin_conn.image.find_image(delimage)
            if not image:
                response = {"error": f"Image '{delimage}' not found."}
                logger.error(f"Image '{delimage}' not found.",
                         extra = custom_log("Delete_image", user_info, org, {}) 
                )
                rspstatus = 400
                break
            admin_conn.image.delete_image(image.id)            
            logger.info(f"Image '{image.name}' deleted.", 
                        extra = custom_log("Delete_image", user_info, org, {}) 
            )
            rspstatus = 200
        if rspstatus == 200:
            response = {"message": f"Images:{delete_images} deleted successfully"}
    except Exception as e:
        response = {"error": str(e)}   
        if isinstance(e, (KeyError, ValueError)):
            rspstatus = 400  # Bad Request – typically for invalid input
        else:
            rspstatus = 500  # Internal Server Error – unexpected failure 
        logger.error(f"Image deletion failed: {str(e)}",
                     extra=custom_log("Delete_Image", user_info, org, {})
                     )
    return JsonResponse(response, safe=False, status=rspstatus)
      
class ImageDownloadView(APIView):
    @swagger_auto_schema(        
        operation_summary="Image Download",
        tags=['Image Management'],
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
    def get(self, request, image_id):
        user_info = request.keystone_user_info        
        org = request.org 
        conn = admin_auth() 

        # Stream data from glance
        image_data = conn.image.download_image(image_id, stream=True)

        def file_iterator():
            for chunk in image_data.iter_content(chunk_size=1024*1024):
                if chunk:
                    yield chunk

        response = StreamingHttpResponse(file_iterator(),
                                         content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{image_id}.qcow2"'
        return response