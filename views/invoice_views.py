from rest_framework.views import APIView
from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from openstack import exceptions as os_exceptions
from django.db import transaction
from django.utils import timezone
#import datetime
import calendar
import logging
logger = logging.getLogger('cloud')
from custom_log_info import custom_log_data, custom_log
from api.models import  Subscription, SubscriptionInvoice, FlavorPricing
import requests
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from django.core.cache import cache
HOUR_DIV = Decimal(3600)
GNOCCHI_BASE_URL = "http://controller:8041/v1"
from decouple import config
INVOICELINE_CACHE_TIME = int(config('INVOICELINE_CACHE_TIME'))
import stripe
from django.conf import settings
stripe.api_key = settings.STRIPE_SECRET_KEY
def get_context(request):
        conn = request.keystone_conn  
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        role = request.role
        return conn, user_info, org, project_id, role

def get_bandwidth(conn, token, from_time, to_time, nic_id, user_info, org):
    try:
        headers = {"X-Auth-Token": token}
        results = {}    
        consumed_bandwidth = 0  
        url = f"{GNOCCHI_BASE_URL}/resource/instance_network_interface/{nic_id}"
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        nic_detail = resp.json()        
        metrics = nic_detail.get("metrics", {})
        #print("nic", nic_detail)
        #print(metrics)
        for metric_name in [
                    "network.incoming.bytes",
                    "network.outgoing.bytes",                
                ]:
            metric_id = metrics.get(metric_name)
            #print("metric_id", metric_id)
            if metric_id:                   
                start = datetime.fromisoformat(str(from_time))               
                end = datetime.fromisoformat(str(to_time))
                params = {
                            "start": start.isoformat(),
                            "end": end.isoformat()
                        }      
                measures_url = f"{GNOCCHI_BASE_URL}/metric/{metric_id}/measures"
                m_resp = requests.get(measures_url, headers=headers, params=params)
                m_resp.raise_for_status()
                measures = m_resp.json()
                if measures:
                    cumulative_values = []
                    for i in range(1, len(measures)):
                        #t1, g1, v1 = measures[i-1]
                        t2, g2, v2 = measures[i]
                        if start > datetime.fromisoformat(t2.replace("Z", "+00:00")):
                            continue
                        if start <= datetime.fromisoformat(t2.replace("Z", "+00:00")) <= end:   
                            #delta_bytes = v2 - v1
                            #delta_time = g2   # usually 300s
                            #kbps = (delta_bytes / delta_time) / 1024                                   
                            cumulative_values.append(round(v2, 2))                            
                        else:
                            break 
                    #print("cumulative", cumulative_values)
                    actual_usage = cumulative_values[-1] - cumulative_values[0]
                    #print(actual_usage)
                    consumed_bandwidth += actual_usage                    
    except Exception as e:        
        logger.error(f"{str(e)}", 
                    extra = custom_log("Consumed_bandwidth", user_info, org, {})
            )
    consumed_bandwidth_gb = (consumed_bandwidth / 1024) / 1024
    return consumed_bandwidth_gb

class InvoiceView(APIView):
    @swagger_auto_schema(
        operation_summary="Invoice View - generated",
        tags=['Bill Management'],
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
        try:
            invoice = []
            conn, user_info, org, project_id, role = get_context(request)
            #print(type(org), org)
 
            #cache_key = f"invoice_{org.id}"
            #cache.delete(cache_key)
            #invoice_details = cache.get(cache_key)            
            #if invoice_details:
            #    return JsonResponse(invoice_details, safe=False, status=200)   
            for subsinfo in Subscription.objects.filter(organization=org): 
                flavor_id = subsinfo.flavor_id
                flavor_name = ""
                if flavor_id:
                    flavor_info = FlavorPricing.objects.filter(flavor_id=flavor_id).first()
                    if flavor_info:
                        flavor_name = flavor_info.name                    
                lines = SubscriptionInvoice.objects.filter(
                    subscription=subsinfo                
                )
                invoicelines = []
                for line in lines:
                    if line.status == "paid":
                        txn_id = line.transaction_id
                        if not txn_id:
                            charge = stripe.Charge.retrieve(line.charge_id).to_dict()
                            txn_id = charge['balance_transaction']
                            if txn_id:
                                line.transaction_id = txn_id
                                line.save(update_fields=["transaction_id"])
                        transaction_info = {"payment_intent_id":line.payment_intent_id,
                                        "charge_id":line.charge_id,
                                        "transaction_id":txn_id,
                                        "paid_at":line.paid_at,
                                        "receipt_url":line.receipt_url
                                        }
                    else:
                        transaction_info = {"error_message":line.error_message}
                    invoicelines.append({   "invoice_number": line.invoice_number,                                             
                                             "start_period": line.start_period,
                                             "end_period":line.end_period,
                                             "transaction_info":transaction_info,
                                             "amount": line.amount,
                                             "status": line.status,
                                             "error_messgae":line.error_message})
                if subsinfo.resource_type == "instance":
                    resource_name = subsinfo.resource_name                    
                else:
                    resource_name = subsinfo.related_instance_name                    
                invoice.append({
                                "subscription_id":str(subsinfo.id),
                                "org_name": subsinfo.organization.organization_name,                                
                                "project_name":subsinfo.project_name,                                           
                                "start_period": subsinfo.period_start,
                                "end_period":subsinfo.period_end,                                
                                "status":subsinfo.status,
                                "invoice_lines":invoicelines,
                                "resource_type": subsinfo.resource_type,
                                "resource_name": resource_name,
                                "volume_gb" : subsinfo.volume_gb,
                                "next_billing_date": subsinfo.next_billing_date,
                                "last_billed_at": subsinfo.billed_upto,
                                "flavor_name": flavor_name
                                }) 
            # Store in cache
            #cache.set(cache_key, invoice, timeout=INVOICELINE_CACHE_TIME)                 
            return JsonResponse(invoice, safe=False, status=200)  
        except Exception as e: 
            print(str(e))  
            logger.error(f"{str(e)}", 
                    extra = custom_log("Invoice", user_info, org, {})
            )         
            return JsonResponse({"error": str(e)}, status=500)
