import stripe
import json
import logging
from django.conf import settings
from django.utils import timezone
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
stripe.api_key = settings.STRIPE_SECRET_KEY
logger = logging.getLogger('cloud')
from django.core.cache import cache
from datetime import datetime
from api.models import SubscriptionInvoice, StripeInvoiceEventLog, Invoice, StripeEventLog
def get_context(request):
        conn = request.keystone_conn  
        user_info = request.keystone_user_info
        org = request.org
        project_id = request.token_project_id 
        role = request.role
        return conn, user_info, org, project_id, role

def charge_customer(org, user_id, amount, invoice_id, subscription_id ):
    stripe.api_key = settings.STRIPE_SECRET_KEY   

    payment_intent = stripe.PaymentIntent.create(
        amount=int(amount * 100),
        currency="usd",
        customer=org.stripe_customer_id,
        payment_method=org.stripe_payment_method_id,
        off_session=True,
        confirm=True,
        metadata={
            "invoice_id": str(invoice_id),
            "user_id": str(user_id),
            "payable_amount": str(amount),
            "subscription_id": subscription_id          
        }
    )
    return payment_intent

@csrf_exempt
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META.get("HTTP_STRIPE_SIGNATURE")
    event = None
    #print(f" webhook: {payload} | Signature: {sig_header}")
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        # Invalid payload
        print("stripe value error")
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        print("SignatureVerificationError")
        return HttpResponse(status=400)
    except Exception as e:
        print("exxx", str(e))
        return HttpResponse(status=400)

    event_type = event["type"]
    data_object = event["data"]["object"]

    if event_type == "payment_intent.succeeded":
        payment_intent = data_object
        charge_id = payment_intent.get("latest_charge")
        #print("charge_id", charge_id)

        if not charge_id:
            logger.warning("Charge id not found")
            return HttpResponse(status=400)

        charge = stripe.Charge.retrieve(charge_id)
        metadata = charge.get("metadata", {}) or payment_intent.get("metadata", {})
        #print("metadata", metadata)
        invoice_id = metadata.get("invoice_id")
        user_id = metadata.get("user_id")
        payable_amount = int(float(metadata.get("payable_amount", 0)) * 100 )

        net_received = charge["amount_captured"] - charge["amount_refunded"]
        #print("amount_captured", charge["amount_captured"])
        #print("amount_refunded", charge["amount_refunded"])
        #print("payable_amount", payable_amount)
        #print("net_received", net_received)
        #print("charge.status", charge.status)
        #print("charge.paid", charge.paid)
        # Validate transaction integrity
        if not charge.paid or charge.status != "succeeded" or net_received != payable_amount:
            logger.error(f"Payment validation failed for invoice {invoice_id}")
            return HttpResponse(status=400)

        paid_at = timezone.make_aware(datetime.utcfromtimestamp(charge["created"]))
        invoice = SubscriptionInvoice.objects.get(invoice_number=invoice_id)

        invoice.payment_intent_id = charge["payment_intent"]
        invoice.charge_id = charge_id
        invoice.transaction_id = charge["balance_transaction"]
        invoice.status = "paid"
        invoice.user_id = user_id
        invoice.paid_at = paid_at
        invoice.receipt_url = charge.get("receipt_url")
        invoice.save(update_fields=[
            "payment_intent_id", "charge_id", "transaction_id",
            "status", "user_id", "paid_at", "receipt_url"
        ])       

        StripeInvoiceEventLog.objects.create(event_id=event["id"], invoice=invoice)
        logger.info(f"✅ Payment successful for invoice {invoice_id} — Charge {charge_id}")
        return HttpResponse(status=200)

    elif event["type"] == "payment_intent.payment_failed":
        payment_intent = event["data"]["object"]
        metadata = payment_intent.get("metadata", {})
        print("failed_metadata", metadata)
        invoice_id = metadata.get("invoice_id")
        user_id = metadata.get("user_id")

        error = payment_intent.get("last_payment_error", {}) or {}
        message = error.get("message", "Payment failed for unknown reason")
        code = error.get("code", "")
        decline_code = error.get("decline_code", "")

        logger.error(
            f"Payment failed for invoice {invoice_id} | Reason: {message} "
            f"[code={code}, decline={decline_code}]"
        )

        # Mark invoice as failed
        sub_invoice = SubscriptionInvoice.objects.filter(invoice_number=invoice_id).first()
        if sub_invoice:
            sub_invoice.status = "failed"
            sub_invoice.error_message = message
            sub_invoice.save(update_fields=["status", "error_message"])

            subscription = sub_invoice.subscription
            subscription.status = "past_due"
            subscription.save(update_fields=["status"])
        

        return HttpResponse(status=200)
    # For unhandled events
    return HttpResponse(status=200)