import logging
import os
import json
import random
import smtplib
import jwt
import stripe

from django.http import HttpRequest, HttpResponse,  JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BasicAuthentication  # Optional fallback
from rest_framework import serializers
from django.views.decorators.csrf import csrf_exempt
from .serializers import AuthLoginSerializer, AuthLoginResponseSerializer, SwitchProSerializer, switchProResponseSerializer, UserInfoResponseSerializer, ProjectInfoResponseSerializer, CreateGroupSerializer, AddGroupSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django_ratelimit.decorators import ratelimit
from django.core.cache import cache
from django.conf import settings
from custom_log_info import custom_log_data, custom_log

#from django.db import connection
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
#from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
from .serializers_reachstack import RegisterSerializer
from api.models import OrganizationReachStack, UserReachStack, EmailVerificationToken, StripeEventLog, SubscriptionInvoice, Subscription
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from decouple import config
from datetime import datetime
from .auth_views import system_admin_auth
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

logger = logging.getLogger('cloud')

stripe.api_key = settings.STRIPE_SECRET_KEY
smtp_server = config('SMTP_SERVER')  # Your SMTP server address
smtp_port = config('SMTP_PORT')  # SMTP server port (587 for TLS, 465 for SSL)
sender_email = config('SENDER_MAIL_ID')  # Your email address
sender_password = config('SENDER_MAIL_PASSWORD')  # Your email password
subject = 'Alert ReachLink Spoke InActive '

auth_header = openapi.Parameter(
    name="Authorization",
    in_=openapi.IN_HEADER,
    description="Bearer token or PreAuth JWT (e.g., 'Bearer <token>')",
    type=openapi.TYPE_STRING,
    required=True,
)
class PreAuthJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = request.headers.get('Authorization')
        if not token:
            return None
        try:
            scheme, _, token_value = token.partition(' ')
            if scheme.lower() != 'bearer' or not token_value:
                raise AuthenticationFailed('Invalid token format')
            payload = jwt.decode(token_value, settings.SECRET_KEY, algorithms=['HS256'])

            if payload.get('type') != 'pre_auth':
                raise AuthenticationFailed('Invalid token type')

            user = UserReachStack.objects.get(id=payload['user_id'])
            return (user, None)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        
    
def post_mail(subject, message, recipient_list):   
    subject = subject
    body = f'{message}.'
    for receiver_email in recipient_list:
        #receiver_email = "bavya@cloudetel.com"  # Recipient's email address
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = receiver_email
        message['Subject'] = subject
        message.attach(MIMEText(body, 'plain'))    
        try:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()  # Use TLS encryption
            server.login(sender_email, sender_password)
            text = message.as_string()
            server.sendmail(sender_email, receiver_email, text)        
            print("Email sent successfully!")
            server.quit()  # Close the connection to the server
        except Exception as e:       
            print(f"An error occurred while sending Email: {str(e)}")
    
def send_verification_email(user):
    otp = str(random.randint(100000, 999999))  # 6 digit
    EmailVerificationToken.objects.filter(user=user, is_used=False).update(is_used=True)
    token = EmailVerificationToken.objects.create(
        user=user,
        otp_code=otp,
        expires_at=timezone.now() + timedelta(minutes=10)
    )
    post_mail(
        subject="Verify your email",
        message=f"Your verification code is {otp}",        
        recipient_list=[user.email],
    )   

def send_reset_password_email(user):
    otp = str(random.randint(100000, 999999))  # 6 digit
    EmailVerificationToken.objects.filter(user=user, is_used=False).update(is_used=True)

    token = EmailVerificationToken.objects.create(
        user=user,
        otp_code=otp,
        expires_at=timezone.now() + timedelta(minutes=10)
    )
    
    post_mail(
        subject="Reset your Password with ReachStack",
        message=f"Your verification code is {otp}",        
        recipient_list=[user.email],
    )     
@swagger_auto_schema(
    method='post',
    operation_summary="Check Email Exist",
    tags=['Register'],    
    request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,            
            properties={
                "email": openapi.Schema(type=openapi.TYPE_STRING),
                "username": openapi.Schema(type=openapi.TYPE_STRING)                  
            }
    ),
    responses= {200: openapi.Response("Success")}
)
@api_view(['POST'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def check_email_exist(request):
    data = json.loads(request.body)
    #if not data.get("email") or not data.get("username") :
    #    return JsonResponse({"error":"Fields Missied"}, status = 400)
    if data.get("email"):
        user = UserReachStack.objects.filter(email=data.get("email")).first()
        if user:
            if user.email_verified:
                return JsonResponse({"error": "email already exist", "verified_status": True})
            else:
                return JsonResponse({"message": "Already Register", "verified_status": False})
        else:
            return JsonResponse({"message": "email not exist"})
    elif data.get("username"):
        user = UserReachStack.objects.filter(email=data.get("username")).first()
        if user:
            if user.email_verified:
                return JsonResponse({"error": "Username already exist", "verified_status": True})
            else:
                return JsonResponse({"message": "Already Register", "verified_status": False})
        else:
            return JsonResponse({"message": "Username not exist"})
    else:
        return JsonResponse({"error":"Fields Missied"}, status = 400)

    
@swagger_auto_schema(
    method='post',
    operation_summary="Register User",
    tags=['Register'],    
    request_body=RegisterSerializer,
    responses={200: openapi.Response("Success")}
)
@api_view(['POST'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def register_view(request):
    data = json.loads(request.body)
    if not data.get("email") or not data.get("password") or \
        not data.get("username") :
        return JsonResponse({"error":"Fields Missed"}, status = 400)
    password_hash = make_password(data.get("password"))
    org = OrganizationReachStack.objects.create(
        organization_name  = f"{data.get('org_name')}_{data.get('username')}"
    )
    user_rs = UserReachStack.objects.create(
            email = data.get("email"),
            password = password_hash,
            username = data.get("username"),
            role="admin",
            organization = org
    )
        #Function to send verification code on email & how to handle    
    send_verification_email(user_rs)
    token = jwt.encode({"user_id": str(user_rs.id), "type": "pre_auth"}, settings.SECRET_KEY, algorithm="HS256")
    return JsonResponse({'message': "Registered Successfully", 
                                 "user_id":str(user_rs.id), "token":token})

@swagger_auto_schema(
    method='post',
    operation_summary="User Verify",
    tags=['Register'],    
    request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email"],
            properties={                
                "email": openapi.Schema(type=openapi.TYPE_STRING)                
            }
        ),
    responses={200: openapi.Response("Success")}
)
@api_view(['POST'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def user_verify(request):
    data = json.loads(request.body)
    if not data.get("email") :
        return JsonResponse({"error":"Email Missed"}, status = 400)
    user = UserReachStack.objects.filter(email=data.get('email')).first()
    if user:       
        send_reset_password_email(user)
        token = jwt.encode({"user_id": str(user.id), "type": "pre_auth"}, settings.SECRET_KEY, algorithm="HS256")
        return JsonResponse({'message': "OTP sent", 
                                 "user_id":str(user.id), "token":token})
    else:
        return JsonResponse({'error': "User not found"})


@swagger_auto_schema(
    method='post',
    operation_summary="Reset Password",
    tags=['Register'],   
    manual_parameters=[auth_header],   
    request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["otp", "new_password"],
            properties={                
                "otp": openapi.Schema(type=openapi.TYPE_STRING),
                "new_password": openapi.Schema(type=openapi.TYPE_STRING)               
            }
        ),
    responses={200: openapi.Response("Success")}
)
@api_view(['POST'])
@authentication_classes([PreAuthJWTAuthentication])
@permission_classes([IsAuthenticated])
def reset_password(request):
    data = json.loads(request.body)
    otp = data.get("otp")
    user = request.user 
    user_id = user.id
    try:
        token = EmailVerificationToken.objects.filter(
            user_id=user_id, otp_code=otp, is_used=False
        ).latest("created_at")
        print("reset_passord", token)
        if not token:
            return JsonResponse({"error": "Invalid ID"}, status=400)

        if token.expires_at < timezone.now():
            return JsonResponse({"error": "OTP expired"}, status=400)
        
        token.is_used = True
        token.save()
        password_hash = make_password(data.get("new_password"))
        user.password = password_hash
        user.save() 
        if user.keystone_id:
            conn = system_admin_auth()
            # Update the password in Keystone
            updated_user = conn.identity.update_user(user.keystone_id, password=data.get("new_password"))

        return JsonResponse({"message": f"Password reset successfully"})

    except Exception as e:
        print(e)
        return JsonResponse({"error": "Invalid code"}, status=400)

def create_stripe_customer(user):
    customer = stripe.Customer.create(
        email=user.email,
        name=f"{user.username}",
        metadata={"user_id": user.id}
    )
    org = user.organization
    org.stripe_customer_id = customer.id
    org.status = "verified"
    org.save()
    return customer
#Login View
@swagger_auto_schema(
    method='post',
    operation_summary="login",
    tags=['Register'],    
    request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["email", "password"],
            properties={                
                "email": openapi.Schema(type=openapi.TYPE_STRING),
                "password": openapi.Schema(type=openapi.TYPE_STRING) 
            }
        ),
    responses={200: openapi.Response("Success")}
)
@api_view(['POST'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def login(request):
    data = json.loads(request.body)
    print("login data", data)
    if not data.get("email") or not data.get("password"):
        return JsonResponse({"error":"Fields Missed"}, status = 400)
    #password_hash = make_password(data.get("password"))    
    user = UserReachStack.objects.filter(email=data.get('email')).first()
    if data.get('email') == "admin":
        if check_password(data.get('password'), user.password):
            token = jwt.encode({"user_id": str(user.id), "type": "pre_auth"}, settings.SECRET_KEY, algorithm="HS256")
            return JsonResponse({   "verified_status": True, "user_id":str(user.id), 
                                    "token":token, 
                                    "payment_method_saved":"True"                                            
            })
        else:
            return JsonResponse({'error': "Invalid Credentials"})  
    if user:
        if check_password(data.get('password'), user.password):
            if user.email_verified:
                org = user.organization
                token = jwt.encode({"user_id": str(user.id), "type": "pre_auth"}, settings.SECRET_KEY, algorithm="HS256")
                if not org.stripe_customer_id:
                    create_stripe_customer(user) # Later have to remove it
                if org.stripe_payment_method_id:
                    payment_method_saved = True
                    subs = Subscription.objects.filter(organization=org, status="active").first()
                    if subs:
                        subscrition_taken = True
                    else:
                        subscrition_taken = False
                    return JsonResponse({   "verified_status": True, "user_id":str(user.id), "token":token, 
                                            "payment_method_saved":payment_method_saved,
                                            "card_brand": org.card_brand,
                                            "card_last4":org.card_last4,
                                            "exp_month":org.exp_month,
                                            "exp_year": org.exp_year,
                                            "subscription_taken": subscrition_taken
                                         })
                else:
                    payment_method_saved = False
                
                #Next to check, payment method added, if added & Subscribed redirect to Dashboard
                return JsonResponse({"verified_status": True, "user_id":str(user.id), "token":token, "payment_method_saved":payment_method_saved })
            else:
                send_verification_email(user)
                token = jwt.encode({"user_id": str(user.id), "type": "pre_auth"}, settings.SECRET_KEY, algorithm="HS256")
                return JsonResponse({   "verified_status": False, 
                                        "token":token})         
        else:
            return JsonResponse({'error': "Invalid Credentials"})  
    else:
        return JsonResponse({'error': "Not Registered"}) 
    

@swagger_auto_schema(
    method='post',
    operation_summary="Verify Email",
    tags=['Register'],   
    manual_parameters=[auth_header],   
    request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["otp"],
            properties={                
                "otp": openapi.Schema(type=openapi.TYPE_STRING)               
            }
        ),
    responses={200: openapi.Response("Success")}
)
@api_view(['POST'])
@authentication_classes([PreAuthJWTAuthentication])
@permission_classes([IsAuthenticated])
def verify_email(request):
    data = json.loads(request.body)
    otp = data.get("otp")
    user = request.user 
    user_id = user.id
    try:
        token = EmailVerificationToken.objects.filter(
            user_id=user_id, otp_code=otp, is_used=False
        ).latest("created_at")
        if not token:
            return JsonResponse({"error": "Invalid ID"}, status=400)

        if token.expires_at < timezone.now():
            return JsonResponse({"error": "OTP expired"}, status=400)
        
        token.is_used = True
        token.save()

        user = token.user
        user.email_verified = True
        user.save() 
        create_stripe_customer(user)
        return JsonResponse({"success": "Email verified successfully"})

    except Exception as e:
        print(e)
        return JsonResponse({"error": "Invalid code"}, status=400)

#Create SetupIntent
@swagger_auto_schema(
    method='get',
    operation_summary="create_setup_intent",
    tags=['Register'],   
    manual_parameters=[auth_header],   
    responses={200: openapi.Response("client_secret")}
)
@api_view(['GET'])
@authentication_classes([PreAuthJWTAuthentication])
@permission_classes([IsAuthenticated])
def create_setup_intent(request):
    user = request.user
    stripe.api_key = settings.STRIPE_SECRET_KEY
    org = user.organization
    setup_intent = stripe.SetupIntent.create(
        customer=org.stripe_customer_id,
        payment_method_types=["card"]
    )
    return JsonResponse({"client_secret": setup_intent.client_secret})

#Save Payment Method
@swagger_auto_schema(
    method='post',
    operation_summary="save_payment_method",
    tags=['Register'],   
    manual_parameters=[auth_header],   
    request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=["payment_method_id"],
            properties={
                "payment_method_id": openapi.Schema(type=openapi.TYPE_STRING)                          
            }
        ),
    responses={200: openapi.Response("success")}
)
@api_view(['POST'])
@authentication_classes([PreAuthJWTAuthentication])
@permission_classes([IsAuthenticated])
def save_payment_method(request):
    user = request.user
    org = user.organization
    payment_method_id = request.data.get("payment_method_id")

    stripe.api_key = settings.STRIPE_SECRET_KEY

    # Attach method to customer
    stripe.PaymentMethod.attach(payment_method_id, customer=org.stripe_customer_id)

    # Set as default payment method
    stripe.Customer.modify(
        org.stripe_customer_id,
        invoice_settings={"default_payment_method": payment_method_id}
    )
    # Fetch metadata from Stripe to store locally
    pm = stripe.PaymentMethod.retrieve(payment_method_id)
    if pm.type == 'card':
        org.stripe_payment_method_id = pm.id
        org.card_brand = pm.card.brand
        org.card_last4 = pm.card.last4
        org.exp_month = pm.card.exp_month
        org.exp_year = pm.card.exp_year
        
    elif pm.type == 'upi':
        org.payment_method_type = 'upi'
        org.upi_id = pm.upi.vpa  # virtual payment address like "user@upi"

    elif pm.type == 'sepa_debit':
        org.payment_method_type = 'sepa_debit'
        org.card_last4 = pm.sepa_debit.last4
        org.bank_code = pm.sepa_debit.bank_code
        org.country = pm.sepa_debit.country

    # Add more types here as needed...
    org.status = "active"
    org.save()
    return JsonResponse({"message": "Payment method saved successfully"})


#Rough just for test
@swagger_auto_schema(
    method='get',
    operation_summary="logged_in_users",
    tags=['Register'],   
    responses={200: openapi.Response("Success")}
)
@api_view(['GET'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def logged_in_users(request): 
    users = UserReachStack.objects.all()    
    user_info = []
    for user in users:
        org = user.organization
        card_brand = None
        card_last4 = None
        exp_month = None
        exp_year = None
        stripe_customer_id =None
        stripe_payment_method_id = None
        if org:
            card_brand = org.card_brand
            card_last4 = org.card_last4
            exp_month = org.exp_month
            exp_year = org.exp_year
            stripe_customer_id = org.stripe_customer_id
            stripe_payment_method_id = org.stripe_payment_method_id
        user_info.append({"username":user.username,
                          "email": user.email,
                          "is_verified":user.email_verified,
                          "id":str(user.id),
                          "role":user.role,
                          "stripe_customer_id":stripe_customer_id,
                          "stripe_payment_method_id":stripe_payment_method_id,
                          "card_brand": card_brand,
                          "card_last4":card_last4,
                          "exp_month":exp_month,
                          "exp_year": exp_year,
                          "subscription_taken":[]})
    return JsonResponse(user_info, safe=False, status=200)  

@swagger_auto_schema(
    method='get',
    operation_summary="generated_otp",
    tags=['Register'],   
    responses={200: openapi.Response("Success")}
)
@api_view(['GET'])
@authentication_classes([])  # Disables authentication
@permission_classes([AllowAny])  # Allows all unauthenticated users
def get_token(request):    
    tokens = EmailVerificationToken.objects.all()    
    token_info = []
    for token in tokens:
        token_info.append({"username":token.user.username,
                          "email": token.user.email,                          
                          "otp_code":str(token.otp_code),
                          "created_at":str(token.created_at),
                          "expires_at":str(token.expires_at),
                          "is_used":token.is_used
                          })
    return JsonResponse(token_info, safe=False, status=200)  
 
    

    
   