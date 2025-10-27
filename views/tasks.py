from celery import shared_task
from keystoneauth1 import session
from keystoneauth1.identity import v3
from rest_framework.exceptions import ValidationError
import crypt
import random
import string
import logging
import time
import yaml, base64
from datetime import timedelta
from openstack import connection
from django.conf import settings
from decouple import config
from django.core.cache import cache
import requests
import base64
from django.utils import timezone
from .payment_views import charge_customer
from decimal import Decimal
from api.models import (                       
                        FlavorPricing, 
                        OrganizationReachStack,
                        SubscriptionInvoice,
                        Subscription,
                        Pricing,
                        Instances, 
                        UserReachStack
                        )
from django.db.models import Q
KEYSTONE_URL = config('KEYSTONE_URL')
SECURITY_RULES_PER_INSTANCE = int(config('SECURITY_RULES_PER_INSTANCE'))
PORTS_PER_INSTANCE = int(config('PORTS_PER_INSTANCE'))
logger = logging.getLogger('cloud')
from custom_log_info import custom_log_data, custom_log_celery
GNOCCHI_BASE_URL = "http://controller:8041/v1"

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_cloud_init(default_username, password_plain, ssh_key):
    cloud_config = {
        "hostname": "reachstack",
        "preserve_hostname": False,
        "users": ["default"],
        "ssh_pwauth": False,
        "disable_root": False,
        "timezone": "Asia/Riyadh",
        "locale": "en_US.UTF-8",
        "manage_resolv_conf": True,
        "resolv_conf": {
            "nameservers": ["8.8.8.8", "1.1.1.1"],
            "searchdomains": [],
            "domain": "localdomain",
        },        
        # ✅ Run ethtool on all interfaces at boot
        "runcmd": [
            # loop through all interfaces except lo
            "for iface in $(ls /sys/class/net/ | grep -v lo); do "
            "ethtool -K $iface rx off tx off sg off gso off gro off || true; "
            "done"
        ]
    }
    
    if ssh_key:       
        cloud_config["ssh_authorized_keys"] = [ssh_key]      

    cloud_config["chpasswd"] = {
        "list": f"{default_username}:{password_plain}",
        "expire": False
    }

    yaml_str = "#cloud-config\n" + yaml.dump(cloud_config)
    return base64.b64encode(yaml_str.encode()).decode()


def generate_windows_user_data(username, password, timezone):
    """
    Generate a cloudbase-init compatible user_data for Windows.
    """

    ps_script = f"""<powershell>
# Set timezone
tzutil /s "{timezone}"

# Create user if not exists
if (-Not (Get-LocalUser -Name "{username}" -ErrorAction SilentlyContinue)) {{
    net user {username} "{password if password else username}" /add
    net localgroup Administrators {username} /add
}}

# Enable RDP
Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# === Disable offloads (checksum + LSO) like ethtool ===
Get-NetAdapter | ForEach-Object {{
    Disable-NetAdapterChecksumOffload -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
    Disable-NetAdapterLso -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
    Disable-NetAdapterRsc -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
}}
</powershell>
"""

    return base64.b64encode(ps_script.encode()).decode()


def generate_hash_password(password):
        # Create a secure random salt
        salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        # Generate SHA-512 hashed password
        return crypt.crypt(password, f"$6${salt}")

@shared_task(bind=True, max_retries=30, default_retry_delay=60)
def CreateNetworkBilling(self, token, user_info, orgid, orgname, server_id, server_name, project_id):  
    try:         

        headers = {"X-Auth-Token": token}
        # 1. Get all NIC resources
        url = f"{GNOCCHI_BASE_URL}/resource/instance_network_interface"
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        nic_resources = resp.json()  
        
        # 2. Find NIC(s) belonging to this instance
        instance_nics = [
                r for r in nic_resources
                if r.get("instance_id") == server_id
        ]  
        if len(instance_nics) == 0:
            logger.info(f"Network Bandwidth info is not yet Ready",
                    extra=custom_log_celery("create_Billing_Bandwidth", user_info, orgid, orgname, {}))            
            raise self.retry(exc=Exception("Bandwidth info not ready yet"))
        #Get Server info
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token, project_id=project_id)
        sess = session.Session(auth=auth)
        conn = connection.Connection(session=sess)       
        ports = list(conn.network.ports(device_id=server_id))           
        for nic in instance_nics:
                # 3. Get NIC details to extract metric IDs
                url = f"{GNOCCHI_BASE_URL}/resource/instance_network_interface/{nic['id']}"
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
                bandwidth_billing = Subscription.objects.filter(resource_id=nic['id'], resource_type="bandwidth",
                                                                 status="running", related_instance_id=server_id).first()
                if bandwidth_billing:
                    logger.info(f"billing for Bandwidth already exist {server_name}",
                                extra = custom_log_celery("Bandwidth_Billing_record", user_info, orgid, orgname, {}))
                else:
                    # Create billing record with new flavor
                    org = OrganizationReachStack.objects.get(id=orgid)
                    period_start = timezone.now()  # time the server became ACTIVE
                    period_end = period_start + timedelta(days=30)  # 1-month validity  
                    subscription = Subscription.objects.create(                             
                        organization = org,     
                        resource_type="bandwidth",
                        resource_id=nic['id'],
                        resource_name = network_name,                
                        related_instance_id=server_id,
                        related_instance_name=server_name,
                        project_id=project_id,
                        project_name=user_info.get("project_name"),                      
                        status="active",
                        period_start=period_start,                        
                        next_billing_date = period_end
                    )
                    
                    logger.info(f"Billing record created for Bandwidth of instance {server_name} ",
                        extra=custom_log_celery("Bandwidth_Billing_record", user_info, orgid, orgname, {}))  
        conn.close()            
    except Exception as e:
            logger.error(f"{str(e)}",
                     extra=custom_log_celery("Bandwidth_Billing_record", user_info, orgid, orgname, {}))
              
@shared_task(bind=True, max_retries=30, default_retry_delay=60)
def createserver_task(self, token, user_info, orgid, orgname, data, volume_id, project_id, subscription_id ):
    try:        
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token, project_id=project_id)
        sess = session.Session(auth=auth)
        conn = connection.Connection(session=sess)          
        volume = conn.block_storage.get_volume(volume_id)             
        if volume.status == "available":
            # Launch instance from volume            
            password = "reachstack"
            os_type = volume.volume_image_metadata['os_type']
            default_username = volume.volume_image_metadata.get('os_default_user', 'reachstack')
            print("default_username", default_username)
            if "windows" not in os_type.lower():                            
                key_name = data.get("key_name")
                print("key_name", key_name)
                ssh_key = None
                if key_name:
                    try:
                        keypair = conn.compute.find_keypair(key_name)
                        if keypair:
                            ssh_key = keypair.public_key 
                    except Exception as e:
                        logger.info(f"Key pair not found - {keypair} ",
                        extra=custom_log_celery("create_instance", user_info, orgid, orgname, {}))                
                userdata = generate_cloud_init(default_username, password, ssh_key)             
            else:
                userdata = generate_windows_user_data("windows", password, "Arab Standard Time")
            sec_group = data.get('security_group', 'default')
            if sec_group == "":
                sec_group = 'default'
            sec_gr = [{"name": sec_group}]
            server = conn.compute.create_server(
                name=data['name'],
                flavor_id=data['flavor_id'], 
                #image_id = data['image_id'],               
                block_device_mapping_v2=[{
                    "source_type": "volume",              # <— from image
                    "destination_type": "volume",        # <— to Cinder volume
                    "uuid": volume.id,                  # <— Volume id
                    "boot_index": 0,                   
                    "delete_on_termination": data.get('delete_on_termination')       # auto-delete with server
                }],
                networks=[{"uuid": data['network_id']}],
                security_groups=sec_gr,                 
                user_data=userdata,
                config_drive=True
            )            
            logger.info(f"Instance launch initiated {server.name}",
                    extra=custom_log_celery("create_instance", user_info, orgid, orgname, {}))
            # Wait for server to become ACTIVE
            server = conn.compute.wait_for_server(server, status="ACTIVE", failures=["ERROR"], interval=5, wait=600)
            org = OrganizationReachStack.objects.get(id=orgid)             
            Subscription.objects.filter(id=subscription_id).update(
                resource_id=server.id,
                resource_name=server.name
            )                    
            logger.info(f"Subscription record updated for instance {server.name}",
                extra=custom_log_celery("subscription_record", user_info, orgid, orgname, {}))
            instance = Instances.objects.create(
                    organization=org,
                    instance_name=server.name,
                    instance_id=server.id,
                    project_id = project_id,
                    project_name=user_info.get("project_name"),                 
                    key_pair_name = data.get("key_name"),
                    flavor_id = data['flavor_id']
            )               
            
            #Create Billing for Network Bandwidth
            #CreateNetworkBilling.apply_async(args=[token, user_info, orgid, orgname, server.id, server.name, project_id], countdown=60 )
            conn.close()            
        else:
            logger.info(f"Volume not ready yet",
                    extra=custom_log_celery("create_instance", user_info, orgid, orgname, {}))
            conn.close()
            raise self.retry(exc=Exception("Volume not ready yet"))
    except Exception as e:        
        logger.error(f"{str(e)}",
                    extra=custom_log_celery("create_instance", user_info, orgid, orgname, {}))

@shared_task(bind=True, max_retries=20, default_retry_delay=60)        
def deleteserver_task(self, token, user_info, orgid, orgname, server_id, project_id):
    try:
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token, project_id=project_id)
        sess = session.Session(auth=auth)
        conn = connection.Connection(session=sess)          
        volumes_to_delete = []
        detachable_volumes = []
        server = conn.compute.get_server(server_id)
        server_name = server.name
        serverdict = server.to_dict()     
        # Separate volumes: detachable vs delete_on_termination
        for attachment in serverdict.get("attached_volumes", []):                
            vol_id = attachment.get("id")
            if attachment.get("delete_on_termination", False):
                volumes_to_delete.append(vol_id)              
            detachable_volumes.append(vol_id)              
        # Delete the server
        conn.compute.delete_server(server) 
        logger.info(f"Instance-{server_name} Delete initiated",
                    extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))
        try:
            conn.compute.wait_for_delete(server, wait=120)
        except Exception as wait_err:
            logger.warning(f"Timeout/issue while waiting for instance deletion: {wait_err}",
                        extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))  
        # First detach non-boot volumes
        for vol_id in detachable_volumes:
            try:
                volume = conn.block_storage.get_volume(vol_id)
                volume = volume.to_dict()                    
                for attach in volume["attachments"]:
                    if attach["server_id"] == server_id:
                        try:
                            server = conn.compute.delete_volume_attachment(server_id, vol_id, ignore_missing=True)
                        except:
                            pass
                        conn.block_storage.detach_volume(vol_id, attach["attachment_id"], force=True)     
                        conn.block_storage.wait_for_status(
                                conn.block_storage.get_volume(vol_id),
                                status="available",
                                failures=["error"],
                                wait=None
                        )               
                        logger.info(f"Detached volume-{vol_id} from instance-{server_name}",
                            extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))
            except Exception as detach_err:
                logger.warning(f"Failed to detach volume {vol_id}: {detach_err}",
                               extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))   
            
        # Delete volumes marked for delete_on_termination
        for vol_id in volumes_to_delete:
            try:
                conn.block_storage.delete_volume(vol_id, ignore_missing=True, force=True)
                logger.info(f"Volume-{vol_id} deleted along with instance",
                            extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))
            except Exception as ve:
                logger.warning(f"Failed to delete volume {vol_id}: {ve}",
                               extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))
    except Exception as e:
            response = {"error": "Internal Server Error"}
            if isinstance(e, (KeyError, ValueError)):
                rspstatus = 400
            else:
                rspstatus = 500
            logger.error(str(e),
                    extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))  

def update_quota_atDelete(conn, project_id, vcpus, ram, disk ):
    try:
        compute_quotas = conn.compute.get_quota_set(project_id).to_dict()
        volume_quotas = conn.block_storage.get_quota_set(project_id).to_dict()
        network_quotas = conn.network.get_quota(project_id).to_dict()
    except Exception as e:
        raise ValidationError(f"Failed to fetch current quotas: {str(e)}")
    
    try:
        # Nova (compute)
        conn.compute.update_quota_set(
                project_id,
                instances = compute_quotas["instances"] - 1,
                cores = compute_quotas["cores"] - vcpus,
                ram = compute_quotas["ram"] - ram
        )

        # Cinder (volume)
        conn.block_storage.update_quota_set(
                project_id,
                gigabytes=volume_quotas["gigabytes"] - disk,
                volumes=volume_quotas["volumes"] - 1               
        )

        # Neutron (network)
        conn.network.update_quota(
                project_id,
                networks = network_quotas["networks"] - 1,
                routers = network_quotas["routers"] - 1,
                floating_ips = network_quotas["floating_ips"] - 1,
                security_groups = network_quotas["security_groups"] - 1,
                security_group_rules = network_quotas["security_group_rules"] + SECURITY_RULES_PER_INSTANCE,
                ports = network_quotas["ports"] + PORTS_PER_INSTANCE
        )
    except Exception as e:
        raise ValidationError(f"Error applying quota updates: {str(e)}")
              
@shared_task(bind=True, max_retries=10, default_retry_delay=60)
def detach_and_cleanup_volumes(self, token, project_id, server_name, volumes_to_delete, detachable_volumes, user_info, orgid, orgname, server_id, vcpus, ram, disk):
    try:
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token, project_id=project_id)
        sess = session.Session(auth=auth)
        conn = connection.Connection(session=sess)

        for vol_id in detachable_volumes:
            volume = conn.block_storage.get_volume(vol_id)
            if volume.status != "available":
                conn.close()
                raise self.retry(exc=Exception(f"Volume {vol_id} still busy"), countdown=60)

        # Once available → delete volumes marked for delete_on_termination
        for vol_id in volumes_to_delete:
            try:
                conn.block_storage.delete_volume(vol_id, ignore_missing=True, force=True)
                logger.info(f"Volume-{vol_id} deleted along with instance {server_name}",
                        extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))
            except Exception as ve:
                logger.warning(f"Failed to delete volume {vol_id} along with {server_name}: {ve}",
                               extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))
        
        #Generate Invoice Lines for deleted server up to now             
        records = Subscription.objects.filter(
                Q(resource_id=server_id) | Q(related_instance_id=server_id),
                status="active"
        )            
        for record in records:
            now = timezone.now()                
            balance_duration = record.next_billing_date - now
            hours= balance_duration.total_seconds() / 3600
            balance_hours = round(hours, 2)
            balance_amount = Decimal('0.00')
            if record.resource_type == "instance":
                flavorprice = FlavorPricing.objects.filter(flavor_id=record.flavor_id).first()
                balance_amount=flavorprice.rate_hour * Decimal(str(balance_hours))
                
            elif record.resource_type == "floating_ip":
                price = Pricing.objects.filter().latest("created_at")
                balance_amount=price.price_per_fip_hr * Decimal(str(balance_hours))

            elif record.resource_type == "bandwidth":
                price = Pricing.objects.filter().latest("created_at")
                balance_amount=price.price_per_bandwidth_gb * Decimal(str(balance_hours))
                    
            elif record.resource_type == "volume":
                price = Pricing.objects.filter().latest("created_at")
                balance_amount=price.price_per_volume_gb_hr * record.volume_gb * Decimal(str(balance_hours))
                
            record.status = "deleted"
            record.billed_upto = now
            record.period_end = now
            record.save(update_fields=["status", "billed_upto", "period_end"])
            logger.info("Subscription Record Closed.", 
                        extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))
            org = record.organization
            org.balance_amount += balance_amount
            org.save(update_fields=["balance_amount"])
        
        update_quota_atDelete(conn, project_id, vcpus, ram, disk )
        logger.info(f"Instance-{server_name} Deleted. Balance amount - {balance_amount} added in your acount",
                    extra=custom_log_celery("delete_instance", user_info, orgid, orgname, {}))       
        conn.close()
    except Exception as e:
        print("volume_delete_celery", str(e))

@shared_task(bind=True, max_retries=10, default_retry_delay=60)
def wait_for_volume_deletion(self, token, project_id, volume_id, volume_size, user_info, orgid, orgname ):
    try:
        auth = v3.Token(auth_url=KEYSTONE_URL, token=token, project_id=project_id)
        sess = session.Session(auth=auth)
        conn = connection.Connection(session=sess)  
        try:        
            vol = conn.block_storage.get_volume(volume_id)
            vol_status = vol.status
        except Exception as e:
            vol_status = "deleted"
        if vol_status == "deleted":
            volume_quotas = conn.block_storage.get_quota_set(project_id).to_dict()
            conn.block_storage.update_quota_set(
                    project_id,
                    gigabytes=volume_quotas["gigabytes"] - volume_size,
                    volumes=volume_quotas["volumes"] - 1                           
            )
            #Delete the subscription plan
            record = Subscription.objects.filter(resource_id=volume_id, status="active").first()
            now = timezone.now()                
            balance_duration = record.next_billing_date - now
            hours= balance_duration.total_seconds() / 3600
            balance_hours = round(hours, 2)
            balance_amount = Decimal('0.00')
            price = Pricing.objects.filter().latest("created_at")
            balance_amount=price.price_per_volume_gb_hr * record.volume_gb * Decimal(str(balance_hours)) 
            record.status = "deleted"
            record.billed_upto = now
            record.save(update_fields=["status", "billed_upto"])
            logger.info("Old Subscription Record Closed.", 
                        extra=custom_log_celery("delete_volume", user_info, orgid, orgname, {}))
            org = record.organization
            org.balance_amount += balance_amount
            org.save(update_fields=["balance_amount"]) 
            logger.info("Subscription Record for this volume Closed.", 
                        extra=custom_log_celery("delete_volume", user_info, orgid, orgname, {})) 
            logger.info(
                f"Deleted volume {volume_id}",
                extra=custom_log_celery("delete_volume", user_info, orgid, orgname, {}))
            conn.close()
        if vol_status == "error_deleting":
            logger.eror(f"Failed to delete volume {volume_id}",
                               extra=custom_log_celery("delete_volume", user_info, orgid, orgname, {}))
            conn.close()
        else:
            logger.info(f"Volume not deleted yet",
                    extra=custom_log_celery("delete_volume", user_info, orgid, orgname, {}))
            conn.close()
            raise self.retry(exc=Exception("Waiting for volume deletion"))
    except Exception as e:
        logger.error(f"Failed to delete volume {volume_id}: {str(e)}",
                               extra=custom_log_celery("delete_volume", user_info, orgid, orgname, {}))
        