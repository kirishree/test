from rest_framework import serializers
from ipaddress import ip_network, ip_interface, AddressValueError
class AuthLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class AuthLoginResponseSerializer(serializers.Serializer):
    access = serializers.CharField()
    refresh = serializers.CharField()
    message = serializers.CharField()
    msg_status = serializers.CharField()

class ProjectUserinfo(serializers.Serializer):   
    user_name = serializers.CharField()
    user_role = serializers.CharField()
    project_name = serializers.CharField()

class ProjectGroupinfo(serializers.Serializer):   
    group_name = serializers.CharField()
    group_role = serializers.CharField()
    project_name = serializers.CharField()
   
class ProjectInfoResponseSerializer(serializers.Serializer):
    project_id = serializers.CharField()
    project_name = serializers.CharField()
    project_description = serializers.CharField()
    project_domain_name =  serializers.CharField()
    project_status = serializers.CharField()
    user_info = serializers.ListField(
        child = ProjectUserinfo()
    )
    group_info = serializers.ListField(
        child = ProjectGroupinfo()
    )

class CreateProjectUser(serializers.Serializer):
    username = serializers.CharField()
    role = serializers.CharField()

class CreateProjectGroup(serializers.Serializer):
    groupname = serializers.CharField()
    role = serializers.CharField()

class CreateProjectSerializer(serializers.Serializer):
    project_name = serializers.CharField()
    project_description = serializers.CharField()
    project_users = serializers.ListField(
        child = CreateProjectUser()
    )
    groups = serializers.ListField(
        child = CreateProjectGroup()
    )

class UpdateProjectSerializer(serializers.Serializer):
    project_id = serializers.Serializer()
    project_name = serializers.CharField()
    project_description = serializers.CharField()
    project_users = serializers.ListField(
        child = CreateProjectUser()
    )
    groups = serializers.ListField(
        child = CreateProjectGroup()
    )
    
class CreateGroupSerializer(serializers.Serializer):
    group_name = serializers.CharField(max_length=100)
    group_description = serializers.CharField(max_length=255, required=False)

class AddGroupSerializer(serializers.Serializer):
    group_name = serializers.CharField()
    users = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of Keystone user names"
    )

class switchProResponseSerializer(serializers.Serializer):
    token = serializers.CharField()
    project_id = serializers.CharField()

class SwitchProSerializer(serializers.Serializer):
    project_name = serializers.CharField()

class UserInfoResponseSerializer(serializers.Serializer):
    project_id =  serializers.CharField()
    project_name =  serializers.CharField()
    role_id =  serializers.CharField()
    role_name = serializers.CharField()

class UserListResponseSerializer(serializers.Serializer):
    id = serializers.CharField()
    name = serializers.CharField()
    email = serializers.CharField()
    enabled = serializers.CharField()
    doamin_id = serializers.CharField()
    default_project_id = serializers.CharField()
    description = serializers.CharField()
    project_list = serializers.ListField()

class UpdatGroupNameSerializer(serializers.Serializer):
    current_group_name = serializers.CharField()
    new_group_name = serializers.CharField()
    new_description = serializers.CharField()

class RemoveUserGroupSerializer(serializers.Serializer):
    group_name = serializers.CharField()
    user_names =  serializers.ListField()

class DeleteGroupSerializer(serializers.Serializer):
    groups = serializers.ListField()

class DeleteProjectSerializer(serializers.Serializer):
    projects = serializers.ListField()

class UpdateUserInfoSerializer(serializers.Serializer):
    username = serializers.CharField()
    description = serializers.CharField()
    emailid = serializers.CharField()
    primary_project = serializers.CharField()

class GetUserInfoSerializer(serializers.Serializer):
    user_id  = serializers.CharField()

class GetProjectInfoSerializer(serializers.Serializer):
    project_id = serializers.CharField()

class ImagesListSerializer(serializers.Serializer):
    image_id = serializers.CharField()
    image_name = serializers.CharField()
    image_status = serializers.CharField()
    image_visibility = serializers.CharField()

visibility_options = ["private", "shared", "public", "community" ]
image_format_options = ["iso", "ova", "ploop", "qcow2", "raw", 
                        "VDI", "vhd", "vmdk", "aki", "ami", "ari", "docker"]
os_type_options = ["linux", "unix", "windows"]
architecture_options = ["x86_64", "arm64"]
class CreateImageSerializer(serializers.Serializer):
    image_name = serializers.CharField()
    image_format = serializers.ChoiceField(choices=image_format_options)
    image_description = serializers.CharField()
    min_ram = serializers.IntegerField()
    min_disk = serializers.IntegerField()
    image_visibility = serializers.ChoiceField(choices=visibility_options)
    architecture = serializers.ChoiceField(choices=architecture_options)
    os_type = serializers.ChoiceField(choices=os_type_options)
    hw_vcpu_min = serializers.CharField()

class UpdateImageSerializer(serializers.Serializer):
    image_id = serializers.CharField()
    image_name = serializers.CharField()
    image_description = serializers.CharField()
    min_ram = serializers.IntegerField()
    min_disk = serializers.IntegerField()
    image_visibility = serializers.ChoiceField(choices=visibility_options)
    architecture = serializers.ChoiceField(choices=architecture_options)
    os_type = serializers.ChoiceField(choices=os_type_options)
    hw_vcpu_min = serializers.CharField()

class DeleteImageSerializer(serializers.Serializer):
    images = serializers.ListField()

class CreateFlavorSerializer(serializers.Serializer):
    flavor_name = serializers.CharField()
    flavor_ram = serializers.IntegerField()
    flavor_vcpus = serializers.IntegerField()
    flavor_disk = serializers.IntegerField()
    flavor_description = serializers.CharField()
    flavor_is_public = serializers.BooleanField()

class FlavorResponseSerializer(serializers.Serializer):
    flavor_name = serializers.CharField()
    flavor_ram = serializers.IntegerField()
    flavor_vcpus = serializers.IntegerField()
    flavor_disk = serializers.IntegerField()
    flavor_description = serializers.CharField()
    flavor_is_public = serializers.BooleanField()
    flavor_id = serializers.CharField()

class UpdateFlavorSerializer(serializers.Serializer):
    flavor_id = serializers.CharField()
    flavor_name = serializers.CharField()
    flavor_description = serializers.CharField()

class DeleteFlavorSerializer(serializers.Serializer):
    flavor_ids = serializers.ListField()

class GetFlavorByIDSerializer(serializers.Serializer):
    flavor_id = serializers.CharField()

class ImportPubblickeySerializer(serializers.Serializer):
    keypair_name = serializers.CharField()
    keypair_public_key = serializers.CharField()

class CreatekeypairSerializer(serializers.Serializer):
    keypair_name = serializers.CharField()

class DeleteKeypairSerializer(serializers.Serializer):
    keypair_names = serializers.ListField()

class DhcpRangeSerializer(serializers.Serializer):
    start = serializers.IPAddressField(protocol='IPv4')
    end = serializers.IPAddressField(protocol='IPv4')

class CreateNetworkSerializer(serializers.Serializer):
    network_name = serializers.CharField()
    project_name = serializers.CharField()
    admin_state_up = serializers.BooleanField()
    create_subnet = serializers.BooleanField()
    subnet_name = serializers.CharField()
    network_address = serializers.CharField()
    enable_dhcp = serializers.BooleanField()
    mtu = serializers.CharField()
    gateway_address = serializers.IPAddressField(protocol='IPv4')
    dhcp_pools = serializers.ListField(
        child = DhcpRangeSerializer()
    )
    primary_dns = serializers.IPAddressField(protocol='IPv4')
    sec_dns = serializers.IPAddressField(protocol='IPv4')
    def validate_network_address(self, value):
        try:
            net = ip_network(value, strict=True)  # strict=True enforces it must be a network
            return str(net)
        except ValueError:
            raise serializers.ValidationError("Network_addres must be a valid network (e.g., 192.168.1.0/24).")

class CreateSubnetSerializer(serializers.Serializer):
    network_name = serializers.CharField()    
    subnet_name = serializers.CharField()
    network_address = serializers.CharField()
    enable_dhcp = serializers.BooleanField()
    gateway_address = serializers.IPAddressField(protocol='IPv4')
    dhcp_pools = serializers.ListField(
        child = DhcpRangeSerializer()
    )
    primary_dns = serializers.IPAddressField(protocol='IPv4')
    sec_dns = serializers.IPAddressField(protocol='IPv4')
    def validate_network_address(self, value):
        try:
            net = ip_network(value, strict=True)  # strict=True enforces it must be a network
            return str(net)
        except ValueError:
            raise serializers.ValidationError("Network_addres must be a valid network (e.g., 192.168.1.0/24).")

class UpdateSubnetSerializer(serializers.Serializer):
    subnet_id = serializers.CharField()
    subnet_name = serializers.CharField()
    enable_dhcp = serializers.BooleanField()
    gateway_address = serializers.IPAddressField(protocol='IPv4')
    dhcp_pools = serializers.ListField(
        child = DhcpRangeSerializer()
    )
    primary_dns = serializers.IPAddressField(protocol='IPv4')
    sec_dns = serializers.IPAddressField(protocol='IPv4')
    def validate_network_address(self, value):
        try:
            net = ip_network(value, strict=True)  # strict=True enforces it must be a network
            return str(net)
        except ValueError:
            raise serializers.ValidationError("Network_addres must be a valid network (e.g., 192.168.1.0/24).")

class UpdateNetworkSerializer(serializers.Serializer):
    network_id = serializers.CharField()
    network_name = serializers.CharField()
    admin_state_up = serializers.BooleanField()

class GetNwSubnetSerializer(serializers.Serializer):
    network_id = serializers.CharField()

class CreateRouterSerializer(serializers.Serializer):
    router_name = serializers.CharField()
    external_network = serializers.CharField()
    enable_snat = serializers.BooleanField()
    internal_subnet = serializers.CharField()
    admin_state_up = serializers.BooleanField()

class DeleteSubnetSerializer(serializers.Serializer):
    subnet_id = serializers.ListField()

class DeleteNetworkSerializer(serializers.Serializer):
    network_id = serializers.ListField()

class AddInterfaceSerializer(serializers.Serializer):
    router_id = serializers.CharField()
    subnet_id = serializers.CharField()
class SetGatewaySerializer(serializers.Serializer):
    network_id = serializers.CharField()
    enable_snat = serializers.BooleanField()

class DeleteRouterSerializer(serializers.Serializer):
    router_ids = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of router IDs to delete"
    )

class CreateSecGroupSerializer(serializers.Serializer):
    name= serializers.CharField()
    description = serializers.CharField()

class AddRuleSerializer(serializers.Serializer):
    security_group_id = serializers.CharField()
    direction = serializers.ChoiceField(choices = [("ingress", "ingress"),
                                                   ("egress", "egress")])
    protocol = serializers.ChoiceField(choices=[('udp','udp'), 
                                                ('tcp', 'tcp'),
                                                ('icmp', 'icmp'),
                                                (None, None)])
    port_range_min = serializers.CharField(allow_null=True)
    port_range_max = serializers.CharField(allow_null=True)
    remote_ip_prefix = serializers.CharField()
    def validate_remote_ip_prefix(self, value):
        try:
            net = ip_network(value, strict=True)  # strict=True enforces it must be a network
            return str(net)
        except ValueError:
            raise serializers.ValidationError("remote_ip_prefix must be a valid network (e.g., 192.168.1.0/24).")

class DeleteSGSerilaizer(serializers.Serializer):
    security_group_ids = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of Security Group IDs to delete"
    )

class DeleteRulesSerializer(serializers.Serializer):
    rule_ids = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of Security Group  Rule IDs to delete"
    )

class DeleteInterfacesSerializer(serializers.Serializer):
    interface_ids = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of Interface IDs to delete"
    )

class DeleteRuleIDSSerializer(serializers.Serializer):
    rule_ids = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of Rule IDs to delete"
    )

class CreatePortSerializer(serializers.Serializer):
    network_id = serializers.CharField()
    subnet_id = serializers.CharField()
    port_name = serializers.CharField()

class RescueBodySerializer(serializers.Serializer):
    admin_pass = serializers.CharField()

class UpdateSecurityGroupSerializer(serializers.Serializer):
    security_groups = serializers.ListField()