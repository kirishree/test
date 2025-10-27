import secrets, base64, time
from openstack import connection

def generate_ssh_keypair():
    # Implementation: use paramiko or ssh-keygen subprocess to generate keypair
    private = "-----BEGIN PRIVATE KEY-----\n..."
    public = "ssh-rsa AAAA..."
    return private, public

def create_helper_and_patch(conn: connection.Connection, volume_id: str, username: str, public_key: str):
    # 1) Launch ephemeral helper with userdata that waits, mounts /dev/vdb and injects public_key
    userdata = f"""#cloud-config
runcmd:
 - [ sh, -c, 'for i in $(seq 1 30); do if [ -b /dev/vdb ]; then break; fi; sleep 2; done; mkdir -p /mnt/v; mount /dev/vdb /mnt/v || exit 1; mkdir -p /mnt/v/home/{username}/.ssh; echo "{public_key}" >> /mnt/v/home/{username}/.ssh/authorized_keys; chown -R 1000:1000 /mnt/v/home/{username}; chmod 700 /mnt/v/home/{username}/.ssh; chmod 600 /mnt/v/home/{username}/.ssh/authorized_keys; umount /mnt/v; shutdown -h now' ]
"""
    image = SOME_SMALL_HELPER_IMAGE_ID
    flavor = SOME_SMALL_FLAVOR_ID
    net = SOME_NETWORK_ID

    helper = conn.compute.create_server(
        name="recover-helper-"+secrets.token_hex(4),
        image_id=image,
        flavor_id=flavor,
        networks=[{"uuid": net}],
        user_data=base64.b64encode(userdata.encode()).decode(),
        key_name=None, # optional: key to access helper if you want
        config_drive=True
    )
    helper = conn.compute.wait_for_server(helper, status='ACTIVE', failures=['ERROR'], wait=120)

    # 2) Attach volume
    conn.block_storage.create_volume_attachment(server=helper, volumeId=volume_id)
    # Wait for helper to shutdown; monitor console or status
    start = time.time()
    while time.time() - start < 600:
        helper = conn.compute.get_server(helper.id)
        if helper.status in ("SHUTOFF","DELETED","ERROR"):
            break
        time.sleep(5)

    # 3) Detach volume
    # find the attachment id and delete
    # 4) Delete helper
    conn.compute.delete_server(helper.id, ignore_missing=True)

    return True
