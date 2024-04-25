from pexpect import pxssh
import pandas as pd
ssh_yang_host = "127.0.0.1"
yang_port = 2222
cred = {"username": "ejahnavi", "password": "Pa$$w0rd5pcc02x*c"}
yang_timeout=5
device_group="ACME"
total_output=[]
#content_tac={35016964: "IPHONE4S", 35016974: "IPHONE3G", 36016974: "IPHONE15"}
df = pd.read_csv('Book_sample.csv')
tac_frame = df[["TAC", "Manufacturer", "Marketingname"]]
new_df = tac_frame[tac_frame["Manufacturer"]=="Apple"]
content_tac = new_df.set_index('TAC')['Marketingname'].to_dict()

def get_ssh_connection_pexpect_with_port(host: str, ssh_credentials: dict, port=22):
    ssh_client = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"})
    ssh_client.login(server=host, **ssh_credentials, port=port, auto_prompt_reset=False)
    return ssh_client


def ccd_command(ssh_connection, cmd: str, timeout: int = 300) -> str:
    print("executing:", cmd)
    ssh_connection.expect_exact(ssh_connection.buffer)
    ssh_connection.sendline(cmd)
    ssh_connection.prompt(timeout)
    ccd_command_out = ssh_connection.before.decode("utf-8").split("\n", 1)[-1].rstrip()
    total_output.append(ccd_command_out)
    print("output:", ccd_command_out)
    return ccd_command_out

def device_type_get(device_type):
    out = ccd_command(ssh_conn, f"show running-config mm ue-device-type {device_type}",timeout=yang_timeout)
    if "element does not exist" in out:
        return True
    else:
        return False


def device_type_put(device_type):

    print(" device type is not available, creating")
    out = ccd_command(ssh_conn, f"config",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"mm ue-device-type {device_type}",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"commit",timeout=yang_timeout)
    if "Proceed?" in out:
       out = ccd_command(ssh_conn, f"yes",timeout=yang_timeout)
       out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    if "Commit complete" in out:
       print("group created successfully")
    out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    #out = ccd_command(ssh_conn, f"no",timeout=yang_timeout)
    return
    #else:
       #print("Error in creating group")
       #out=None
       #sys.exit(-1)

def device_type_tac_get(device_type,tac):
    out = ccd_command(ssh_conn, f"show running-config mm ue-device-type-imei-tac {device_type} {tac}",timeout=yang_timeout)
    if "element does not exist" in out:
        return True
    else:
        return False


def device_type_tac_put(device_type,tac):

    print(" device type is not available, creating")
    out = ccd_command(ssh_conn, f"config",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"mm ue-device-type-imei-tac {device_type} {tac}",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"commit",timeout=yang_timeout)
    if "Proceed?" in out:
       out = ccd_command(ssh_conn, f"yes",timeout=yang_timeout)
       out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    if "Commit complete" in out:
       print("group created successfully")
    out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    #out = ccd_command(ssh_conn, f"no",timeout=yang_timeout)
    return
    #else:
       #print("Error in creating group")
       #out=None
       #sys.exit(-1)

def device_type_group_get(device_type,device_group):
    out = ccd_command(ssh_conn, f"show running-config mm ue-dg-device-type {device_group} {device_type}",timeout=yang_timeout)
    if "element does not exist" in out:
        return True
    else:
        return False


def device_type_group_put(device_type,device_group):

    print(" device type is not available, creating")
    out = ccd_command(ssh_conn, f"config",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"mm ue-dg-device-type {device_group} {device_type}",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"commit",timeout=yang_timeout)
    if "Proceed?" in out:
       out = ccd_command(ssh_conn, f"yes",timeout=yang_timeout)
       out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    if "Commit complete" in out:
       print("group created successfully")
    out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    #out = ccd_command(ssh_conn, f"no",timeout=yang_timeout)
    return
    #else:
       #print("Error in creating group")
       #out=None
       #sys.exit(-1)


def device_type_execution(content_tac):
    x = content_tac.values()
    for i in x:
        print("start")
        print(i,"loop CONTENT")
        y=device_type_get(i)
        print(y)
        print("stop")

        if y:
            print(f"{i} not available")
            device_type_put(i)
            print("++++++++++++++++++++++++++")
            ll=device_type_get(i)
            print(ll)
            print("++++++++++++++++++++++++++")
        else:
            print("Available")

def device_type_tac_execution(content_tac):
    for tac,device_name in content_tac.items():
        print("start")
        print(device_name,"loop CONTENT")
        y=device_type_tac_get(device_name,tac)
        print(y)
        print("stop")

        if y:
            print(f"not available")
            device_type_tac_put(device_name,tac)
            print("++++++++++++++++++++++++++")
            ll=device_type_tac_get(device_name,tac)
            print(ll)
            print("++++++++++++++++++++++++++")
        else:
            print("Available")

def device_type_group_execution(content_tac):
    for device_name in content_tac.values():
        print("start")
        print(device_name,"loop CONTENT")
        y=device_type_group_get(device_name,device_group)
        print(y)
        print("stop")

        if y:
            print(f"not available")
            device_type_group_put(device_name,device_group)
            print("++++++++++++++++++++++++++")
            ll=device_type_group_get(device_name,device_group)
            print(ll)
            print("++++++++++++++++++++++++++")
        else:
            print("Available")

ssh_conn = get_ssh_connection_pexpect_with_port(ssh_yang_host, cred, port=yang_port)

device_type_execution(content_tac)
device_type_tac_execution(content_tac)
device_type_group_execution(content_tac)
for i in total_output:
    print(i)
