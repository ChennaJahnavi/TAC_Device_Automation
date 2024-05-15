import sys
import pexpect
from pexpect import pxssh
import pandas as pd
import logging
from datetime import datetime
ssh_yang_host = "127.0.0.1"
yang_port = 2222
cred = {"username": "ejahnavi", "password": "Pa$$w0rd5pcc02x*d"}
yang_timeout=5
logging.basicConfig(
    level="DEBUG",
    format="%(asctime)s - %(levelname)s - [ %(message)s ]",
    datefmt='%d-%b-%y %H:%M:%S',
    force=True,
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler()
    ])
logger = logging.getLogger('urbanGUI')

device_group="ACME"
total_output=[]

#content_tac={35016964: "IPHONE4S", 35016974: "IPHONE3G", 36016974: "IPHONE15"}
df = pd.read_csv('Book_Sample_updated.csv')
tac_frame = df[["TAC", "Manufacturer", "Marketingname"]]
#new_df = tac_frame[tac_frame["Manufacturer"]=="Apple"]

new_df =tac_frame[(tac_frame['Manufacturer'] == 'Apple') & (tac_frame['TAC'].astype(str).str.len()==8)]
new_df =new_df[(new_df['Manufacturer'] == 'Apple') & (new_df['Marketingname'].str.len()<=32)]

abnormal_entities=tac_frame[(tac_frame['Manufacturer'] == 'Apple') & ((tac_frame['TAC'].astype(str).str.len()!=8) | (tac_frame['Marketingname'].str.len()>32))]
content_tac = new_df.set_index('TAC')['Marketingname'].to_dict()

abnormal_tac=abnormal_entities.set_index('TAC')['Marketingname'].to_dict()
for k, v in abnormal_tac.items():
    logging.error(f"{k}, {v} abnormality in any of this entity")


def get_ssh_connection_pexpect_with_port(host: str, ssh_credentials: dict, port=22):
    ssh_client = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"})
    ssh_client.login(server=host, **ssh_credentials, port=port, auto_prompt_reset=False)
    return ssh_client


def ccd_command(ssh_connection, cmd: str, timeout: int = 300) -> str:
    total_output.append(cmd)
    print("executing:", cmd)
    try:
        ssh_connection.expect_exact(ssh_connection.buffer)
        ssh_connection.sendline(cmd)
        ssh_connection.prompt(timeout)
        ccd_command_out = ssh_connection.before.decode("utf-8").split("\n", 1)[-1].rstrip()
    except pexpect.exceptions.EOF:
        print('exceptions.EOF')
        sys.exit()
    except pexpect.pxssh.ExceptionPxssh:
        print('ExceptionPxssh')
        sys.exit()
    total_output.append(ccd_command_out)
    print("output:", ccd_command_out)
    return ccd_command_out

def device_type_get(device_type):
    out = ccd_command(ssh_conn, f"show running-config mm ue-device-type {device_type}",timeout=yang_timeout)
    if "element does not exist" in out:
        return True
    else:
        logging.debug(f"{device_type} is available")
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
        logging.debug(f"{device_type} {tac} available")
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
        logging.debug(f"{device_type} {device_group} available")
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
        if config_mode_check():
            config_mode_exit()
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
        if config_mode_check():
            config_mode_exit()
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
        if config_mode_check():
            config_mode_exit()
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

def config_mode_check():
    out = ccd_command(ssh_conn, f"", timeout=yang_timeout)
    if "config" in out:
        return True
    else:
        return False

def config_mode_exit():
    out = ccd_command(ssh_conn, f"exit", timeout=yang_timeout)
    if "Uncommitted changes found" in out:
        out = ccd_command(ssh_conn, f"no", timeout=yang_timeout)
    return


try:
    ssh_conn = get_ssh_connection_pexpect_with_port(ssh_yang_host, cred, port=yang_port)
except pexpect.pxssh.ExceptionPxssh:
    logging.error(f'could not establish connection to host {ssh_yang_host}')
    sys.exit()

device_type_execution(content_tac)
device_type_tac_execution(content_tac)
#print(total_output)
device_type_group_execution(content_tac)

current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
str_current_datetime = str(current_datetime)
file_name = "tac_log"+str_current_datetime+".txt"
file = open(file_name,'w')
for item in total_output:
    file.write(item+"\n")
file.close()
if not ssh_conn is None:
 ssh_conn.logout()


