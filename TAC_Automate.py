import sys
import argparse
import re
import pexpect
from pexpect import pxssh
import pandas as pd
import logging
from datetime import datetime

yang_timeout=3
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
# node = {}
# freq_node_devices = {}

def get_ssh_connection_pexpect_with_port(host: str, ssh_credentials: dict, port=22):
    ssh_client = pxssh.pxssh(options={"StrictHostKeyChecking": "no", "UserKnownHostsFile": "/dev/null"})
    ssh_client.login(server=host, **ssh_credentials, port=port, auto_prompt_reset=False)
    ssh_client.setwinsize(5000,5000)
    return ssh_client

def commit_changes(change_type):
    out = ccd_command(ssh_conn, f"commit",timeout=yang_timeout)
    if "Proceed?" in out:
       out = ccd_command(ssh_conn, f"yes",timeout=yang_timeout)
       out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    if "Commit complete" in out:
        commited = True
    out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    if commited:
        logging.debug(f"Commited {change_type}")
        return True
    else:
        logging.debug(f"Unable to Commit Changes")
        return False

def ccd_command(ssh_connection, cmd: str, timeout: int = 300) -> str:
    total_output.append(cmd)
    print("executing:", cmd)
    try:
        ssh_connection.expect_exact(ssh_connection.buffer)
        ssh_connection.sendline(cmd)
        ssh_connection.prompt(timeout)
        ccd_command_out = ssh_connection.before.decode("utf-8").split("\n", 1)[-1].rstrip()
        if not ccd_command_out:
            logging.debug(f"Connection Timed Out")
            sys.exit()
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
def device_type_put(list_devices):

    #print(list_devices)
    print(" all these device types not available, creating")
    out = ccd_command(ssh_conn, f"config",timeout=yang_timeout)
    for device_type in list_devices:
        out = ccd_command(ssh_conn, f"mm ue-device-type {device_type}",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"commit",timeout=yang_timeout)
    if "Proceed?" in out:
       out = ccd_command(ssh_conn, f"yes",timeout=yang_timeout)
       out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    if "Commit complete" in out:
       print("group created successfully")
       #logging.debug(f"Created {device_type}")
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


def device_type_tac_put(device_tac_dict):

    print(" all these device type and TAC are not available, creating")
    out = ccd_command(ssh_conn, f"config",timeout=yang_timeout)
    for tac,device_type in device_tac_dict.items():
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


def device_type_group_put(device_type_list,device_group):

    print(" all these devices type are not mapped to ACME, creating")
    out = ccd_command(ssh_conn, f"config",timeout=yang_timeout)
    for device_type in device_type_list:
        out = ccd_command(ssh_conn, f"mm ue-dg-device-type {device_group} {device_type}",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"commit",timeout=yang_timeout)
    if "Proceed?" in out:
       out = ccd_command(ssh_conn, f"yes",timeout=yang_timeout)
       out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    if "Commit complete" in out:
       print("group created successfully")
       #logging.debug(f"Created {device_type} against {device_group}")
    out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    #out = ccd_command(ssh_conn, f"no",timeout=yang_timeout)
    return
    #else:
       #print("Error in creating group")
       #out=None
       #sys.exit(-1)
def only_remove_group(li):
    print(" all these devices type are mapped to ACME need to be removed, creating")
    out = ccd_command(ssh_conn, f"config",timeout=yang_timeout)
    for device_type in li: 
        out = ccd_command(ssh_conn, f"no mm ue-dg-device-type {device_group} {device_type}",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"commit",timeout=yang_timeout)
    if "Proceed?" in out:
       out = ccd_command(ssh_conn, f"yes",timeout=yang_timeout)
       #out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    if "Commit complete" in out:
       print("group created successfully")
       #logging.debug(f"Created {device_type} against {device_group}")
    out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    #out = ccd_command(ssh_conn, f"no",timeout=yang_timeout)
    return
    #else:
       #print("Error in creating group")
       #out=None
       #sys.exit(-1)


def only_remove_tac(li):
    print(" all these TAC against device type to be removed, creating")
    out = ccd_command(ssh_conn, f"config",timeout=yang_timeout)
    for device_type,tac in li:
        out = ccd_command(ssh_conn, f"no mm ue-device-type-imei-tac {device_type} {tac}",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"commit",timeout=yang_timeout)
    if "Proceed?" in out:
       out = ccd_command(ssh_conn, f"yes",timeout=yang_timeout)
       #out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    if "Commit complete" in out:
       print("group created successfully")
    out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    #out = ccd_command(ssh_conn, f"no",timeout=yang_timeout)
    return
    #else:
       #print("Error in creating group")
       #out=None
       #sys.exit(-1)

def only_remove_type(li):
    print(" all these device types to be removed, creating")
    print(li)
    out = ccd_command(ssh_conn, f"config",timeout=yang_timeout)
    for device_type in li:
        out = ccd_command(ssh_conn, f"no mm ue-device-type {device_type}",timeout=yang_timeout)
    out = ccd_command(ssh_conn, f"commit",timeout=yang_timeout)
    if "Proceed?" in out:
       out = ccd_command(ssh_conn, f"yes",timeout=yang_timeout)
       #out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    if "Commit complete" in out:
       print("group created successfully")
       #logging.debug(f"Created {device_type}")
    out = ccd_command(ssh_conn, f"exit",timeout=yang_timeout)
    #out = ccd_command(ssh_conn, f"no",timeout=yang_timeout)
    return
    #else:
       #print("Error in creating group")
       #out=None
       #sys.exit(-1)




def TAC_group_delete(remove_tac_group,freq_node_devices_dict):
    node_devices=freq_node_devices_dict
    print(freq_node_devices_dict)
    print(remove_tac_group,'removal list')
    print()
    print(node_devices,'freq before')
    li = []
    dg = current_grouped_devices_in_node()
    print(dg,'node data')
    if remove_tac_group:
        for i in remove_tac_group:
            dt = i.split(' ')[0]
            if dt in node_devices:
                if node_devices[dt]==1 and dt in dg:
                    li.append(dt)
                    node_devices[dt]-=1
                    if node_devices[dt]==0:
                        node_devices.pop(dt)
    print(li,'type in group delete')
    print(node_devices,'freq after')
    if li:
        only_remove_group(li)

def TAC_tac_delete(remove_tac_group,node_dict):
    print(node_dict,'before tac delete')
    li = []
    if remove_tac_group:
        for i in remove_tac_group:
            dt_tac = i.split(' ')
            dt_tac[1]= int(dt_tac[1])
            if dt_tac[1] in node_dict:
                li.append([dt_tac[0],dt_tac[1]])
    if li:
        only_remove_tac(li)

def TAC_type_delete(remove_tac_group,node_dict,freq_node_devices_dict):
    print(node_dict,'after tac delete')
    counts=dict()
    for i in node_dict.values():
        counts[i]=counts.get(i,0)+1
    print(counts,'node_devices_freq')
    print()
    li = []
    device_type_node= current_devices_in_node()
    print(device_type_node,'chcvjgjhjg')
    print()
    print(remove_tac_group)
    if remove_tac_group:
        for i in remove_tac_group:
            print(i)
            dt = i.split(' ')[0]
            print(dt,'abc')
            print(counts)
            if dt in counts:
                if counts[dt] == 1 and dt in device_type_node:
                    print(dt,'efg')
                    li.append(dt)
                    counts[dt]-=1
                    if counts[dt]==0:
                        counts.pop(dt)
    print(li,'removal list')
    if li:
        only_remove_type(li)


def device_type_execution(content_tac,node_device_type):
    x = set(content_tac.values())
    print(x)
    y = node_device_type
    addition = list((x-y))
    print(x,"csv data type")
    print(y,"node data type")
    print(addition, "need to be added")
    if config_mode_check():
        config_mode_exit()
    if addition:
        device_type_put(addition)

    # for i in addition:
    #     print(f"{i} not available")
    #     device_type_put(i)
    #     print("++++++++++++++++++++++++++")
    #     ll=device_type_get(i)
    #     print(ll)
    #     print("++++++++++++++++++++++++++")

def device_type_tac_execution(content_tac,node_device_tac):

    csv_list=[]
    for i in content_tac.items():
        csv_list.append(i[1]+" "+str(i[0]))

    node_list= []
    for i in node_device_tac.items():
        node_list.append(i[1]+" "+str(i[0]))

    addition = (set(csv_list)-set(node_list))

    print(csv_list, "csv data")
    print(node_list, "node data")
    print(addition, "values to be added")

    device_tac_dict = {}
    for i in addition:
        jaan = re.split('\s', i)

        jaan[1] = int(jaan[1])
        device_tac_dict[jaan[1]] = jaan[0]

    if config_mode_check():
        config_mode_exit()
    if device_tac_dict:
        device_type_tac_put(device_tac_dict)

def device_type_group_execution(content_tac,freq_node_devices_after_deletion):
    csv_device_names=set(content_tac.values())
    node_device_names= set(freq_node_devices_after_deletion.keys())
    addition = csv_device_names-node_device_names
    print(csv_device_names,"csv data")
    print(node_device_names,"node data")
    print(addition,"need to be added")
    if config_mode_check():
        config_mode_exit()
    if addition:
        device_type_group_put(addition,device_group)

def current_grouped_devices_in_node():
    print(" A list of all the devices attched to ACME in node")
    out = ccd_command(ssh_conn, f"show running-config mm ue-dg-device-type", timeout=yang_timeout)
    foo= out
    matches = re.findall(r"mm\sue-dg-device-type\sACME\s\S{1,32}", foo)
    #print(matches)

    dt_group = [re.sub('mm ue-dg-device-type ACME ', '', i) for i in matches]
    print(dt_group)
    return dt_group

def current_devices_in_node():
    print(" A list of all the devices present in node")
    out = ccd_command(ssh_conn, f"show running-config mm ue-device-type", timeout=yang_timeout)
    foo= out
    matches = re.findall(r"mm\sue-device-type\s\S{1,32}", foo)
    #print(matches)

    device_type = [re.sub('mm ue-device-type ', '', i) for i in matches]
    #print(device_type)
    #device_type = [re.sub('\n', '', i) for i in device_type]
    #print(device_type)
    return set(device_type)


def current_Tac_in_node():
    print(" A list of all the TAC present in node")
    out = ccd_command(ssh_conn, f"show running-config mm ue-device-type-imei-tac", timeout=yang_timeout)
    foo = out
    # matches = re.findall(r"mm\sue-device-type-imei-tac\s\w+\s\d{8}\n", foo)
    matches = re.findall(r"mm\sue-device-type-imei-tac\s\S{1,32}\s\d{8}", foo)

    # print(matches)

    device_tac = [re.sub('mm ue-device-type-imei-tac ', '', i) for i in matches]
    print(device_tac)
    node = {}
    freq_node_devices = {}
    for i in device_tac:
        if i:
            li = re.split('\s',i)
            if li[0] not in freq_node_devices:
                freq_node_devices[li[0]] = 1
            else:
                freq_node_devices[li[0]] += 1

    for i in device_tac:
        if i:
            jaan = i.split(" ")
            if len(jaan) == 2 and jaan[1].isnumeric():
                jaan[1] = int(jaan[1])
                node[jaan[1]] = jaan[0]
                # if jaan[1] not in node:
                #     node[jaan[1]] = []
                #     node[jaan[1]].append(jaan[0])
                # else:
                #     node[jaan[1]].append(jaan[0])
            else:
                print("Unproccesable Element found" + i)
                # logging.error('%s Unproccesable Element found', i)
        else:
            print("Unproccesable Element found" + i)
    return node,freq_node_devices

def Tac_delete_execution(content_tac, node,freq_node_devices):
    # for k, v in content_tac.items():
    #     print(k, v)
    #     if k in node and node[k] == content_tac[k]:
    #         node.pop(k)
    # print(node)
    # print(freq_node_devices)

    csv_list = []
    for i in content_tac.items():
        csv_list.append(i[1] + " " + str(i[0]))

    node_list = []
    for i in node.items():
        node_list.append(i[1] + " " + str(i[0]))

    removal= set(node_list)-set(csv_list)
    print(csv_list, 'csv data')
    print()
    print(node_list, 'node data')
    print()
    print(removal, 'to be removed')
    #sys.exit()
    #freq_node_devices_1= freq_node_devices

    TAC_group_delete(removal,freq_node_devices)
    #sys.exit()
    TAC_tac_delete(removal,node)
    #sys.exit()
    print(removal)
    TAC_type_delete(removal,node,freq_node_devices)

    # removal_dict = {}
    # for i in removal:
    #     jaan = re.split('\s', i)
    #
    #     jaan[1] = int(jaan[1])
    #     removal_dict[jaan[1]] = jaan[0]
    #
    # if config_mode_check():
    #     config_mode_exit()
    # for k, v in removal_dict.items():
    #     if freq_node_devices[v] > 1:
    #         Only_TAC_delete(k, v)
    #         freq_node_devices[v] -= 1
    #         if freq_node_devices[v] == 0:
    #             freq_node_devices.pop(v)
    #     else:
    #         ALL_TAC_delete(k, v)

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


def config_output_log():
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    str_current_datetime = str(current_datetime)
    file_name = "tac_log" + str_current_datetime + ".txt"
    file = open(file_name, 'w')
    for item in total_output:
        file.write(item + "\n")
    file.close()

def init_utils(hostip, port, username, password, input_csv_file):
    global ssh_conn
    df = pd.read_csv(input_csv_file)
    tac_frame = df[["TAC", "Manufacturer", "Marketingname"]]

    new_df = tac_frame[(tac_frame['Manufacturer'] == 'Apple') & (tac_frame['TAC'].astype(str).str.len() == 8)]
    new_df = new_df[(new_df['Manufacturer'] == 'Apple') & (new_df['Marketingname'].str.len() <= 32)]

    abnormal_entities = tac_frame[(tac_frame['Manufacturer'] == 'Apple') & (
                (tac_frame['TAC'].astype(str).str.len() != 8) | (tac_frame['Marketingname'].str.len() > 32))]
    content_tac = new_df.set_index('TAC')['Marketingname'].to_dict()

    abnormal_tac = abnormal_entities.set_index('TAC')['Marketingname'].to_dict()

    for k, v in abnormal_tac.items():
        logging.error(f"{k}, {v} abnormality in any of this entity")

    ssh_yang_host = str(hostip)
    yang_port = str(port)
    cred = {"username": str(username), "password": str(password)}
    try:
        ssh_conn = get_ssh_connection_pexpect_with_port(ssh_yang_host, cred, port=yang_port)
        if not ssh_conn:
            logging.error(f'connection error')
            sys.exit()
    except pexpect.pxssh.ExceptionPxssh:
        logging.error(f'could not establish connection to host {ssh_yang_host}')
        sys.exit()
    node,freq_node_devices=current_Tac_in_node()
    #this will give node, freq  dictionary { tac : type }
    print(node,'node data')
    print()
    print()
    print(freq_node_devices,'type freq')
    Tac_delete_execution(content_tac, node,freq_node_devices) # 3 separate removals

    node_device_type = current_devices_in_node()
    print(node_device_type)
    device_type_execution(content_tac,node_device_type)
    node_device_tac,freq_node_devices_after_deletion= current_Tac_in_node()  # type_tac dict, freq_dict
    device_type_tac_execution(content_tac,node_device_tac)
    device_type_group_execution(content_tac,freq_node_devices_after_deletion)

    #config_output_log()
    return True


parser = argparse.ArgumentParser()
parser.add_argument('hostip', help='Target HostName or IP')
parser.add_argument('port', help='Port for the Target Server')
parser.add_argument('username', help='Username for the Target Server')
parser.add_argument('password', help='Password for the Taget Server')
parser.add_argument('input_csv_file', help='Absolute Path to the CSV file as Input')
args = parser.parse_args()
init_utils(hostip=args.hostip, port=args.port, username=args.username, password=args.password, input_csv_file=args.input_csv_file)


if not ssh_conn is None:
 ssh_conn.logout()

