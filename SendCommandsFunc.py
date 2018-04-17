import openpyxl
import xlrd
from netmiko import ConnectHandler
from getpass import getpass
from getpass import getuser
from easygui import passwordbox
import easygui
import time
import sys
import json

i = 1
data = []
print(sys.argv)
print("aaa")
while i<len(sys.argv)-1:
    #print(sys.argv[i][1])
    data.append(json.loads(sys.argv[i]))
    print(data)
    i = i+1

Commands = sys.argv[i]
print (Commands)
def sendCommands (DeviceJSON, *ComandLine):
    Command = []
    for arg in ComandLine:
        Command.append(arg)
    device = (DeviceJSON)
    print(Command)
    net_connect = ConnectHandler(**device)
    output = net_connect.send_command(str(Command[0]))
    print(output)

for device in data :
    sendCommands(device,Commands)
sys.exit(0)
