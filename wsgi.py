from flask import Flask, render_template, request
from pymongo import MongoClient
#from netmiko import ConnectHandler
import time
import re
import netaddr

Forti_Siege = {
    'device_type': 'fortinet',
    'ip': '172.23.47.254',
    'username': 'ldlc.aa',
    'password': 'tJBGebr6',

}



app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index1.html")


@app.route('/Demandes')
def demandes():

    return render_template("Demandes.html")


@app.route('/Demandes', methods=['POST'])
def demandesReturn():
        text= request.form['source0']
        print(text)
        return text



@app.route('/Services')
def GetServices():

    client = MongoClient('localhost', 27017)
    db = client['local']

    FWservices = db.Firewall_Services.distinct('name')

    return render_template("RepertorierServices.html", servs = FWservices)

@app.route('/Objects')
def GetObjects():

    client = MongoClient('localhost', 27017)
    db = client['local']

    FWservices = db.Firewall_Objects.distinct('name')

    return render_template("RepertorierObjects.html", servs = FWservices)


@app.route('/UpgradeObjects')
def UpgradeObjects():
    client = MongoClient('localhost', 27017)
    db = client['local']

    FWservices = db.Firewall_Objects
    net_connect = ConnectHandler(**Forti_Siege)

    output = net_connect.send_command('get firewall address | grep name')
    i =0

    rowz =[]
    strings = ""
    for letter in output:
        if (letter != "\n"):
            strings = strings+letter
        elif (letter == "\n"):

            rowz.append(strings)
            strings=""
            i = i+1
    i = 0
    for row in rowz:
        row = row.replace("name:", '')

        entry = {
            "name": row
        }

        if (FWservices.find_one({"name": row}) == None):
            FWservices.insert_one(entry)
            i = i+1
    net_connect.disconnect()
    return render_template("UpgradeObjects.html", servs = i)


#REQUETE POST POUR CREER UN OBJET



@app.route('/UpgradeServices')
def UpgradeServices():
    client = MongoClient('localhost', 27017)
    db = client['local']

    FWservices = db.Firewall_Services
    net_connect = ConnectHandler(**Forti_Siege)

    output = net_connect.send_command('get firewall service custom | grep name')
    i =0

    rowz =[]
    strings = ""
    for letter in output:
        if (letter != "\n"):
            strings = strings+letter
        elif (letter == "\n"):

            rowz.append(strings)
            strings=""
            i = i+1
    i = 0
    for row in rowz:
        row = row.replace("name:", '')

        entry = {
            "name": row
        }

        if (FWservices.find_one({"name": row}) == None):
            FWservices.insert_one(entry)
            i = i+1
    net_connect.disconnect()
    return render_template("UpgradeServices.html", servs=i)



@app.route('/UpgradePolicies')
def UpgradePolicies():

    client = MongoClient('localhost', 27017)
    db = client['local']

    FWservices = db.Firewall_Policies
    FWservices.remove({})
    net_connect = ConnectHandler(**Forti_Siege)
    #J=0 : numero , J=1 : addresse source, J=2 dest J=3 : port
    j=0
    rowz = [[], [], [], [], [], []]
    while (j<6):
        if (j==0):
            output = net_connect.send_command('show firewall policy | grep edit')
        elif (j==1):
            output = net_connect.send_command('show firewall policy | grep srcaddr')
        elif (j==2):
            output = net_connect.send_command('show firewall policy | grep dstaddr')
        elif (j==3):
            output = net_connect.send_command('show firewall policy | grep service')
        elif (j==4):
            output = net_connect.send_command('show firewall policy | grep srcintf')
        elif (j==5):
            output = net_connect.send_command('show firewall policy | grep dstintf')
        i =0


        strings = ""

        for letter in output:
            if (letter != "\n"):
                strings = strings+letter
            elif (letter == "\n"):

                rowz[j].append(strings)
                strings=""
                i = i+1

        j=j+1
    ind = 0
    i = 0

    for row in rowz[0]:
        bool = "yes"
        if "all" in rowz[1][ind] and "all" in rowz[2][ind]:
            bool = "no"

        if ('"LAN-CLASS-A - 10.0.0.0/8"' not in rowz[2][ind]) and bool== "yes":

                        row = row.replace("edit ", '')
                        rowz[1][ind] = rowz[1][ind].replace("set srcaddr", '')
                        rowz[2][ind] = rowz[2][ind].replace("set dstaddr", '')
                        rowz[3][ind] = rowz[3][ind].replace("set service", '')
                        rowz[4][ind] = rowz[4][ind].replace("set srcintf", '')
                        rowz[5][ind] = rowz[5][ind].replace("set dstintf", '')
                        entry = {
                            "number" : row,
                            "source address" : rowz[1][ind],
                            "destination address": rowz[2][ind],
                            "service": rowz[3][ind],
                            "source zone": rowz[4][ind],
                            "destination zone": rowz[5][ind]
                        }
                        print(entry)



                        FWservices.insert_one(entry)
                        i = i+1
        ind = ind + 1



    net_connect.disconnect()
    return render_template("UpgradePolicies.html", servs = i)


@app.route('/Policies')
def Policies():





    return render_template("Demandes.html")

@app.route('/Policies', methods=['POST'])
def returnPolicies():
    client = MongoClient('localhost', 27017)
    db = client['local']
    SourcesTab = []
    DestinationsTab=[]
    ServicesTab = []
    IDTab = []
    SourceZoneTab=[]
    DestZoneTab = []



    Sources = db.Firewall_Policies.find({}, {"_id":0, "source address": 1})
    Destinations = db.Firewall_Policies.find({}, {"_id": 0, "destination address": 1})
    Services = db.Firewall_Policies.find({}, {"_id": 0, "service": 1})
    ID = db.Firewall_Policies.find({}, {"_id": 0, "number": 1})
    SourceZones = db.Firewall_Policies.find({}, {"_id": 0, "source zone": 1})
    DestZones = db.Firewall_Policies.find({}, {"_id": 0, "destination zone": 1})

    for u in DestZones:
        DestZoneTab.append(str(u))

    for v in SourceZones:
        SourceZoneTab.append(str(v))

    for w in ID:
        IDTab.append(str(w))

    for x in Sources:
        SourcesTab.append(str(x))

    for y in Destinations:
        DestinationsTab.append(str(y))

    for z in Services:
        ServicesTab.append(str(z))





    SourcesIps = [[],[]]
    DestIps = [[],[]]
    ServIps = []
    IDSTab = []
    SourcesZonesTab = []
    DestsZonesTab= []
    indSource = 0
    indDest = 0

    for s in SourcesTab :
        if "GROUPE LANS FRANCHISES" in s:
            LANFRANCHISES = [ "10.254.3.0/27", "10.254.4.0/27", "10.254.5.0/27", "10.254.6.0/27", "10.254.7.0/27", "10.254.8.0/27", "10.254.9.0/27", "10.254.47.0/27", "10.254.19.0/24", "10.254.22.0/27", "10.254.23.0/27", "10.254.24.0/27",  "10.254.25.0/27", "10.254.26.0/27", "10.254.27.0/27", "10.254.28.0/27",  "10.254.29.0/27", "10.254.30.0/27", "10.254.31.0/27", "10.254.32.0/27", "10.254.33.0/27", "10.254.34.0/27", "10.254.35.0/27", "10.254.36.0/27", "10.254.37.0/27", "10.254.38.0/27", "10.254.39.0/27", "10.254.40.0/27", "10.254.41.0/27", "10.254.42.0/27", "10.254.43.0/27", "10.254.45.0/27", "10.254.46.0/27", "10.254.48.0/27", "10.254.99.0/27"]
            for lan in LANFRANCHISES:
                SourcesIps[0].append(indSource)
                SourcesIps[1].append(lan)

        if "Groupe-SIEGE-LAN-DHCP" in s:
            LANDHCP = ["172.23.0.0/20", "172.23.16.0/22", "172.23.28.0/22", "172.23.32.0/22", "172.23.36.0/22"]
            for lan in LANDHCP:
                SourcesIps[0].append(indSource)
                SourcesIps[1].append(lan)

        if "GROUPE-PREP-V3-WWW/SECURE" in s:
            LANPREPV3 = ["172.17.50.41/32", "172.17.50.116/32", "172.17.50.26/32", "172.17.50.171/32", "172.17.50.51/32", "172.17.50.26/32", "172.17.50.56/32","172.17.50.111/32"]
            for lan in LANPREPV3:
                SourcesIps[0].append(indSource)
                SourcesIps[1].append(lan)

        if "LAN SQ" in s:
            LANSQ = ["10.200.100.0/22","10.200.101.0/22","10.200.102.0/22","10.200.103.0/22"]
            for lan in LANSQ:
                SourcesIps[0].append(indSource)
                SourcesIps[1].append(lan)

        if "all" in s :
            SourcesIps[0].append(indSource)
            SourcesIps[1].append("all")

        if "/" not in s:
            ipAccess = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)
            for IP in ipAccess:
                if IP != '':
                    IP = IP + "/32"
                    SourcesIps[0].append(indSource)
                    SourcesIps[1].append(IP)

        if "/" in s:
            ip = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d\d?)', s)
            for IP in ip:
                if IP != '':
                    SourcesIps[0].append(indSource)
                    SourcesIps[1].append(IP)


        indSource = indSource + 1


    for s in DestinationsTab:

        if "GROUPE LANS FRANCHISES" in s:
            LANFRANCHISES = [ "10.254.3.0/27", "10.254.4.0/27", "10.254.5.0/27", "10.254.6.0/27", "10.254.7.0/27", "10.254.8.0/27", "10.254.9.0/27", "10.254.47.0/27", "10.254.19.0/24", "10.254.22.0/27", "10.254.23.0/27", "10.254.24.0/27",  "10.254.25.0/27", "10.254.26.0/27", "10.254.27.0/27", "10.254.28.0/27",  "10.254.29.0/27", "10.254.30.0/27", "10.254.31.0/27", "10.254.32.0/27", "10.254.33.0/27", "10.254.34.0/27", "10.254.35.0/27", "10.254.36.0/27", "10.254.37.0/27", "10.254.38.0/27", "10.254.39.0/27", "10.254.40.0/27", "10.254.41.0/27", "10.254.42.0/27", "10.254.43.0/27", "10.254.45.0/27", "10.254.46.0/27", "10.254.48.0/27", "10.254.99.0/27"]
            for lan in LANFRANCHISES:
                DestIps[0].append(indDest)
                DestIps[1].append(lan)

        if "Groupe-SIEGE-LAN-DHCP" in s:
            LANDHCP = ["172.23.0.0/20", "172.23.16.0/22", "172.23.28.0/22", "172.23.32.0/22", "172.23.36.0/22"]
            for lan in LANDHCP:
                DestIps[0].append(indDest)
                DestIps[1].append(lan)

        if "LAN SQ" in s:
            LANSQ = ["10.200.100.0/22","10.200.101.0/22","10.200.102.0/22","10.200.103.0/22"]
            for lan in LANSQ:
                DestIps[0].append(indDest)
                DestIps[1].append(lan)

        if "GROUPE-PREP-V3-WWW/SECURE" in s:
            LANPREPV3 = ["172.17.50.41/32", "172.17.50.116/32", "172.17.50.26/32", "172.17.50.171/32", "172.17.50.51/32", "172.17.50.26/32", "172.17.50.56/32","172.17.50.111/32"]
            for lan in LANPREPV3:
                DestIps[0].append(indDest)
                DestIps[1].append(lan)
        if "all" in s :
            DestIps[0].append(indDest)
            DestIps[1].append("all")
        if "/" not in s:
            ipAccess = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)
            for IP in ipAccess:
                if IP != '':
                    IP = IP + "/32"
                    DestIps[0].append(indDest)
                    DestIps[1].append(IP)
        if "/" in s:
            ip = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d\d?)', s)
            for IP in ip:
                if IP != '':
                    DestIps[0].append(indDest)
                    DestIps[1].append(IP)

        indDest = indDest + 1

    for s in ServicesTab:
        serv = re.findall('"([^"]*)"', s)
        ServIps.append(serv)

    for s in IDTab:
        ids = re.sub("[^0-9]", "", s)
        IDSTab.append(ids)

    for s in SourceZoneTab:
        if "INTERCO - SIEGE-VEN300" in s :
            src = "VENISSIEUX"
            SourcesZonesTab.append(src)
        elif "VLAN4" in s :
            src = "VLAN4 (SVR-DEV SIEGE)"
            SourcesZonesTab.append(src)
        elif "SIEGE" in s:
            src = "SIEGE (Bureautique, Admin, Dev...)"
            SourcesZonesTab.append(src)
        else :
            src = re.findall('"([^"]*)"', s)
            SourcesZonesTab.append(src)

    for s in DestZoneTab:
        if "INTERCO - SIEGE-VEN300" in s :
            dst = "VENISSIEUX"
            DestsZonesTab.append(dst)
        elif "VLAN4" in s :
            dst = "VLAN4 (SVR-DEV SIEGE)"
            DestsZonesTab.append(dst)
        elif "SIEGE" in s :
            dst = "SIEGE (Bureautique, Admin, Dev...)"
            DestsZonesTab.append(dst)
        else :
            dst = re.findall('"([^"]*)"', s)
            DestsZonesTab.append(dst)



    dest = request.form['destination0']

    source = request.form['source0']

    if "/" in source and re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d\d?)', source)!=None:
        ip = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d\d?)', source)
        for IP in ip:
            SourceHost = netaddr.IPNetwork(IP)

    elif re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', source)!=None :
        ip = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', source)

        for IP in ip:
            IP = IP + "/32"
            SourceHost = netaddr.IPNetwork(IP)

    else :
        return render_template("InvalidIP.html")


    if "/" in dest and re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d\d?)', dest)!=None:
        ip = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d\d?)', dest)
        for IP in ip:
            DestHost = netaddr.IPNetwork(IP)

    elif re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', dest)!=None:
        ip = re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', dest)

        for IP in ip:
            IP = IP + "/32"
            DestHost = netaddr.IPNetwork(IP)

    else :
        return render_template("InvalidIP.html")

    indiceSource=0
    indiceDestination = 0
    increment = 0
    indiceResultTab=[]
    ResultTabSources = []
    ResultTabDestination = []
    ResultTabServices = []
    ResultTabID = []
    ResultTabSourcesZone = []
    ResultTabDestZone = []
    Rtab =[]
    j=0

    while indiceSource != len(SourcesIps[0])-1:


        if (SourcesIps[0][indiceSource] == SourcesIps[0][indiceSource+1]) and (DestIps[0][indiceDestination]!=DestIps[0][indiceDestination+1]):

            if SourcesIps[1][indiceSource] != "all" and DestIps[1][indiceDestination]!="all" :

                if ((SourceHost in netaddr.IPNetwork(SourcesIps[1][indiceSource])) or (netaddr.IPNetwork(SourcesIps[1][indiceSource]) in SourceHost)) and ((DestHost in netaddr.IPNetwork(DestIps[1][indiceDestination])) or (netaddr.IPNetwork(DestIps[1][indiceDestination]) in DestHost)) :

                    if SourcesIps[0][indiceSource] not in indiceResultTab :
                        indiceResultTab.append(SourcesIps[0][indiceSource])

            elif SourcesIps[1][indiceSource] == "all" and ((DestHost in netaddr.IPNetwork(DestIps[1][indiceDestination])) or (netaddr.IPNetwork(DestIps[1][indiceDestination]) in DestHost)):

                if SourcesIps[0][indiceSource] not in indiceResultTab:
                    indiceResultTab.append(SourcesIps[0][indiceSource])

            elif DestIps[1][indiceDestination] == "all" and ((SourceHost in netaddr.IPNetwork(SourcesIps[1][indiceSource])) or (netaddr.IPNetwork(SourcesIps[1][indiceSource]) in SourceHost)):

                if DestIps[0][indiceDestination] not in indiceResultTab:
                    indiceResultTab.append(DestIps[0][indiceDestination])
            indiceSource = indiceSource+1
            indiceDestination = indiceDestination - increment
            increment = 0

        elif (SourcesIps[0][indiceSource] != SourcesIps[0][indiceSource+1]) and (DestIps[0][indiceDestination]==DestIps[0][indiceDestination+1]):

            if SourcesIps[1][indiceSource] != "all" and DestIps[1][indiceDestination]!="all" :

                if ((SourceHost in netaddr.IPNetwork(SourcesIps[1][indiceSource])) or (netaddr.IPNetwork(SourcesIps[1][indiceSource]) in SourceHost)) and ((DestHost in netaddr.IPNetwork(DestIps[1][indiceDestination])) or (netaddr.IPNetwork(DestIps[1][indiceDestination]) in DestHost)) :

                    if SourcesIps[0][indiceSource] not in indiceResultTab :
                        indiceResultTab.append(SourcesIps[0][indiceSource])

            elif SourcesIps[1][indiceSource] == "all" and ((DestHost in netaddr.IPNetwork(DestIps[1][indiceDestination])) or (netaddr.IPNetwork(DestIps[1][indiceDestination]) in DestHost)):

                if SourcesIps[0][indiceSource] not in indiceResultTab:
                    indiceResultTab.append(SourcesIps[0][indiceSource])

            elif DestIps[1][indiceDestination] == "all" and ((SourceHost in netaddr.IPNetwork(SourcesIps[1][indiceSource])) or (netaddr.IPNetwork(SourcesIps[1][indiceSource]) in SourceHost)):

                if DestIps[0][indiceDestination] not in indiceResultTab:
                    indiceResultTab.append(DestIps[0][indiceDestination])
            indiceDestination = indiceDestination+1

        elif (SourcesIps[0][indiceSource] != SourcesIps[0][indiceSource+1]) and (DestIps[0][indiceDestination]!=DestIps[0][indiceDestination+1]):

            if SourcesIps[1][indiceSource] != "all" and DestIps[1][indiceDestination]!="all" :

                if ((SourceHost in netaddr.IPNetwork(SourcesIps[1][indiceSource])) or (netaddr.IPNetwork(SourcesIps[1][indiceSource]) in SourceHost)) and ((DestHost in netaddr.IPNetwork(DestIps[1][indiceDestination])) or (netaddr.IPNetwork(DestIps[1][indiceDestination]) in DestHost)) :

                    if SourcesIps[0][indiceSource] not in indiceResultTab :
                        indiceResultTab.append(SourcesIps[0][indiceSource])

            elif SourcesIps[1][indiceSource] == "all" and ((DestHost in netaddr.IPNetwork(DestIps[1][indiceDestination])) or (netaddr.IPNetwork(DestIps[1][indiceDestination]) in DestHost)):

                if SourcesIps[0][indiceSource] not in indiceResultTab:
                    indiceResultTab.append(SourcesIps[0][indiceSource])

            elif DestIps[1][indiceDestination] == "all" and ((SourceHost in netaddr.IPNetwork(SourcesIps[1][indiceSource])) or (netaddr.IPNetwork(SourcesIps[1][indiceSource]) in SourceHost)):

                if DestIps[0][indiceDestination] not in indiceResultTab:
                    indiceResultTab.append(DestIps[0][indiceDestination])
            indiceSource = indiceSource+1
            indiceDestination = indiceDestination + 1

        elif (SourcesIps[0][indiceSource] == SourcesIps[0][indiceSource+1]) and (DestIps[0][indiceDestination]==DestIps[0][indiceDestination+1]):

            if SourcesIps[1][indiceSource] != "all" and DestIps[1][indiceDestination]!="all" :

                if ((SourceHost in netaddr.IPNetwork(SourcesIps[1][indiceSource])) or (netaddr.IPNetwork(SourcesIps[1][indiceSource]) in SourceHost)) and ((DestHost in netaddr.IPNetwork(DestIps[1][indiceDestination])) or (netaddr.IPNetwork(DestIps[1][indiceDestination]) in DestHost)) :

                    if SourcesIps[0][indiceSource] not in indiceResultTab :
                        indiceResultTab.append(SourcesIps[0][indiceSource])

            elif SourcesIps[1][indiceSource] == "all" and ((DestHost in netaddr.IPNetwork(DestIps[1][indiceDestination])) or (netaddr.IPNetwork(DestIps[1][indiceDestination]) in DestHost)):

                if SourcesIps[0][indiceSource] not in indiceResultTab:
                    indiceResultTab.append(SourcesIps[0][indiceSource])

            elif DestIps[1][indiceDestination] == "all" and ((SourceHost in netaddr.IPNetwork(SourcesIps[1][indiceSource])) or (netaddr.IPNetwork(SourcesIps[1][indiceSource]) in SourceHost)):

                if DestIps[0][indiceDestination] not in indiceResultTab:
                    indiceResultTab.append(DestIps[0][indiceDestination])

            indiceDestination = indiceDestination + 1
            increment = increment + 1




    for i in range(0,len(SourcesIps[1])-1):

        if SourcesIps[1][i] != "all":
            if (SourcesIps[0][i] in indiceResultTab) and ((SourceHost in netaddr.IPNetwork(SourcesIps[1][i])) or (netaddr.IPNetwork(SourcesIps[1][i]) in SourceHost)) :


               if SourcesIps[0][i]!= indiceResultTab[j]:

                   ResultTabSources.append(Rtab)
                   Rtab = []
                   Rtab.append(SourcesIps[1][i])
                   j = j + 1
               else:
                   Rtab.append(SourcesIps[1][i])

        elif SourcesIps[1][i] == "all":

            if (SourcesIps[0][i] in indiceResultTab):

                if SourcesIps[0][i] != indiceResultTab[j]:

                    ResultTabSources.append(Rtab)
                    Rtab = []
                    Rtab.append(SourcesIps[1][i])
                    j = j + 1
                else:
                    Rtab.append(SourcesIps[1][i])


    ResultTabSources.append(Rtab)
    j=0
    Rtab=[]

    for i in range(0,len(DestIps[1])):
        if DestIps[1][i] != "all":
            if (DestIps[0][i] in indiceResultTab) and ((DestHost in netaddr.IPNetwork(DestIps[1][i])) or (netaddr.IPNetwork(DestIps[1][i]) in DestHost)):


                if DestIps[0][i] != indiceResultTab[j]:

                    ResultTabDestination.append(Rtab)

                    Rtab = []
                    Rtab.append(DestIps[1][i])
                    ResultTabServices.append(ServIps[DestIps[0][i]])
                    ResultTabID.append(IDSTab[DestIps[0][i]])
                    ResultTabSourcesZone.append(SourcesZonesTab[DestIps[0][i]])
                    ResultTabDestZone.append(DestsZonesTab[DestIps[0][i]])
                    j = j + 1
                else :
                    Rtab.append(DestIps[1][i])


        elif DestIps[1][i] == "all":

            if (DestIps[0][i] in indiceResultTab):

                if DestIps[0][i] != indiceResultTab[j]:

                    ResultTabDestination.append(Rtab)

                    Rtab = []
                    Rtab.append(DestIps[1][i])
                    ResultTabServices.append(ServIps[DestIps[0][i]])
                    ResultTabID.append(IDSTab[DestIps[0][i]])
                    ResultTabSourcesZone.append(SourcesZonesTab[DestIps[0][i]])
                    ResultTabDestZone.append(DestsZonesTab[DestIps[0][i]])
                    j = j + 1

                else:

                    Rtab.append(DestIps[1][i])








    ResultTabDestination.append(Rtab)
    ResultTabServices.append(ServIps[DestIps[0][i]])
    ResultTabID.append(IDSTab[DestIps[0][i]])
    ResultTabSourcesZone.append(SourcesZonesTab[DestIps[0][i]])
    ResultTabDestZone.append(DestsZonesTab[DestIps[0][i]])







    return render_template("RepertorierFlux.html", sources= ResultTabSources, destinations= ResultTabDestination, services=ResultTabServices, ids=ResultTabID, sourcezone=ResultTabSourcesZone, destinationzone=ResultTabDestZone)










if __name__ == "__main__":
    app.run(debug=True)
