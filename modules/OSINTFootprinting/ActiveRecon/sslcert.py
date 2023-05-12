#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:-:-:#
#   TIDoS Framework    #
#-:-:-:-:-:-:-:-:-:-:-:#

#Author : @_tID
#This module is a part of TIDoS Framework
#https://github.com/0xInfection/TIDoS-Framework


import socket
import ssl
import time
from core.Core.colors import *
from core.database.database_module import save_data
from core.variables import database
from core.methods.cache import targetname
import inspect

info = "Displays info on the website's certificate."
searchinfo = "SSL Cert Info"
properties = {}

def sslcert(web):
    name = targetname(web)
    if 'https' not in web:
        print(f'{R} [-] Website does not use SSL...')
    else:
        if str(web).split("/")[2]:
            web = str(web).split("/")[2]
        elif str(web).split("/")[3]:
            web = str(web).split("/")[2]
        #print(R+'\n   =========================================')
        #print(R+'    S S L   C E R T I F I C A T E   I N F O')
        #print(R+'   =========================================\n')
        from core.methods.print import posintact
        posintact("ssl certificate info")
        time.sleep(0.3)
        context = ssl.create_default_context()
        server = context.wrap_socket(socket.socket(), server_hostname=web)
        server.connect((web, 443))
        cer = server.getpeercert()
        cerpec = server.cipher()
        cerp = list(cerpec)
        sn = str(cer.get('serialNumber'))
        vers = str(cer.get('version'))
        cs = str(cerp[0])
        proto = str(cerp[1])
        etype = str(cerp[2])
        print(f"{B} [+] Certificate Serial Number : {W}{sn}")
        print(f"{B} [+] Certificate SSL Version : {W}{vers}")
        print(f'{B} [+] SSL Cipher Suite : {W}{cs}')
        print(f'{B} [+] Encryption Protocol : {W}{proto}')
        print(f'{B} [+] Encryption Type : {W}{etype} bit')
        print(B+' [+] Certificate as Raw : \n'+W+str(cer))
        data = (
            f"Serial Number :> {sn}\nVersion :> {vers}\nCipher Suite :> {cs}\n"
            + f"Encryption Protocol :> {proto}\nEncryption Type :> {etype}\n\n{str(cer)}"
        )
        lvl2 = "sslcert"
        module = "ReconANDOSINT"
        lvl1 = "Active Reconnaissance"
        lvl3 = ""
        save_data(database, module, lvl1, lvl2, lvl3, name, data)

def attack(web):
    web = web.fullurl
    sslcert(web)