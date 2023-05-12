#!/usr/bin/env python3
# coding:  utf-8

#-:-:-:-:-:-:-:-:-:-:-:-:#
#    TIDoS Framework     #
#-:-:-:-:-:-:-:-:-:-:-:-:#

#Author : @_tID
#This module requires TIDoS Framework
#https://github.com/0xInfection/TIDoS-Framework


import os
from time import sleep
from core.Core.colors import *
from core.database.database_module import save_data
from core.variables import database
from core.methods.cache import targetname
import inspect

info = "Traceroute module."
searchinfo = "Traceroute module"
properties = {}

#TODO DB saving
def traceroute(web):
    name = targetname(web)
    lvl2 = "traceroute"
    module = "ReconANDOSINT"
    lvl1 = "Active Reconnaissance"
    lvl3 = ""
    #print(R+'\n   =====================')
    #print(R+'    T R A C E R O U T E')
    #print(R+'   =====================\n')
    from core.methods.print import posintact
    posintact("traceroute") 

    web = web.replace('https://','')
    web = web.replace('http://','')
    m = input(f'{C} [?] Do you want to fragment the packets? (y/n) :> ')
    if m in ['y', 'Y']:
        print(f'{GR} [!] Using fragmented packets...')
        p = input(f'{C} [§] Enter the network type to be used [(I)CMP/(T)CP] :> ')
        if p in ['icmp', 'ICMP', 'I', 'i']:
            print(GR+' [*] Using ICMP ECHO type for traceroute...')
            w = input(C+' [*] Enable socket level debugging? (y/n) :> ')
            if w in ['y', 'Y']:
                print(GR+' [+] Enabling socket level debugging...')
                sleep(0.3)
                print(GR+' [+] Starting traceroute...'+C)
                os.system('traceroute -I -d '+web)
            elif w in ['n', 'N']:
                sleep(0.3)
                print(GR+' [+] Starting traceroute...'+C)
                os.system('traceroute -I '+web)
            else:
                print(R+' [-] Invalid choice...')
                traceroute(web)
        elif p in ['tcp', 'TCP', 't', 'T']:
            print(GR+' [*] Using TCP/SYN for traceroute...')
            w = input(C+' [*] Enable socket level debugging? (y/n) :> ')
            if w in ['y', 'Y']:
                print(GR+' [+] Enabling socket level debugging...')
                sleep(0.3)
                print(GR+' [+] Starting traceroute...'+C)
                os.system('traceroute -T -d '+web)
            elif w in ['n', 'N']:
                sleep(0.3)
                print(GR+' [+] Starting traceroute...'+C)
                os.system('traceroute -T '+web)
            else:
                print(R+' [-] Invalid choice...')
                traceroute(web)
        else:
            print(R+' [-] Invalid choice...')
            traceroute(web)
    elif m in ['n', 'N']:
        print(GR+' [!] Using unfragmented packets...')
        p = input(C+' [§] Enter the network type to be used (ICMP/TCP) :> ')
        if p in ['icmp', 'ICMP', 'I', 'i']:
            print(GR+' [*] Using ICMP ECHO type for traceroute...')
            w = input(C+' [*] Enable socket level debugging? (y/n) :> ')
            if w in ['y', 'Y']:
                print(GR+' [+] Enabling socket level debugging...')
                sleep(0.3)
                print(GR+' [+] Starting traceroute...'+C)
                os.system('traceroute -I -d -F '+web)
            elif w in ['n', 'N']:
                sleep(0.3)
                print(GR+' [+] Starting traceroute...'+C)
                os.system('traceroute -I -F '+web)
            else:
                print(R+' [-] Invalid choice...')
                traceroute(web)
        elif p in ['tcp', 'TCP', 't', 'T']:
            print(GR+' [*] Using TCP/SYN for traceroute...')
            w = input(C+' [*] Enable socket level debugging? (y/n) :> ')
            if w in ['y', 'Y']:
                print(GR+' [+] Enabling socket level debugging...')
                sleep(0.3)
                print(GR+' [+] Starting traceroute...'+C)
                os.system('traceroute -T -d -F '+web)
            elif w in ['n', 'N']:
                sleep(0.3)
                print(GR+' [+] Starting traceroute...'+C)
                os.system('traceroute -T -F '+web)
            else:
                print(R+' [-] Invalid choice...')
                traceroute(web)
        else:
            print(R+' [-] Invalid choice...')
            traceroute(web)
    else:
        print(R+' [-] Invalid choice...')
        traceroute(web)

    print(G+' [+] Traceroute done.'+C+color.TR2+C+'\n')

def attack(web):
    web = web.fullurl
    traceroute(web)