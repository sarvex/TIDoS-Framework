#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
_____, ___
   '+ .;    
    , ;   
     .   
           
       .    
     .;.    
     .;  
      :  
      ,   
       

┌─[TIDoS]─[]
└──╼ VainlyStrain
"""


import core.variables as vars
import importlib, socket
from core.methods.select import bareimport
from core.methods.threat import Target
from core.Core.colors import R, color

def targetparse(targetinp):
    user = ""
    passwd = ""
    ip = False
    if "https://" in targetinp:
        port = 443
    elif "http://" in targetinp:
        port = 80
    else:
        ip = True
    if not ip:
        target = targetinp.split("://")[1]
        tchk = target
        if "@" in target:
            creds = target.split("@")[0]
            user = creds.split(":")[0]
            passwd = creds.split(":")[1]
            rest = target.split("@")[1]
            tchk = rest
            if ":" in rest:
                try:
                    port = int(rest.split(":")[1])
                    tchk = rest.split(":")[0]
                except Exception as e:
                    print(e)
        elif ":" in target:
            try:
                port = int(target.split(":")[1])
                tchk = target.split(":")[0]
            except Exception as e:
                print(e)

        if str(tchk).endswith('/'):
            tchk = tchk[:-1]

        try:
            ip = socket.gethostbyname(tchk)
            parsedTarget = Target(tchk, ip)
            parsedTarget.fullurl = targetinp
            parsedTarget.port = port
            parsedTarget.urluser = user
            parsedTarget.urlpasswd = passwd
            return parsedTarget
        except socket.gaierror:
            print(
                f"{R} [-] "
                + "\033[0m"
                + color.UNDERLINE
                + "\033[1m"
                + "Target seems down..."
            )
        return None
    else:
        parsedTarget = Target(targetinp, targetinp)
        parsedTarget.fullurl = targetinp
        return parsedTarget


def targetname(fulltarget):
    return target.name if (target := targetparse(fulltarget)) else ""
        

def load(i):
    targets = []
    with open(f"core/sessioncache/{i}", "r") as f:
        targets = [line.rstrip("\n") for line in f]
    for vic in targets:
        if vic2 := targetparse(vic):
            vars.targets.append(vic2)

    
def save(i):
    with open(f"core/sessioncache/{i}", "w") as f:
        for vic in vars.targets:
            f.write(vic.fullurl)
            f.write("\n")

def sessionparse(i, load=True):
    victims = []
    modules = {}
    oneline = ""
    with open(f"core/sessioncache/{i}", "r") as file:
        for line in file:
            oneline += line
    vicblocks = oneline.split("<victim ")[1:]
    for block in vicblocks:
        block = block.split("</victim>")[0]
        victim = block.split(">")[0].strip()
        victims.append(victim)
        if load:
            if target := targetparse(victim):
                vars.targets.append(target)
        inter = block.replace(f"{victim}>", "")
        modblocks = inter.split("<module ")[1:]
        for modblock in modblocks:
            properties = {}
            module = modblock.split(">")[0].strip()
            modblock = modblock.split("</module>")[0]
            if ">" in modblock:
                modblock = modblock.split(">")[1]
            proplist = modblock.split(";")
            for proptuple in proplist:
                if ":" in proptuple:
                    prop = proptuple.split(":")[0].strip()
                    val = proptuple.split(":")[1].strip()
                    properties[prop] = val
            modules[module] = properties
    return (victims, modules)

def createVal(victims, modules, name):
    with open(f"core/sessioncache/{name}", "w") as file:
        for victim in victims:
            file.write(f"<victim {victim.fullurl}" + ">\n")
            for module in modules:
                file.write(f"  <module {module}" + ">\n")
                if "modules" in module:
                    j = importlib.import_module(module)
                else:
                    p = bareimport(module)
                    md = p[1]
                    j = importlib.import_module(md)
                properties = j.properties
                for key, value in properties.items():
                    if value[1].strip() != "":
                        file.write(f"    {key}:{value[1]};\n")
                file.write("  </module>\n")
            file.write("</victim>\n")
