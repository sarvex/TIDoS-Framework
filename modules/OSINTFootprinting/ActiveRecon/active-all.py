#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
_____, ___
   '+ .;.    
    , ;.    
     . :,  
     ;'.    
      ..    
     .;.    
      .;  
       :  
       ,   
       

┌─[TIDoS]─[]
└──╼ VainlyStrain
"""

from core.methods.select import list as modules
from core.Core.colors import R, B, C, color
import importlib as imp

info = "Launch all osint-active modules."
searchinfo = "ALL: osint-active"
properties = {}

modlist = modules("osint-active",False)

def attack(web):
    for module in modlist:
        try:
            if "-all" not in module:
                mod = imp.import_module(module)
                mod.attack(web)
        except ImportError:
            print(
                f"{R} [-] "
                + "\033[0m"
                + color.UNDERLINE
                + "\033[1m"
                + f"Failed to import module: {module}"
            )
        except Exception as e:
            print(
                f"{R} [-] "
                + "\033[0m"
                + color.UNDERLINE
                + "\033[1m"
                + f"Module {mod} failed on target {web.fullurl}:"
                + "\033[0m"
                + color.CURSIVE
                + f"\n{e}"
                + C
            )
