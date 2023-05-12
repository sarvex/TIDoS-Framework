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


def listsplit(l, n):
    """Yield successive n-sized chunks from l."""
    if n == 0:
        n += 1
    for i in range(0, len(l), n):
        yield l[i:i + n] 

def file2list(path):
    lines = []
    with open(path, "r") as f:
        lines.extend(line.strip("\n") for line in f)
    return lines
