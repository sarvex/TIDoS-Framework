#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#-:-:-:-:-:-:-:-:-:-:-:-:#
#    TIDoS Framework     #
#-:-:-:-:-:-:-:-:-:-:-:-:#

#Author : @_tID
#This module requires TIDoS Framework
#https://github.com/0xInfection/TIDoS-Framework


import urllib
from core.Core.colors import *
from cgi import escape
from time import sleep
try:
    import StringIO # python2
except ImportError:
    from io import StringIO
    # python3
import gzip
import os

info = "This module encodes the input to an encoding of your choosing."
searchinfo = "String Encoder"
properties = {}

def url0x00(url):

    encoded = urllib.quote_plus(url)
    print(f"{G} [+] Encoded string : {O}", encoded)

def html0x00(st):

    encod = ''
    stri = list(st)
    for i in stri:
        encod = encod + escape(i)
    print(f'{G} [+] Encoded String : {O}', encod)

def base640x00(st):

    m = st.encode('base64', 'strict')
    print(f'{G} [+] Encoded String : {O}{m}')

def ascii0x00(st):

    m = st.decode('unicode_escape')
    print(f'{G} [+] Encoded String : {O}{m}')

def hex0x00(st):

    m = st.encode('hex', 'strict')
    print(f'{G} [+] Encoded String : {O}{m}')

def octal0x00(st):

    result = ['\%o' % ord(char) for char in st]
    print(f'{G} [+] Octal Encoded String : {O}' + ''.join(result))

def binary0x00(st):

    m = ''.join(format(ord(x),'b') for x in st)
    print(f'{G} [+] Encoded String : {O}{m}')

def gzip0x00(st):

    m = st.encode('zlib','strict')
    print(f'{G} [+] Encoded String : {O}{m}')


def encodeall():
    try:
        #print(R+'\n    =============================')
        print(R+'\n     S T R I N G   E N C O D E R')
        print(R+'    ---<>----<>----<>----<>----<>\n')

        st = input(f'{O} [-] Enter a string to be encoded :> ')

        def encode0x00(st):
            print(O+'\n  Choose from the options to encode to:\n')
            print(f'{B}    [1]{C} URL Encode')
            print(f'{B}    [2]{C} HTML Encode')
            print(f'{B}    [3]{C} Base64 Encode')
            print(f'{B}    [4]{C} Plain ASCII Encode')
            print(f'{B}    [5]{C} Hex Encode')
            print(f'{B}    [6]{C} Octal Encode')
            print(f'{B}    [7]{C} Binary Encode')
            print(f'{B}    [8]{C}' + ' GZip Encode\n')
            print(f'{B}    [99]{C}' + ' Back\n')
            r = input(f'{O} [§] Enter your option :> ')
            print(f'{GR} [*] Encoding string...')
            sleep(0.5)
            if r == '1':
                url0x00(st)
                input(O+'\n [+] Press '+GR+'Enter'+O+' to Continue...')
                encode0x00(st)
            elif r == '2':
                html0x00(st)
                input(O+'\n [+] Press '+GR+'Enter'+O+' to Continue...')
                encode0x00(st)
            elif r == '3':
                base640x00(st)
                input(O+'\n [+] Press '+GR+'Enter'+O+' to Continue...')
                encode0x00(st)
            elif r == '4':
                ascii0x00(st)
                input(O+'\n [+] Press '+GR+'Enter'+O+' to Continue...')
                encode0x00(st)
            elif r == '5':
                hex0x00(st)
                input(O+'\n [+] Press '+GR+'Enter'+O+' to Continue...')
                encode0x00(st)
            elif r == '6':
                octal0x00(st)
                input(O+'\n [+] Press '+GR+'Enter'+O+' to Continue...')
                encode0x00(st)
            elif r == '7':
                binary0x00(st)
                input(O+'\n [+] Press '+GR+'Enter'+O+' to Continue...')
                encode0x00(st)
            elif r == '8':
                gzip0x00(st)
                input(O+'\n [+] Press '+GR+'Enter'+O+' to Continue...')
                encode0x00(st)
            elif r == '99':
                print(f'{G} [+] Back!')
                os.system('clear')

        encode0x00(st)

    except Exception as e:
        print(f"{R} [-] Caught Exception : {str(e)}")

def attack(web):
    encodeall()
