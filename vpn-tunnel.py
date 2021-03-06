#!/usr/bin/env python
import os
import sys
import boto3
import xmltodict
from jinja2 import Template

profile = sys.argv[1]
vpnid = sys.argv[2]
routing = sys.argv[3]
mylocalip = os.environ.get("myip","")
localcidr = os.environ.get("mylocalcidr","")
remotecidr = os.environ.get("myremotecidr","")

s = boto3.Session(profile_name=profile)
ec2 = s.client('ec2')

vpn = ec2.describe_vpn_connections(
    VpnConnectionIds=[
        vpnid,
    ]
)

x = vpn['VpnConnections'][0]['CustomerGatewayConfiguration']

d = xmltodict.parse(x)

tunnels = d['vpn_connection']['ipsec_tunnel']

with open('racoon_conf.tmpl') as f:
    racoon_conf = f.read()
with open('ipsec_tools_conf.tmpl') as f:
    ipsec_tools_conf = f.read()
with open('ipsec_conf_fsw.tmpl') as f:
    ipsec_conf_fsw = f.read()
with open('ipsec_conf_osw.tmpl') as f:
    ipsec_conf_osw = f.read()
with open('bgpd_conf.tmpl') as f:
    bgpd_conf = f.read()
with open('rc_conf.tmpl') as f:
    rc_conf = f.read()
tnum = 1
templaterac = Template(racoon_conf)
templateips = Template(ipsec_tools_conf)
templatefsw = Template(ipsec_conf_fsw)
templateosw = Template(ipsec_conf_osw)
templatequa = Template(bgpd_conf)
templaterc = Template(rc_conf)

for tun in tunnels:
    cgw_out_addr = tun['customer_gateway']['tunnel_outside_address']['ip_address']
    cgw_in_addr = tun['customer_gateway']['tunnel_inside_address']['ip_address']
    cgw_in_cidr = tun['customer_gateway']['tunnel_inside_address']['network_cidr']
    if routing != 'static':
        cgw_bgp_asn = tun['customer_gateway']['bgp']['asn']
        cgw_bgp_ht = tun['customer_gateway']['bgp']['hold_time']
        vgw_bgp_asn = tun['vpn_gateway']['bgp']['asn']
        vgw_bgp_ht = tun['vpn_gateway']['bgp']['hold_time']
    vgw_out_addr = tun['vpn_gateway']['tunnel_outside_address']['ip_address']
    vgw_in_addr = tun['vpn_gateway']['tunnel_inside_address']['ip_address']
    vgw_in_cidr = tun['vpn_gateway']['tunnel_inside_address']['network_cidr']
    ike_authentication_protocol = tun['ike']['authentication_protocol']
    ike_encryption_protocol = ''.join(tun['ike']['encryption_protocol'].split('-')[:2])
    ike_lifetime = tun['ike']['lifetime']
    ike_perfect_forward_secrecy = tun['ike']['perfect_forward_secrecy'][-1]
    ike_mode = tun['ike']['mode']
    ike_pre_shared_key = tun['ike']['pre_shared_key']
    ipsec_protocol = tun['ipsec']['protocol']
    ipsec_authentication_protocol = tun['ipsec']['authentication_protocol']
    ipsec_encryption_protocol = ''.join(tun['ipsec']['encryption_protocol'].split('-')[:2])
    ipsec_lifetime = tun['ipsec']['lifetime']
    ipsec_perfect_forward_secrecy = tun['ipsec']['perfect_forward_secrecy'][-1]
    ipsec_mode = tun['ipsec']['mode']
    ipsec_clear_df_bit = tun['ipsec']['clear_df_bit']
    ipsec_fragmentation_before_encryption = tun['ipsec']['fragmentation_before_encryption']
    ipsec_tcp_mss_adjustment = tun['ipsec']['tcp_mss_adjustment']
    dpd_delay = tun['ipsec']['dead_peer_detection']['interval']
    dpd_retry = tun['ipsec']['dead_peer_detection']['retries']
    sys.stdout = open('psk.txt', 'a')
    print('{1}\t{2}'.format(profile.title(), vgw_out_addr, ike_pre_shared_key))
    sys.stdout = open('ipsec.secrets.txt', 'a')
    print('{1} {2} : PSK "{3}"'.format(profile.title(), cgw_out_addr, vgw_out_addr, ike_pre_shared_key))
    sys.stdout = open('racoon.conf.txt', 'a')
    print(templaterac.render(
    tnum = tnum,
    vgw_out_addr = vgw_out_addr,
    ike_mode = ike_mode,
    ike_lifetime = ike_lifetime,
    ike_encryption_protocol = ike_encryption_protocol,
    ike_authentication_protocol = ike_authentication_protocol,
    ike_perfect_forward_secrecy = ike_perfect_forward_secrecy,
    dpd_delay = dpd_delay,
    dpd_retry = dpd_retry,
    cgw_in_addr = cgw_in_addr,
    cgw_in_cidr = cgw_in_cidr,
    vgw_in_addr = vgw_in_addr,
    vgw_in_cidr = vgw_in_cidr,
    mylocalip = mylocalip,
    cgw_out_addr = cgw_out_addr,
    ipsec_perfect_forward_secrecy = ipsec_perfect_forward_secrecy,
    ipsec_encryption_protocol = ipsec_encryption_protocol,
    ipsec_authentication_protocol = '_'.join(ipsec_authentication_protocol.split('-')[:2]),
    ipsec_lifetime = ipsec_lifetime
        ))
    sys.stdout = open('ipsec-tools.conf.txt', 'a')
    print(templateips.render(
    tnum = tnum,
    localcidr = localcidr,
    remotecidr = remotecidr,
    cgw_in_addr = cgw_in_addr,
    cgw_in_cidr = cgw_in_cidr,
    vgw_in_addr = vgw_in_addr,
    vgw_in_cidr = vgw_in_cidr,
    mylocalip = mylocalip,
    cgw_out_addr = cgw_out_addr,
    vgw_out_addr = vgw_out_addr
        ))
    sys.stdout = open('ipsec_conf.txt', 'a')
    print('#tunnel#{0}\n'.format(tnum))
    print(templatefsw.render(
    tnum = tnum,
    cgw_out_addr = cgw_out_addr,
    vgw_out_addr = vgw_out_addr,
    cgw_in_addr = cgw_in_addr,
    cgw_in_cidr = cgw_in_cidr,
    vgw_in_addr = vgw_in_addr,
    vgw_in_cidr = vgw_in_cidr,
    ike_encryption_protocol = ike_encryption_protocol,
    ike_authentication_protocol = ike_authentication_protocol,
    ike_lifetime = int(ike_lifetime)/3600,
    ipsec_encryption_protocol = ipsec_encryption_protocol,
    ipsec_authentication_protocol = (ipsec_authentication_protocol.split('-')[1]),
    ipsec_lifetime = int(ipsec_lifetime)/3600,
    dpd_delay = int(dpd_delay),
    dpdtimeout = int(dpd_retry)*int(dpd_delay)
        ))
    sys.stdout = open('ipsec.conf.txt', 'a')
    print('#tunnel#{0}\n'.format(tnum))
    print(templateosw.render(
    tnum = tnum,
    cgw_out_addr = cgw_out_addr,
    vgw_out_addr = vgw_out_addr,
    cgw_in_addr = cgw_in_addr,
    cgw_in_cidr = cgw_in_cidr,
    vgw_in_addr = vgw_in_addr,
    vgw_in_cidr = vgw_in_cidr,
    ike_encryption_protocol = ike_encryption_protocol,
    ike_authentication_protocol = ike_authentication_protocol,
    ike_lifetime = ike_lifetime,
    ipsec_encryption_protocol = ipsec_encryption_protocol,
    ipsec_authentication_protocol = (ipsec_authentication_protocol.split('-')[1]),
    ipsec_lifetime = ipsec_lifetime,
    dpd_delay = int(dpd_delay),
    dpdtimeout = int(dpd_retry)*int(dpd_delay)
        ))
    sys.stdout = open('rcconf.conf.txt', 'a')
    print(templaterc.render(
    tnum = tnum,
    cgw_in_addr = cgw_in_addr,
    vgw_in_addr = vgw_in_addr,
    mylocalip = mylocalip,
    cgw_out_addr = cgw_out_addr,
    vgw_out_addr = vgw_out_addr
        ))
    if routing != 'static':
        sys.stdout = open('bgpd.conf.txt', 'a')
        print('! tunnel #{0}\n'.format(tnum))
        print(templatequa.render(
        tnum = tnum,
        cgw_bgp_asn = cgw_bgp_asn,
        vgw_in_addr = vgw_in_addr,
        vgw_bgp_asn = vgw_bgp_asn
            ))
        print('\n')
    tnum += 1
f.close()

