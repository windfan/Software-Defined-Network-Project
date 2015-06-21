# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from random import randint

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]



    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # arp table: for searching
        
        self.arp_table={}
        self.arp_table["10.0.0.1"] = "00:00:00:00:00:01"
        self.arp_table["10.0.0.2"] = "00:00:00:00:00:02"
	self.mac_to_port = {}
	self.counter_add = 1
        self.counter_del = 1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)


    def add_flow(self, datapath, cookie, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
	
	# delete flow from flow table
    def del_flow(self, datapath, cookie):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, cookie_mask=0xFFFFFFFFFFFFFFFF, priority=30,
                                match=None, command=ofproto.OFPFC_DELETE, out_group=ofproto.OFPG_ANY,
				out_port = ofproto.OFPP_ANY)
        datapath.send_msg(mod)



    def handle_arp(self, datapath, in_port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # parse out the ethernet and arp packet
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        # obtain the MAC of dst IP  
        arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]

        ### generate the ARP reply msg, please refer RYU documentation
        ### the packet library section

        ether_hd = ethernet.ethernet(dst = eth_pkt.src, 
                                src = arp_resolv_mac, 
                                ethertype = ether.ETH_TYPE_ARP);
        arp_hd = arp.arp(hwtype=1, proto = 2048, hlen = 6, plen = 4,
                         opcode = 2, src_mac = arp_resolv_mac, 
                         src_ip = arp_pkt.dst_ip, dst_mac = eth_pkt.src,
                         dst_ip = arp_pkt.src_ip);
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ether_hd)
        arp_reply.add_protocol(arp_hd)
	arp_reply.serialize()
       



        
        # send the Packet Out mst to back to the host who is initilaizing the ARP
        actions = [parser.OFPActionOutput(in_port)];
        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, 
                                  ofproto.OFPP_CONTROLLER, actions,
                                  arp_reply.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
#	counter_add = 1
#    	counter_del = 1
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ethertype = eth.ethertype
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4) # parse out the IPv4 pkt
        tcp_pkt = pkt.get_protocol(tcp.tcp)
#       if pkt_tcp:
#            tcp_dst = pkt_tcp.dst_port
#            tcp_src = pkt_tcp.src_port
	

        dst = eth.dst
        src = eth.src

#        dpid = datapath.id
#        self.mac_to_port.setdefault(dpid, {})
        
        '''
        if src=='00:00:00:00:00:01' or dst=='00:00:00:00:00:01':
	       self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        '''

        # process ARP 
        if ethertype == ether.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, pkt)
            return


        

        # Adding flow entries
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
    			        ipv4_src = '10.0.0.1',
                                ipv4_dst = '10.0.0.2',
		  	        tcp_src = tcp_pkt.src_port, tcp_dst = tcp_pkt.dst_port)
        actions = [parser.OFPActionOutput(2)]
       	self.counter_add = self.counter_add + 1
        self.add_flow(datapath, self.counter_add, 30, match, actions) 

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
			  	ipv4_src = '10.0.0.2',
                                ipv4_dst = '10.0.0.1',
				tcp_src = tcp_pkt.src_port, tcp_dst = tcp_pkt.dst_port)
        actions = [parser.OFPActionOutput(1)]
       	self.counter_add = self.counter_add + 1
        self.add_flow(datapath, self.counter_add, 30, match, actions)  
            


	if self.counter_add > 100:
	    self.random1 = randint(1, 100)
	    self.random2 = randint(1, 100) 
	    if self.random1 == self.random2:
		self.random2 = self.random2 - 1
	    self.del_flow(datapath, self.random1)
	    self.del_flow(datapath, self.random2)
	    self.counter_add = self.counter_add - 2
#	    self.counter_del = self.counter_del + 2     		


        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
