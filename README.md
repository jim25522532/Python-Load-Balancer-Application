# README

原作者: Pranit Yadav 
專案名稱: A round-robin load balancer application deployed on RYU controller to perform load-balancing across servers using Python
University of Colorado Boulder 
程式檔案: llb.py and pranit13extra.py  
參考文獻: https://bitbucket.org/sdnhub/ryu-starter-kit/src/7a162d81f97d080c10beb15d8653a8e0eff8a469/stateless_lb.py?at=master&fileviewer=file-view-default 

Note: llb.py and pranit13extra.py are applications present in '~/.local/lib/python2.7/site-packages/ryu/app' 

# 無狀態負載平衡演算法 

## 程式使用方法
1. Step1: 使用Mininet模擬Single Switch網路拓樸 
```
sudo mn --topo single,7 --mac --controller=remote,ip=127.0.0.1 --switch ovs,protocols=OpenFlow13
```
2. Step2: 啟動Ryu Controller
```
ryu run llb.py
```
3. Step3: 在Mininet 使用Xterm開啟7個host h1 h2 h3 h4 h5 h6 h7

```
mininet> xterm h1 h2 h3 h4 h5 h6 h7 
```

4. Step4: h1 h2 h3啟動監聽80 port (h1 h2 h3為模擬接收請求的伺服器)　, 在h1,h2,h3 xterm視窗執行底下命令
```
python -m SimpleHTTPserver 80　
```

5. 在CMD CLI利用crul tool測試 target Server IP　10.0.0.100是否有將流量導引到　h1 h2 h3伺服器上

```
curl 10.0.0.100

```
## Load Balancer架構圖

# 有狀態的負載平衡演算法
## 程式使用方法
1. Step1: 使用Mininet模擬Single Switch網路拓樸 
```
sudo mn --topo single,7 --mac --controller=remote,ip=127.0.0.1 --switch ovs,protocols=OpenFlow13
```

2. Step2: 啟動Ryu Controller
```
ryu run pranit13extra.py
```

3. 來自h4或h5的request會被Load balancer把流量導引到h1 Web Server , 來自h6 client的 requet　Load balancer將流量導引到 h2 web server ,
來自h7 client的request Load balancer將流量導引到h3 web server. 

## Load Balancer架構圖


# 關鍵程式碼

## 初始化程式碼
``` python
def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.serverlist=[]                                                              #建立Server清單
        self.virtual_lb_ip = "10.0.0.100"                                               #　負載平衡Server IP(Virtual)
        self.virtual_lb_mac = "AB:BC:CD:EF:AB:BC"                                       #　負載平衡Server MAC Address
        self.counter = 0                                                                #　使用計算方式將流量Offloading到請求服務上
        
        self.serverlist.append({'ip':"10.0.0.1", 'mac':"00:00:00:00:00:01", "outport":"1"})            #添加提供服務的Server IP與MAC Address
        self.serverlist.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02", "outport":"2"})
        self.serverlist.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03", "outport":"3"})
        print("Done with initial setup related to server list creation.")

```

## 初始化時新增Table Miss Flow Entry
``` python 
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
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

``` 
## 設定Load Balance連接的服務Server對應MAC Address
``` python

def function_for_arp_reply(self, dst_ip, dst_mac):                                      #Function placed here, source MAC and IP passed from below now become the destination for the reply ppacket 
        print("(((Entered the ARP Reply function to build a packet and reply back appropriately)))")
        arp_target_ip = dst_ip
        arp_target_mac = dst_mac
        src_ip = self.virtual_lb_ip                         #Making the load balancers IP and MAC as source IP and MAC
        src_mac = self.virtual_lb_mac

        arp_opcode = 2                          #ARP opcode is 2 for ARP reply
        hardware_type = 1                       #1 indicates Ethernet ie 10Mb
        arp_protocol = 2048                       #2048 means IPv4 packet
        ether_protocol = 2054                   #2054 indicates ARP protocol
        len_of_mac = 6                  #Indicates length of MAC in bytes
        len_of_ip = 4                   #Indicates length of IP in bytes

        pkt = packet.Packet()
        ether_frame = ethernet.ethernet(dst_mac, src_mac, ether_protocol)               #Dealing with only layer 2
        arp_reply_pkt = arp.arp(hardware_type, arp_protocol, len_of_mac, len_of_ip, arp_opcode, src_mac, src_ip, arp_target_mac, dst_ip)   #Building the ARP reply packet, dealing with layer 3
        pkt.add_protocol(ether_frame)
        pkt.add_protocol(arp_reply_pkt)
        pkt.serialize()
        print("{{{Exiting the ARP Reply Function as done with processing for ARP reply packet}}}")
        return pkt

``` 


## 負載平衡伺服器流量導引核心函數
``` python

 @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)                
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        #print("Debugging purpose dpid", dpid)
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if eth.ethertype == ether.ETH_TYPE_ARP:                                   #If the ethernet frame has eth type as 2054 indicating as ARP packet..  
            arp_header = pkt.get_protocols(arp.arp)[0]
            
            if arp_header.dst_ip == self.virtual_lb_ip and arp_header.opcode == arp.ARP_REQUEST:                 #..and if the destination is the virtual IP of the load balancer and Opcode = 1 indicating ARP Request

                reply_packet=self.function_for_arp_reply(arp_header.src_ip, arp_header.src_mac)    #Call the function that would build a packet for ARP reply passing source MAC and source IP
                actions = [parser.OFPActionOutput(in_port)]
                packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY, data=reply_packet.data, actions=actions, buffer_id=0xffffffff)    
                datapath.send_msg(packet_out)
                print("::::Sent the packet_out::::")
            return
        ip_header=[]
        tcp_header=[]
        if len(pkt.get_protocols(ipv4.ipv4))>0:
        	ip_header = pkt.get_protocols(ipv4.ipv4)[0]
        
        #print("IP_Header", ip_header)
        	tcp_header = pkt.get_protocols(tcp.tcp)[0]
    
       
        #print("TCP_Header", tcp_header)
        count = self.counter % 3                            #Round robin fashion setup
        server_ip_selected = self.serverlist[count]['ip']
        server_mac_selected = self.serverlist[count]['mac']
        server_outport_selected = self.serverlist[count]['outport']
        server_outport_selected = int(server_outport_selected)
        self.counter = self.counter + 1
        print("The selected server is ===> ", server_ip_selected)

        
        #Route to server
        if len(ip_header)>=1:
        	match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, eth_src=eth.src, eth_dst=eth.dst, ip_proto=ip_header.proto, ipv4_src=ip_header.src, ipv4_dst=ip_header.dst, tcp_src=tcp_header.src_port, tcp_dst=tcp_header.dst_port)
        	actions = [parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip), parser.OFPActionSetField(eth_src=self.virtual_lb_mac), parser.OFPActionSetField(eth_dst=server_mac_selected), parser.OFPActionSetField(ipv4_dst=server_ip_selected), parser.OFPActionOutput(server_outport_selected)]
        	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        	cookie = random.randint(0, 0xffffffffffffffff)
        	flow_mod = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=7, instructions=inst, buffer_id = msg.buffer_id, cookie=cookie)
        	datapath.send_msg(flow_mod)
        	print("<========Packet from client: "+str(ip_header.src)+". Sent to server: "+str(server_ip_selected)+", MAC: "+str(server_mac_selected)+" and on switch port: "+str(server_outport_selected)+"========>")  


        #Reverse route from server
        	match = parser.OFPMatch(in_port=server_outport_selected, eth_type=eth.ethertype, eth_src=server_mac_selected, eth_dst=self.virtual_lb_mac, ip_proto=ip_header.proto, ipv4_src=server_ip_selected, ipv4_dst=self.virtual_lb_ip, tcp_src=tcp_header.dst_port, tcp_dst=tcp_header.src_port)
        	actions = [parser.OFPActionSetField(eth_src=self.virtual_lb_mac), parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip), parser.OFPActionSetField(ipv4_dst=ip_header.src), parser.OFPActionSetField(eth_dst=eth.src), parser.OFPActionOutput(in_port)]
        	inst2 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        	cookie = random.randint(0, 0xffffffffffffffff)
        	flow_mod2 = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=7, instructions=inst2, cookie=cookie)
        	datapath.send_msg(flow_mod2)
        	print("<++++++++Reply sent from server: "+str(server_ip_selected)+", MAC: "+str(server_mac_selected)+". Via load balancer: "+str(self.virtual_lb_ip)+". To client: "+str(ip_header.src)+"++++++++>")

```
# 執行結果