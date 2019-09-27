from mininet.topo import Topo
from mininet.node import Host
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import Intf, TCLink
import time
import threading
import sys
from cmd import Cmd
from os import isatty


#h1,h2,s1,s2,h11,h22 = net.get('h1','h2','s1','s2','h11','h22')
#h1.intf( 'h1-eth0' ).config(bw = 20)
#h2.intf( 'h2-eth0' ).config(bw = 20)
#h11.intf( 'h11-eth0' ).config(bw = 20)
#h22.intf( 'h22-eth0' ).config(bw = 20)
#s1.intf('s1-eth1').config(bw = 20)
#s1.intf('s1-eth2').config(bw = 20)
#s1.intf('s1-eth3').config(bw = 20)
#s2.intf('s2-eth1').config(bw = 20)
#s2.intf('s2-eth2').config(bw = 20)
#s2.intf('s2-eth3').config(bw = 20)


#list1 = [h1,h2]
#list2 = [h11,h22]

#net.iperf(hosts=list1,l4Type = 'UDP',udpBw='30M',seconds=5,port=5002)


#net.iperf(hosts=list2,l4Type = 'UDP',udpBw='30M',seconds=5,port=5001)



#myScript = "test.sh"
#cli=CLI(net,script=myScript)

#py execfile("test.py")