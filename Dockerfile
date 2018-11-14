FROM 192.168.1.103:5000/docker-snort 
MAINTAINER chloe zhangshasha0104@outlook.com
RUN cd /etc/snort/rules
RUN echo "alert icmp any any -> any any (msg:"Pinging...";sid:1000004;)" >>local.rules
RUN snort -i eth0 -c /etc/snort/etc/snort.conf -d
 
