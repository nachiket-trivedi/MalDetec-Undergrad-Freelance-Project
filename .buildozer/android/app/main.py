from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
import dpkt
import subprocess
import os
import shutil
import time
import json
import urllib
import urllib2
import simplejson
import sys
import requests

class MalDetec(App):

    def main(self, event):
        self.label.text = "Process Started!"
        global Api_Key
        global lPointer
        Api_Key = "17c467e4ef26c07369d5c021afbdba97de192970c2f559632d29acd6a3c23ed5"
        lPointer=-1

        # if not os.path.exists('/storage/emulated/0/MalDetec'):
        #     os.makedirs('/storage/emulated/0/MalDetec/dump')
        # else:
        #     shutil.rmtree('/storage/emulated/0/MalDetec', ignore_errors=False, onerror=None)
        #     os.makedirs('/storage/emulated/0/MalDetec/dump')
        # fork1=os.fork()
        # if fork1==0:
        #     fork2=os.fork()
        #     if fork2>0:
        #         self.n1()
        #     elif fork2==0:
        #         self.n2()
        # elif fork1>0:
        #     fork4=os.fork()
        #     if fork4==0:
        #         time.sleep(20)
        #         for x in range(1,100):
        #             self.merging()
        #             time.sleep(3)
        #     elif fork4>0:
        #         time.sleep(25)
        f1=os.fork()
        if f1==0:
            self.scan()
            time.sleep(3)

    def build(self):
        layout = BoxLayout(orientation='vertical')
        blue = (0, 0, 2, 2.5)
        red = (2, 0, 0, 2.5)
        green = (0, 1.5, 0, 2.5)
        btnStart =  Button(text='Start', background_color=blue, font_size=120)
        btnStop =  Button(text='Stop', background_color=red, font_size=120)
        btnStart.bind(on_press=self.main)
        btnStop.bind(on_press=self.stop)
        self.label = Label(text="The results will be displayed here", background_color=blue, font_size='15sp')
        layout.add_widget(btnStart)
        layout.add_widget(btnStop)
        layout.add_widget(self.label)
        return layout

    def stop(self, event):
        self.label.text = "The results will be displayed here"
        #App.get_running_app().stop()

    def n1(self):
        tLast=0
        pFinal=0
        s1_final=open("/storage/emulated/0/MalDetec/s1_final.txt","w")
        while True:
            files = [os.path.join('/storage/emulated/0/Android/data/jp.co.taosoftware.android.packetcapture/files/', x) for x in os.listdir('/storage/emulated/0/Android/data/jp.co.taosoftware.android.packetcapture/files/')]
            mxFile = max(files , key = os.path.getctime)
            f = open(mxFile,'r')
            pcap = dpkt.pcap.Reader(f)
            lst=set()
            for ts, buf in pcap:
                if pcap.datalink() == dpkt.pcap.DLT_EN10MB :
                    eth = dpkt.ethernet.Ethernet(buf)
                else:
                    eth = dpkt.sll.SLL(raw_pkt)
                if eth.type!=2048 or eth.type!=dpkt.ethernet.ETH_TYPE_IP: #For ipv4, dpkt.ethernet.Ethernet(buf).type =2048
                    continue
                ip=eth.data
                if ip.p!=6 or ip.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                    continue
                tcp=ip.data
                if type(tcp)!=str: #tcp.__class__.__name__ == 'TCP' can be added here
                    if (tcp.dport == 80 or tcp.dport == 443) and len(tcp.data) > 0:# u can add tcp port 8080 here
                        try:
                            http1 = dpkt.http.Request(tcp.data)
                            if http1.uri!='/_ping':
                                time=float(ts)
                                intpart,decpart = int(time),time-int(time)
                                if decpart>=0.5:
                                    tFinal=str(intpart+1)
                                else:
                                    tFinal=str(intpart)
                                if tFinal<tLast or (tFinal==tLast and pFinal==str((hex(tcp.sport).split('x')[-1])).upper()):
                                    continue
                                tLast=tFinal
                                s1_final.write("t "+tFinal)
                                s1_final.write('\n')
                                pFinal=str((hex(tcp.sport).split('x')[-1])).upper()
                                s1_final.write("p "+pFinal)
                                lst.add(str((hex(tcp.sport).split('x')[-1])).upper())
                                s1_final.write('\n')
                                s1_final.write("u "+(http1.headers['host'] + http1.uri))
                                s1_final.write('\n')
                                s1_final.write('\n')
                        except Exception as e: #previously it was except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                            continue
            f.close()

    def n2(self):
        fork3=os.fork()
        if fork3==0:#i=1;while true;i=$(($i+1)) to use if below one fails
            sh="""for i in `seq 1 1000`
            do
            date +%s > /storage/emulated/0/MalDetec/dump/netdump$i.txt
            cat /proc/net/tcp6 >> /storage/emulated/0/MalDetec/dump/netdump$i.txt #what happens when its tcp
            sleep 1
            done"""
            os.system(sh)
        else:
            s2_final=open("/storage/emulated/0/MalDetec/s2_final.txt","w")
            listt=set()
            time.sleep(1)
            while True:
                time.sleep(0.7)
                files = [os.path.join('/storage/emulated/0/MalDetec/dump/', x) for x in os.listdir('/storage/emulated/0/MalDetec/dump/')]
                mxFile = max(files , key = os.path.getctime)
                f = open(mxFile,'r')
                c=0
                lns=f.readlines()
                for line in lns:
                    words=line.split()
                    c=c+1
                    if c==1:
                        s2_final.write("t "+line)
                        continue
                    if words[0]=='sl':
                        continue
                    d=0
                    for word in line.split():
                        d=d+1
                        if d==2:
                            list=word.split(":")
                            s2_final.write(list[1])
                            s2_final.write(" ")
                        elif d==8:#here uid to app name conversion is to be done
                			s2_final.write(word+"\n")
                			break
                f.close()
            s2_final.close()

    def merging(self):
        s3_temp=open("/storage/emulated/0/MalDetec/s3_temp.txt","w")
        thelist=set()
        time=0
        t2=0
        pu11=dict()
        # s2_final=open("/storage/emulated/0/MalDetec/s2_final.txt","r")
        # s2_f=open("/storage/emulated/0/MalDetec/temp_s2_final.txt","w")
        # for line in s2_final.readlines():
        #     s2_f.write(str(line))
        # s2_f.close()
        # s1_final=open("/storage/emulated/0/MalDetec/s1_final.txt","r")
        # s1_f=open("/storage/emulated/0/MalDetec/temp_s1_final.txt","w")
        # for line in s1_final.readlines():
        #     s1_f.write(str(line))
        # s1_f.close()
        #s2_f=open("/storage/emulated/0/MalDetec/temp_s2_final.txt","r")
        s2_f=open("/storage/emulated/0/MalDetec/s2_final.txt","r")
        for line in s2_f.readlines():
            words=line.split()
            if len(words)==2 and words[0]=='t':
                t2=words[1]
                #s1_f=open("/storage/emulated/0/MalDetec/temp_s1_final.txt","r")
                s1_f=open("/storage/emulated/0/MalDetec/s1_final.txt","r")
                pu1=dict()
                b=0
                p,u="",""
                for lne in s1_f.readlines() :
                    word=lne.split()
                    if len(word)==2 and word[0]=='t' and word[1]==t2:
                        b=1
                        continue
                    if b==1:
                        if word[0]=='p':
                            p=word[1]
                        elif word[0]=='u':
                            u=word[1]
                            b=0
                            pu1[p]=u
                pu11=pu1
                s1_f.close()
            elif len(words)==2 and words[0]!='t':
                p2=words[0]
                a2=words[1]
                if p2 in pu11:
                    s3_temp.write("time: "+t2+"\n"+"port: "+p2+"\n"+"app: "+a2+"\n"+"url: "+pu11[p2]+"\n\n")
        s2_f.close()
        # s2_final.close()
        # s1_final.close()
        s3_temp.close()
        s3_final=open('/storage/emulated/0/MalDetec/s3_final.txt','w')
        s3_temp=open('/storage/emulated/0/MalDetec/s3_temp.txt','r')
        for line1 in s3_temp.readlines():
            s3_final.write(str(line1))
        s3_final.close()

    def scan(self):
        f=open('/storage/emulated/0/MalDetec/s3_final.txt','r')
        #f=open('/home/nachiket/Desktop/Research_work/my_project/Static_url_scanning/s3_final.txt','r')
        scan_final=open('/storage/emulated/0/MalDetec/scan_final.txt','w')
        #scan_final=open('/home/nachiket/Desktop/scan_final.txt','w')
        count=1
        for lines in f.readlines():
            scan_final.write(str(lines))
            if count<=lPointer:
                count=count+1
                scan_final.write(str(lPointer)+"\n")
                continue
            else:
                count=1000
                scan_final.write(str(lPointer)+"***\n")
            words=lines.split()
            if len(words)==2 and words[0]=='url:':
                global lPointer
                global Api_Key
                lPointer=lPointer+5
                scan_final.write(str(words[1])+" === "+str(lPointer)+"\n")
                get_link=str(words[1])
                url = "https://www.virustotal.com/vtapi/v2/url/report"
                parameters = {"resource": get_link,"apikey": Api_Key}
                data = urllib.urlencode(parameters)
                scan_final.write("1")
                # proxy = urllib2.ProxyHandler({'https': 'http://proxy:port'})
                # opener = urllib2.build_opener(proxy)
                # urllib2.install_opener(opener)
                hdr = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','User-Agent': 'Mozilla/5.0'}
                req = urllib2.Request(url,data,headers=hdr)
                scan_final.write("2")
                scan_final.write(str(req))
                try:
                    response = urllib2.urlopen(req)
                    scan_final.write("2.6")
                except:# urllib2.HTTPError, e:
                    scan_final.write("2.5")
                    #scan_final.write(str(e.fp.read()))
                scan_final.write("3")
                scan_final.write(str(response))

                # hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
                # 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                # 'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
                # 'Accept-Encoding': 'none',
                # 'Accept-Language': 'en-US,en;q=0.8',
                # 'Connection': 'keep-alive'}
                # params = {'apikey': Api_Key, 'url':'http://www.virustotal.com'}
                # response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',params=params,headers=hdr)
                # scan_final.write("3")
                # json_response = response.json()

                scan_final.write("6")
                json = response.read()
                scan_final.write("7")
                response_dict = simplejson.loads(json)
                scan_final.write("8")
                scan_id = response_dict.get("scan_id")
                scan_final.write("9")
                link = response_dict.get("url")
                scan_final.write("|Link: "+link)
                response_code = response_dict.get("response_code")
                scan_date = response_dict.get("scan_date")
                analysis = response_dict.get("permalink")
                Positives = response_dict.get("positives")
                total = response_dict.get("total")
                if response_code==1:
                    scan_final.write("|Link: "+link)
                    scan_final.write("|Scan Date: "+scan_date)
                    scan_final.write("|Scan report url: "+analysis)
                    scan_final.write("|Scanner: "+str(total)+ " Scanner.")
                    scan_final.write("|Positives: "+str(Positives))
                    scan_final.write("\n")
                time.sleep(3)
        f.close()
        scan_final.close()

MalDetec().run()
