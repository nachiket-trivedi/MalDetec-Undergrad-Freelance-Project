# coding=utf-8
from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.boxlayout import BoxLayout
from plyer import notification
from plyer import vibrator
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
import httplib
import ssl
import urlparse

class MalDetec(App):

    def main(self, event):
        self.label.text = "Process Started!"
        notification.notify('Process Started','Results will be displayed soon')
        vibrator.vibrate(0.2)
        if not os.path.exists('/storage/emulated/0/MalDetec'):
            os.makedirs('/storage/emulated/0/MalDetec/db')
            os.makedirs('/storage/emulated/0/MalDetec/files/dump')
            hd=open('/storage/emulated/0/MalDetec/db/hotdata.txt','w')
            hd.close()
        else:
            if os.path.exists('/storage/emulated/0/MalDetec/files'):
                shutil.rmtree('/storage/emulated/0/MalDetec/files', ignore_errors=False, onerror=None)
                os.makedirs('/storage/emulated/0/MalDetec/files/dump')
            else:
                os.makedirs('/storage/emulated/0/MalDetec/files/dump')
            if not os.path.exists('/storage/emulated/0/MalDetec/db'):
                os.makedirs('/storage/emulated/0/MalDetec/db')
                hd=open('/storage/emulated/0/MalDetec/db/hotdata.txt','w')
                hd.close()
        hd1=open('/storage/emulated/0/MalDetec/db/roughWork_scan.txt','w')
        hd1.close()
        hd1=open('/storage/emulated/0/MalDetec/db/forlaterscan_final.txt','w')
        hd1.close()
        res=open('/storage/emulated/0/MalDetec/db/results.txt','w')
        res.close()
        fork1=os.fork()
        if fork1==0:
            global Api_Key
            global lPointer
            Api_Key = "17c467e4ef26c07369d5c021afbdba97de192970c2f559632d29acd6a3c23ed5"
            lPointer=-1
            global ulist
            ulist=set()
            global scanResult
            scanResult=dict()
            fork2=os.fork()
            if fork2>0:
                self.n1()
            elif fork2==0:
                self.n2()
        elif fork1>0:
            global s3counter
            global fcounter
            s3counter=0
            fcounter=0
            fork4=os.fork()
            if fork4==0:
                time.sleep(30)
                for i in range(1,1000):
                    self.merging_lookDB()
                    time.sleep(3)
            fork5=os.fork()
            if fork5==0:
                time.sleep(40)
                # self.scan()
                for i in range(1,1000):
                    self.scan()
                    time.sleep(6)

    def build(self):
        layout = BoxLayout(orientation='vertical')
        blue = (0, 0, 2, 2.5)
        red = (2, 0, 0, 2.5)
        green = (0, 1.5, 0, 2.5)
        btnStart =  Button(text='Start', background_color=blue, font_size=120)
        btnStop =  Button(text='Stop', background_color=red, font_size=120)
        btnStart.bind(on_press=self.main)
        btnStop.bind(on_press=self.stop)
        self.label = Label(text="Welcome to MalDetec!\n\nPress Start to initiate url scanning", background_color=blue, halign='center', font_size='15sp')
        layout.add_widget(btnStart)
        layout.add_widget(btnStop)
        layout.add_widget(self.label)
        return layout

    def close(self):
        App.get_running_app().stop()

    def stop(self, event):
        self.label.text = "Stopped"

    def n1(self):
        tLast=0
        pFinal=0
        s1_final=open("/storage/emulated/0/MalDetec/files/s1_final.txt","w")
        s1_final.close()
        while True:
            s1_final=open("/storage/emulated/0/MalDetec/files/s1_final.txt","a")
            files = [os.path.join('/storage/emulated/0/Android/data/jp.co.taosoftware.android.packetcapture/files/', x) for x in os.listdir('/storage/emulated/0/Android/data/jp.co.taosoftware.android.packetcapture/files/')]
            mxFile = max(files , key = os.path.getctime)
            f = open(mxFile,"r")
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
            s1_final.close()
        s1_final.close()

    def n2(self):
        fork3=os.fork()
        if fork3>0:#i=1;while true;i=$(($i+1)) to use if below one fails
            sh="""for i in `seq 1 100000`
            do
            date +%s > /storage/emulated/0/MalDetec/files/dump/netdump$i.txt
            cat /proc/net/tcp6 >> /storage/emulated/0/MalDetec/files/dump/netdump$i.txt #what happens when its tcp
            sleep 1
            done"""
            os.system(sh)
        elif fork3==0:
            s2_final=open("/storage/emulated/0/MalDetec/files/s2_final.txt","w")
            s2_final.close()
            listt=set()
            time.sleep(2)
            inc=1
            pp=" "
            while True:
                s2_final=open("/storage/emulated/0/MalDetec/files/s2_final.txt","a")
                time.sleep(1.2)
                # files = [os.path.join('/storage/emulated/0/MalDetec/files/dump/', x) for x in os.listdir('/storage/emulated/0/MalDetec/files/dump/')]
                # mxFile = max(files , key = os.path.getctime)
                mxFile=str("/storage/emulated/0/MalDetec/files/dump/netdump%s.txt" %inc)
                inc=inc+1
                f = open(mxFile,"r")
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
                        elif d==8:
                            if str(word)=='9999' or str(word)=='0' or str(word)=='1000' or str(word)=='1001':
                                s2_final.write("\n")
                                continue
                            wrd=os.popen("cat /storage/emulated/0/MalDetec/uid_pkg_map.txt | grep -A1 userId='%s'"%word).read()
                            wrd1=wrd.split("\n")
                            p=str(wrd1[1])
                            p=p[8:-2]
                            p=p.split()[1]
                            s2_final.write(str(p))
                            s2_final.write("\n")
                            break
                f.close()
                s2_final.close()
            s2_final.close()

    def merging_lookDB(self):
        s3_temp=open("/storage/emulated/0/MalDetec/files/s3_temp.txt","w")
        thelist=set()
        time=0
        t2=0
        pu11=dict()
        s2_f=open("/storage/emulated/0/MalDetec/files/s2_final.txt","r")
        for line in s2_f.readlines():
            words=line.split()
            if len(words)==2 and words[0]=='t':
                t2=words[1]
                s1_f=open("/storage/emulated/0/MalDetec/files/s1_final.txt","r")
                pu1=dict()
                b=0
                p,u="",""
                for lne in s1_f.readlines():
                    word=lne.split()
                    if len(word)==2 and word[0]=='t' and int(word[1])==int(t2):
                        b=1
                        continue
                    elif len(word)==2 and word[0]=='t' and int(word[1])>int(t2):
                        break
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
                    # ul=str(pu11[p2]).strip()
                    ul=str(''.join(str(pu11[p2]).split()))
                    s3_temp.write("time: "+t2+"\n"+"port: "+p2+"\n"+"app: "+a2+"\n"+"url: "+str(ul)+"\n\n")
        s2_f.close()
        s3_temp.close()
        s3_final=open('/storage/emulated/0/MalDetec/files/s3_final.txt','w')
        s3_temp=open('/storage/emulated/0/MalDetec/files/s3_temp.txt','r')
        for line1 in s3_temp.readlines():
            s3_final.write(str(line1))
        s3_final.close()
        s3_temp.close()
        # DBlooking starts here
        s3_final=open('/storage/emulated/0/MalDetec/files/s3_final.txt','r')
        fls_final=open('/storage/emulated/0/MalDetec/db/forlaterscan_final.txt','a')
        results=open('/storage/emulated/0/MalDetec/db/results.txt','a')
        global s3counter
        i=0
        app=" "
        url=" "
        for lines in s3_final.readlines():
            #fls_final.write("-*"+str(i)+"\n")
            i=i+1
            if int(i)<=int(s3counter):
                continue
            words=lines.split()
            if len(words)==2 and words[0]=='app:':
                app=str(words[1])
            elif len(words)==2 and words[0]=='url:':
                # url=str(words[1]).strip()
                url=str(''.join(str(words[1]).split()))
                found=0
                wd=" "
                hdata=open('/storage/emulated/0/MalDetec/db/hotdata.txt','r')
                for liness in hdata.readlines():
                    word=liness.split()
                    if len(word)==2:
                        # wd=str(word[0]).strip()
                        wd=str(''.join(str(word[0]).split()))
                        # fls_final.write("\n****"+str(url)+"==="+str(wd)+"\n ")
                        if str(wd)==str(url):
                            found=1
                            # fls_final.write(str(app)+"****************** "+str(url)+"\n"+"\n")
                            results.write("App: "+str(app)+"\n"+"URL: "+str(url)+"\n"+"Positives: "+str(word[1])+"\n"+"\n")
                            if os.fork()==0:
                                scn="HData | App= "+str(app)
                                pos="Positives= "+str(word[1])+" | url= "+str(url)
                                notification.notify(title=str(scn),message=str(pos),timeout=1)#notify-app with its url and positives
                            if os.fork()==0:
                                vibrator.vibrate(0.2)
                            break
                hdata.close()
                if found==0:
                    fls_final.write(str(app)+" "+str(url)+"\n"+"\n")
        s3counter=i
        s3_final.close()
        fls_final.close()
        results.close()

    def scan(self):
        f=open('/storage/emulated/0/MalDetec/db/forlaterscan_final.txt','r')
        roughWork_scan=open('/storage/emulated/0/MalDetec/db/roughWork_scan.txt','a')
        hdata=open('/storage/emulated/0/MalDetec/db/hotdata.txt','a')
        results=open('/storage/emulated/0/MalDetec/db/results.txt','a')
        global fcounter
        i=0
        roughWork_scan.write("\n"+"#*****Outermost Iteration*****#")
        app=" "
        get_link=" "
        for lines in f.readlines():
            Api_Key = "17c467e4ef26c07369d5c021afbdba97de192970c2f559632d29acd6a3c23ed5"
            # Api_Key="8e424e0d9c44757d39b95441fca4d21a8e1e452ac70090e3264f9265d23d5775"
            i=i+1
            if int(i)<=int(fcounter):
                continue
            words=lines.split()
            if len(words)==2:
                roughWork_scan.write("\n"+"-----New url entry-----")
                app=str(words[0])
                roughWork_scan.write("\n"+"1 "+app)
                get_link=str(''.join(str(words[1]).split()))
                roughWork_scan.write("\n"+"2 "+get_link)
                url = "https://www.virustotal.com/vtapi/v2/url/report"
                roughWork_scan.write("\n"+"3")
                parameters = {"resource": get_link,"apikey": Api_Key,"scan" : 1}
                roughWork_scan.write("\n"+"4")
                data = urllib.urlencode(parameters)
                roughWork_scan.write("\n"+"5")
                req = urllib2.Request(url,data)
                roughWork_scan.write("\n"+"6")
                try:
                    response = urllib2.urlopen(req)
                    roughWork_scan.write("\n"+"7")
                except urllib2.HTTPError, e:
                    roughWork_scan.write("\n"+"b")
                    continue
                except urllib2.URLError, e:
                    roughWork_scan.write("\n"+"c ")
                    roughWork_scan.write(str(e.reason))
                    continue
                except urllib2.HTTPException, e:
                    roughWork_scan.write("\n"+"d")
                    continue
                json = response.read()
                if json is None:
                    roughWork_scan.write("\n"+" json failed ")
                    continue
                roughWork_scan  .write("\n"+"8")#+" "+json)
                try:
                    response_dict = simplejson.loads(json)
                except:
                    continue
                scan_id = response_dict.get("scan_id")
                roughWork_scan.write("\n"+"9")
                link = response_dict.get("url")
                response_code = response_dict.get("response_code")
                roughWork_scan.write("\n"+"10")
                if response_code==0:
                    roughWork_scan.write("\n"+"RESPONSE_CODE_0")
                    continue
                scan_date = response_dict.get("scan_date")
                analysis = response_dict.get("permalink")
                Positives = response_dict.get("positives")
                total = response_dict.get("total")
                if response_code==1:
                    time.sleep(15)
                    hdata.write(str(get_link)+" "+str(Positives)+"\n"+"\n")
                    results.write("App: "+str(app)+"\n"+"URL: "+str(get_link)+"\n"+"Positives: "+str(Positives)+"\n"+"\n")
                    if os.fork()==0:
                        vibrator.vibrate(0.2)
                    if os.fork()==0:
                        scn="Vtotal | App= "+str(app)
                        pos="Positives= "+str(Positives)+" | url= "+str(get_link)
                        notification.notify(title=str(scn),message=str(pos),timeout=5)
                    roughWork_scan.write("\nLink: "+link)
                    roughWork_scan.write("\nScan Date: "+scan_date)
                    roughWork_scan.write("\nScan report url: "+analysis)
                    roughWork_scan.write("\nScanner: "+str(total)+ " Scanner.")
                    roughWork_scan.write("\nPositives: "+str(Positives))
                    roughWork_scan.write("\n")
        f.close()
        roughWork_scan.close()
        hdata.close()
        fcounter=i
        results.close()

    # def scandummy(self):
    #     f=open('/storage/emulated/0/MalDetec/db/forlaterscan.txt','r')
    #     roughWork_scan=open('/storage/emulated/0/MalDetec/db/roughWork_scan.txt','w')
    #     #hdata=open('/storage/emulated/0/MalDetec/db/hotdata.txt','w')
    #     count=1
    #     global lPointer
    #     global Api_Key
    #     for lines in f.readlines():
    #         roughWork_scan.write("\n"+str(lPointer)+"\n")
    #         if count<=lPointer:
    #             count=count+1
    #             continue
    #         else:
    #             count=10000
    #         words=lines.split()
    #         if len(words)==2 and words[0]=='url:':
    #             global lPointer
    #             global Api_Key
    #             lPointer=lPointer+5
    #             get_link=str(words[1])
    #             if get_link in ulist:
    #                 self.label.text = scanResult[get_link]
    #             # s=get_link
    #             # if isinstance(s, unicode):
    #             #     s = s.encode(charset, 'ignore')
    #             # scheme, netloc, path, qs, anchor = urlparse.urlsplit(s)
    #             # path = urllib.quote(path, '/%')
    #             # qs = urllib.quote_plus(qs, ':&=')
    #             # get_link=urlparse.urlunsplit((scheme, netloc, path, qs, anchor))
    #             url = "https://www.virustotal.com/vtapi/v2/url/report"
    #             parameters = {"resource": get_link,"apikey": Api_Key}
    #             data = urllib.urlencode(parameters)
    #             req = urllib2.Request(url,data)
    #             roughWork_scan.write("\n"+str(get_link)+"\n")
    #             #os.environ['http_proxy']=''
    #             try:
    #                 response = urllib2.urlopen(req,timeout=3)
    #                 #roughWork_scan.write("a")
    #             except urllib2.HTTPError, e:
    #                 roughWork_scan.write("b")
    #                 continue
    #             except urllib2.URLError, e:
    #                 roughWork_scan.write("c ")
    #                 roughWork_scan.write(str(e.reason))
    #                 continue
    #             except urllib2.HTTPException, e:
    #                 roughWork_scan.write("d")
    #                 continue
    #             except:
    #                 roughWork_scan.write(" oops ")
    #                 continue
    #             json = response.read()
    #             # if json==None:
    #             #     roughWork_scan.write("@@@@@@@")
    #             #     continue
    #             roughWork_scan.write(str(json))
    #             response_dict = simplejson.loads(json)
    #             scan_id = response_dict.get("scan_id")
    #             #roughWork_scan.write("\nsc_id"+scan_id+"\n")
    #             link = response_dict.get("url")
    #             response_code = response_dict.get("response_code")
    #             #roughWork_scan.write("\nrcode"+response_code+"\n")
    #             if response_code==0:
    #                 roughWork_scan.write("\nRESPONSE_CODE_0)\n")
    #                 continue
    #             scan_date = response_dict.get("scan_date")
    #             analysis = response_dict.get("permalink")
    #             Positives = response_dict.get("positives")
    #             total = response_dict.get("total")
    #             time.sleep(12)
    #             if response_code==1:
    #                 ulist.add(str(get_link))
    #                 scanResult[get_link]="Positives: "+str(Positives)
    #                 roughWork_scan.write("\nLink: "+link)
    #                 roughWork_scan.write("\nScan Date: "+scan_date)
    #                 roughWork_scan.write("\nScan report url: "+analysis)
    #                 roughWork_scan.write("\nScanner: "+str(total)+ " Scanner.")
    #                 roughWork_scan.write("\nPositives: "+str(Positives))
    #                 roughWork_scan.write("\n")
    #                 for items in ulist:
    #                     roughWork_scan.write("\n% "+str(items))
    #     for items in ulist:
    #         roughWork_scan.write("\n$ "+str(items))
    #     for items in ulist:
    #         roughWork_scan.write("\n@ "+str(items)+" "+str(scanResult[items]))
    #     f.close()
    #     roughWork_scan.close()

MalDetec().run()
