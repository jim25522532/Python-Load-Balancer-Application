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


<<<<<<<<<<<<<<<< Stateful load balancer >>>>>>>>>>>>>>>>
8) Execute the command 'sudo mn --topo single,7 --mac --controller=remote,ip=192.168.94.52 --switch `ovs,protocols=OpenFlow13' in Mininet
9) Initialize the RYU controller with the pranit13extra.py application using the command 'ryu run pranit13extra.py'
10) In this case, any request made by curl or wget command from h4 or h5 would be redirected by the load balancer to h1 web server, requests from h6 would be redirected to h2 web server and requests from h7 would be redirected to h3 web server.
11) This re-direction to specific seervers by the load balancer is done on basis of source IP of the clients h4, h5, h6 and h7 that it learns
12) All communications to and fro the web servers are via the load balancer
