# Proxifier-For-Linux

1)sudo su

2)make 

3)make install

4)make uninstall(to uninstall software from device)

Here's how it works in breif

1.When you run 'proxifier start n' command from terminal it grabs the required information(username password proxyserverip proxyserverport) from file proxifier.conf.n and writes them to proxifier.conf

2.It also starts three servers fakehttpserver fakehttpsserver fakednsserver

3.iptables are configured so that all 80 packets except packets to proxyserver goes to fakehttpserver and //ly 443 packets to fakehttpsserver,Those servers modifies the http request accordingly and sends them to proxy server 

4.To be frank browsers really wont resolve the hostnames when configured to work in proxy I took it as an insipiration and wrote fakednsserver which sends some fake ipaddress for requested hostnames , But having recorded them i can get back the matching hostname from ip by doing reverse dns search(not exactly reverse dns search but type like that) , and in proxy enviroment what matters is hostname and so i can make connections 

