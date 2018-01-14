# Proxifier-For-Linux


install and unistall are 'C' executable  files , change permission level to 755 with 'chmod 755 install uninstall' and run below comamands

Install Proxifier as "sudo ./install"
Uninstall if installed as "sudo ./uninstall"

If Proxifier is not working take a look at debug_suggestions.txt

You can find source code in my another repository Proxifier-For-Linux(Source)

Here is how it works in breif...

1.When you run 'proxifier start' command from terminal it grabs the required information(username password proxyserverip proxyserverport) from file proxifier.conf.* and writes them to proxifier.conf

2.It also starts three servers fakehttpserver fakehttpsserver fakednsserver

3.iptables are configured so that all 80 packets except packets to proxyserver goes to fakehttpserver and //ly 443 packets to fakehttpsserver

4.To be frank browsers really wont resolve the hostnames when configured to work in proxy I took it as an insipiration and wrote fakednsserver which sends some fake ipaddress for requested hostnames , But having recorded them i can get back the matching hostname from ip by doing reverse dns search(not exactly reverse dns search but type like that) , and in proxy enviroment what matters is hostname and so i can make connections 

