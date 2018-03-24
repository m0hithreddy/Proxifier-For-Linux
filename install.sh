echo 'sudo /opt/proxifier/bin/proxifier "$@"'  >/usr/local/bin/proxifier
chmod 755 /usr/local/bin/proxifier


mkdir -p /opt/proxifier/bin /opt/proxifier/bak /opt/proxifier/conf /opt/proxifier/buffer

cp executables/* /opt/proxifier/bin/
chmod 755 /opt/proxifier/bin/*


echo "\nEnter the proxydetails , It creates proxyserver.conf file in /opt/proxifier/conf directory you can created mutiple files as proxifier.conf.<profilename> and run that profile as proxifier.conf.<profilename>\n"

echo "Note:If ProxyServer has no authorization hit enter during proxypass prompt\n"

read -p "ProxyServer IP-> " proxyserverip
read -p "ProxyServer Port-> " proxyserverport
read -p "ProxyServer Pass(username:password)-> " proxyserverpass

echo "ProxyServerIP=$proxyserverip\nProxyServerPort=$proxyserverport\nProxyServerAuthorization=$proxyserverpass" >/opt/proxifier/conf/proxifier.conf
