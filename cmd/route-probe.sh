#!/system/bin/sh
(printf 'GET /?tun2proxy_test=uid_route_probe HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'; sleep 8) | toybox nc -w 12 104.20.23.154 80
