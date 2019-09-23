![alt text](https://cdn.pixabay.com/photo/2017/01/02/13/28/astronaut-1946806_960_720.jpg)

# ASNVhostDiscover
This tool allows you to discover hidden vhost on an IP range. You can use it in BugBounty for example to find servers containing forgotten vhost

You can also use it to bypasse SaaS WAF like cloudflare when the target use know AS

# how to use

Run the tool :
```bash
php scan.php
```

```
--ports           Ports to scan if there are many port separate it by , : --ports=80,443
--host            Host to scan (single value) : google.fr
--network         Network to scan exemple : 10.0.0.0/8

--check-name      Only on HTTPS check if certs match with this domaine
--check-name-file Only on HTTPS check if certs match with domaines in file
--check-vhost     if domaine match with the certificate the script try to detect vhost. Require check-name or check-file-name option

--size-variation  Use it for detect vhost with variation of lenght response (default: 100) : --size-variatoion=200

--verbose         Display error

--burp            Send to burp proxy request for discover vhost (127.0.0.1:8080)

--only-vhost      Show only potential vhost
```
