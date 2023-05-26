# Build and run

Install dependencies (deb-based systems):

```shell
sudo apt install libnetfilter-queue-dev
```

Package requires CGO to be built, so you'll also need a C compiler.

Before run, packets should be redirected to NFQUEUE:

```shell
# Capture all TCP packets coming to port 8080 on eth1.
sudo iptables -A INPUT -p tcp --dport 8080 -i eth1 -j NFQUEUE --queue-num 0
```

Queue number must match the one used in source code.

For program to work, you can either:

1. Run it as root every time:
    ```shell
   sudo ./tcp_mimic 
    ```
2. Add required capabilities and then run as normal user:
    ```shell
   sudo setcap 'cap_net_admin=+ep' ./tcp_mimic
   ./tcp_mimic
    ```