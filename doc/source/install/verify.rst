.. _verify:

Verify operation
~~~~~~~~~~~~~~~~

Verify operation of the kuryr-libnetwork.

#. Create a IPv4 network:

   .. code-block:: console

      # docker network create --driver kuryr --ipam-driver kuryr \
            --subnet 10.10.0.0/16 --gateway=10.10.0.1 test_net
      785f8c1b5ae480c4ebcb54c1c48ab875754e4680d915b270279e4f6a1aa52283
      # docker network ls
      NETWORK ID          NAME                DRIVER              SCOPE
      ...
      e13c98aa096b        test_net            kuryr               local
      # docker run --net test_net cirros ifconfig
      eth0      Link encap:Ethernet  HWaddr FA:16:3E:D5:BB:5F
                inet addr:10.10.0.9  Bcast:0.0.0.0  Mask:255.255.0.0
                UP BROADCAST RUNNING MULTICAST  MTU:1450  Metric:1
                RX packets:9 errors:0 dropped:0 overruns:0 frame:0
                TX packets:2 errors:0 dropped:0 overruns:0 carrier:0
                collisions:0 txqueuelen:1000
                RX bytes:894 (894.0 B)  TX bytes:188 (188.0 B)

      lo        Link encap:Local Loopback
                inet addr:127.0.0.1  Mask:255.0.0.0
                UP LOOPBACK RUNNING  MTU:65536  Metric:1
                RX packets:0 errors:0 dropped:0 overruns:0 frame:0
                TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
                collisions:0 txqueuelen:1
                RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
