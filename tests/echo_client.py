#!/usr/bin/python

import argparse, sys, socket, string, os
import ipaddress

def is_ipv6(address):
    try:
        ipaddress.IPv6Address(address)
        return True
    except ValueError:
        return False

class IN:
    IP_PMTUDISC_DO = 1
    IP_PMTUDISC_DONT = 0
    IP_MTU_DISCOVER = 10

class Echo:
    def __init__(self, target, port, timeout, df, ttl, size):
      self.sock = None
      self.af = socket.AF_INET6 if is_ipv6(target) else socket.AF_INET
      self.target = target
      self.port = port
      self.timeout = timeout
      self.df = df
      self.ttl = ttl
      self.data = ((string.ascii_letters *
                    (size // len(string.ascii_letters) +1))[:size]).encode("ascii")

    def set_socket_opt(self):
      self.sock.settimeout(self.timeout)
      if self.ttl:
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.ttl)

      # Ideally we'd want PROBE instead of DO if available
      pmtud = IN.IP_PMTUDISC_DO if self.df else IN.IP_PMTUDISC_DONT
      self.sock.setsockopt(socket.IPPROTO_IP, IN.IP_MTU_DISCOVER, pmtud)

    def send(self):
      return False

class EchoUDP(Echo):
    def __init__(self, target, port, timeout, df, ttl, size):
      # Resolve peer now, to have a consistent address
      resolved = socket.gethostbyname(target)
      Echo.__init__(self, resolved, port, timeout, df, ttl, size)
      self.sock = socket.socket(self.af, socket.SOCK_DGRAM)
      self.set_socket_opt()

    def send(self):
      if self.sock.sendto(self.data, (self.target, self.port)) != len(self.data):
        raise BaseException('failed to send all data')

      ret, peer = self.sock.recvfrom(len(self.data))
      if ret != self.data:
        raise BaseException('failed to receive all data')

      if (peer !=  (self.target, self.port)):
        raise BaseException('received data from wrong peer')

      return True

class EchoTCP(Echo):
    def __init__(self, target, port, timeout, df, ttl, size):
      Echo.__init__(self, target, port, timeout, df, ttl, size)

    def send(self):
      self.sock = socket.socket(self.af, socket.SOCK_STREAM)
      self.set_socket_opt()
      self.sock.connect((self.target, self.port))

      if self.sock.send(self.data) != len(self.data):
        raise BaseException('failed to send all data')

      self.sock.shutdown(socket.SHUT_WR)

      recv_data = bytes()
      while byte := self.sock.recv(1):
          recv_data += byte

      if self.data != recv_data:
        raise BaseException('failed to receive all data')

      self.sock.close()

      return True

def echo_factory(proto, target, port, timeout, df, ttl, size):
  if proto == 'tcp':
    return EchoTCP(target, port, timeout, df, ttl, size)
  if proto == 'udp':
    return EchoUDP(target, port, timeout, df, ttl, size)
  raise BaseException('unsupported protocol')

def test_tcp(target, port, name, args):
    for size in [32, 111, 1480, 1600, 33333, 65000]:
        echo = echo_factory('tcp', target, port,
                            args['timeout'], args['df'], args['ttl'], size)

        try:
            if echo.send():
                print(f"{name} test (size={size}): OK")
        except Exception as e:
            print(f"{name} test (size={size}): Failed: {e}")
            sys.exit(1)

def test_tcp_echo(args):
    target = os.getenv('DPIP_IP4_ADDR')
    port = int(os.getenv('TCP_ECHO_PORT'))
    test_tcp(target, port, "TCP Echo", args)

def test_tcp6_echo(args):
    target = os.getenv('DPIP_IP6_ADDR')
    port = int(os.getenv('TCP_ECHO_PORT'))
    test_tcp(target, port, "TCP6 Echo", args)

def test_tcp_proxy(args):
    target = os.getenv('DPIP_IP4_ADDR')
    port = int(os.getenv('TCP_PROXY_PORT'))
    test_tcp(target, port, "TCP Proxy", args)

def parse_args():
  parser = argparse.ArgumentParser(description='Echo client over TCP/UDP')
  parser.add_argument('--target', default = 'localhost', help = "Target host")
  parser.add_argument('--count', default = '4', type=int, help = "Number of echo request")
  parser.add_argument('--protocol', default='udp', help = "Protocol to use")
  parser.add_argument('--port', default = 5555, type=int, help = "Port to use")
  parser.add_argument('--timeout', default = 5, type=int, help = "Timeout in seconds")
  parser.add_argument('--df', default = False, action='store_true', help = "Set DF flag")
  parser.add_argument('--ttl', default = 0, type=int, help = "Set IP TTL")
  parser.add_argument('--size', default = 32, type=int, help = "The size of data")

  return vars(parser.parse_args())

if __name__ == '__main__':
  args = parse_args()
  test_tcp_echo(args)
  test_tcp6_echo(args)
  test_tcp_proxy(args)

