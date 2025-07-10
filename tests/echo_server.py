#!/usr/bin/python

import argparse, socket, os

BUFFER_MAX_SIZE = 66000

def listen_tcp(address, port):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind((address, port))
  sock.listen(1)

  while True:
    data = b""
    conn, addr = sock.accept()
    print(f"Connection address: {addr}")

    while len(data) < BUFFER_MAX_SIZE:
      chunk = conn.recv(BUFFER_MAX_SIZE - len(data))
      if not chunk:
        # Our read-end has shutdown
        print("received zero chunk")
        break
      print("received data chunk of size:", len(chunk))
      data += chunk

    while len(data) > 0:
      sent = conn.send(data)
      data = data[sent:]

    conn.close()

def listen_udp(address, port):
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.bind((address, port))

  while True:
    data, addr = sock.recvfrom(BUFFER_MAX_SIZE)
    print("received connection from: ", addr)
    if not data:
      print("received zero bytes")
      continue
    print("received data of size:", len(data), "\n")

    if len(data) != sock.sendto(data, addr):
      print("failed to resend data")


def parse_args():
  parser = argparse.ArgumentParser(description='Echo server over TCP/UDP')
  parser.add_argument('--tcp', default=False, action='store_true', help = "Listen TCP (default is UDP)")
  parser.add_argument('--address', default = 'localhost', help = "Address to listen")
  parser.add_argument('--port', default = 7070, type=int, help = "Port to use")
  return vars(parser.parse_args())


if __name__ == '__main__':
  args = parse_args()

  if args['tcp']:
    listen_tcp(args['address'], args['port'])
  else:
    listen_udp(args['address'], args['port'])

