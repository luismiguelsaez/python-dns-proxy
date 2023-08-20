import socket
from select import select
from threading import Thread
import logging
from sys import stdout
import ssl

def ssl_wrap(server_addr: str, server_port: int, data: bytes)->bytes:

  server = (server_addr, server_port)

  context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  context.load_verify_locations('/etc/ssl/cert.pem')
  context.check_hostname = True
  context.minimum_version = ssl.TLSVersion.TLSv1_3
  
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    with context.wrap_socket(sock=sock,server_hostname=server_addr) as ssock:
      ssock.connect(server)
      ssock.send(data)
      data = ssock.recv(BUFFER_SIZE)

  return data

def udp_dns_query(server_ip: str, server_port: int, data: bytes)->bytes:
  
  # Create a bytes object from the DNS query
  bytes_data = data
  
  # Create a UDP socket to the upstream DNS server
  sock_upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  
  logger.debug(f'Sending DNS query to upstream UDP server {server_ip}:{server_port}')

  # Connect to the upstream DNS server
  sock_upstream.connect((server_ip, server_port))
  
  # Send the DNS query to the upstream DNS server
  sock_upstream.send(bytes_data)
  
  # Get the response from the upstream DNS server
  response = sock_upstream.recv(1024)
  
  # Close the socket
  sock_upstream.close()
  
  # Return parsed response
  return response

def tcp_dns_query(server_ip: str, server_port: int, data: bytes, ssl_upstream: bool = True)->bytes:
  
  # Create a bytes object from the DNS query
  bytes_data = data
  
  if ssl_upstream:
    logger.debug(f'Sending SSL DNS query to upstream TCP server {server_ip}:{server_port}')
    response = ssl_wrap(server_ip, server_port, bytes_data)
  else:
    # Create a TCP socket to the upstream DNS server
    sock_upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    logger.debug(f'Sending plain DNS query to upstream TCP server {server_ip}:{server_port}')
      
    # Connect to the upstream DNS server
    sock_upstream.connect((server_ip, server_port))
    
    # Send the DNS query to the upstream DNS server
    sock_upstream.send(bytes_data)
    
    # Get the response from the upstream DNS server
    response = sock_upstream.recv(BUFFER_SIZE)
    
    # Close the socket
    sock_upstream.close()

  # Return parsed response
  return response

def tcp_handler(conn: socket.socket, addr: tuple)->None:
  
  # Receive data from the client
  data = conn.recv(BUFFER_SIZE)
  
  # Send the DNS query to the upstream DNS server
  response = tcp_dns_query(UPSTREAM_TCP_ADDR, 853, data, ssl_upstream=True)

  # Send the response to the client
  conn.send(response)
  
  # Close the connection
  conn.close()

def udp_handler(data: bytes, addr: tuple, sock: socket.socket)->None:
  
  # Send the DNS query to the upstream DNS server
  response = udp_dns_query(UPSTREAM_UDP_ADDR, UPSTREAM_UDP_PORT, data)

  # Send the response to the client
  sock.sendto(response, addr)


BUFFER_SIZE = 1024
BIND_ADDR = 'localhost'
BIND_PORT = 2553

UPSTREAM_TCP_ADDR = '1.1.1.1'
UPSTREAM_TCP_PORT = 53
UPSTREAM_UDP_ADDR = '1.1.1.1'
UPSTREAM_UDP_PORT = 53

# Create logger
logger = logging.getLogger(__name__)

# Create a system output handler
stdout_handler = logging.StreamHandler(stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stdout_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)
logger.setLevel(logging.DEBUG)

# Create a UDP socket
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Create a TCP socket
tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind the UDP socket to the port
udp_sock.bind((BIND_ADDR, BIND_PORT))

# Bind the TCP socket to the port
tcp_sock.bind((BIND_ADDR, BIND_PORT))
tcp_sock.listen()

# Receive data from the client
while True:
  
  select([udp_sock, tcp_sock], [], [])

  if udp_sock in select([udp_sock, tcp_sock], [], [])[0]:

    data, addr = udp_sock.recvfrom(BUFFER_SIZE)
    
    logger.debug(f'New UDP connection from {addr[0]}:{addr[1]}')

    Thread(target=udp_handler, args=(data, addr, udp_sock)).start()

  if tcp_sock in select([udp_sock, tcp_sock], [], [])[0]:
    
    conn, addr = tcp_sock.accept()
    
    logger.debug(f'New TCP connection from {addr[0]}:{addr[1]}')

    Thread(target=tcp_handler, args=(conn, addr)).start()
