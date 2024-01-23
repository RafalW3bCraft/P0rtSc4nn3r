import socket
from common_ports import ports_and_services

def get_open_ports(target, port_range, verbose=False):
  open_ports = []
  try:
    ipaddr = socket.gethostbyname(target)
    for port in range(port_range[0], port_range[1]+1):
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(0.13)
      conn = sock.connect_ex((ipaddr, port))
      if conn == 0:
        open_ports.append(port)
      sock.close()
  except socket.gaierror:
    if target[0].isdigit():
      return 'Error: Invalid IP address'
    else:
      return 'Error: Invalid hostname'
  if verbose:
    host = None
    try:
      host = socket.gethostbyaddr(ipaddr)[0]
    except socket.herror:
      pass
    if host is not None:
      fn_str = f'Open ports for {host} ({ipaddr})\nPORT     SERVICE\n'
    else:
      fn_str = f'Open ports for {ipaddr}\nPORT     SERVICE\n'
    for port in open_ports:
      try:
          service_name = ports_and_services[port]
      except OSError:
          service_name = 'Unknown'
      fn_str += f'{port:<9}{service_name}\n'

    return fn_str.strip()
  return(open_ports)