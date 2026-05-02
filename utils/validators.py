import ipaddress

def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_port(port_str):
    return port_str.isdigit()