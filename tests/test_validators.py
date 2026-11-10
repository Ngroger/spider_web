from utils.validators import is_valid_cidr_or_ip, ip_matches, port_in_range
def test_cidr():
    assert is_valid_cidr_or_ip("192.168.0.0/16")
    assert not is_valid_cidr_or_ip("300.0.0.0/99")
    assert ip_matches("192.168.1.5","192.168.0.0/16")
    assert not ip_matches("10.0.0.1","192.168.0.0/16")
    assert port_in_range(8080,"8000-8100") and not port_in_range(9000,"8000-8100")
