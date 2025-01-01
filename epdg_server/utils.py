from binascii import hexlify, unhexlify

import dns.resolver


def toHex(value):
    return hexlify(value).decode("utf-8")


def fromHex(value):
    return unhexlify(value)


def resolve_domain(operator_url, ip_version="v4v6"):
    dnsres = dns.resolver.Resolver()
    records = []
    try:
        if "v4" in ip_version:
            ans = dnsres.resolve(operator_url, "A")
            for record in ans:
                records.append(record.address)
    except dns.resolver.NoAnswer:  # no answer
        pass
    except dns.resolver.NXDOMAIN:  # domain not found
        pass
    except dns.exception.DNSException as e:
        print(f"Error resolving A records for {operator_url}: {e}")

    try:
        if "v6" in ip_version:
            ans = dnsres.resolve(operator_url, "AAAA")
            for record in ans:
                records.append(record.address)
    except dns.resolver.NoAnswer:  # no answer
        pass
    except dns.resolver.NXDOMAIN:  # domain not found
        pass
    except dns.exception.DNSException as e:
        print(f"Error resolving AAAA records for {operator_url}: {e}")

    try:
        ans = dnsres.resolve(operator_url, "CNAME")
        for record in ans:
            records.extend(resolve_domain(record.target.to_text(), ip_version))
    except dns.resolver.NoAnswer:  # no answer
        pass
    except dns.resolver.NXDOMAIN:  # domain not found
        pass
    except dns.exception.DNSException as e:
        print(f"Error resolving CNAME for {operator_url}: {e}")

    return list(dict.fromkeys(records))  # remove duplicates while mantaining order
