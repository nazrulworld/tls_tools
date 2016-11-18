#!/usr/bin/env python
#
# check_certificate_chain.py:
# does exactly what the name suggests.
#
# X.509 sucks!
#
# AUTHORS:
#   Aaron <azet@azet.org> Zauner
#
# LICENSE:
#   MIT License
#
# TODO: 
# - Add interface to certificate-transparency.
# - Check/Verify certificates.
#
from __future__ import print_function
import sys
import datetime
import argparse
import M2Crypto.SSL

parser = argparse.ArgumentParser()

OK = 0, "OK - "
WARNING = 1, "WARNING - "
CRITICAL = 2, "CRITICAL - "
UNKNOWN = 3, "UNKNOWN - "

parser.add_argument('-S', '--server', action='store', dest="server", nargs="+")
parser.add_argument('-P', '--port', action="store", dest="port", type=int)

utc_now = datetime.datetime.utcnow().replace(tzinfo=None)
# 30 days
warning_duration = datetime.timedelta(days=30)


def main():
    options = vars(parser.parse_args())

    port = options.get('port') or 443
    servers = []
    for server in options.get('server', []):
        server = server.split(":")
        if len(server) == 1:
            server += (port, )
        servers.append((server[0], server[1], ))

    if not servers:
        print (UNKNOWN[1] + "At least one server address is required!")
        sys.exit(UNKNOWN[0])

    tls_context = M2Crypto.SSL.Context()
    # we want to check unknown CAs as well
    tls_context.set_allow_unknown_ca(True)
    # sadly, certificate verification almost always fails.
    tls_context.set_verify(M2Crypto.SSL.verify_none, False)
 
    conn = M2Crypto.SSL.Connection(tls_context)

    try:
        reports = dict()
        for host in servers:
            # host = address, port
            conn.connect(host)
            chain = conn.get_peer_cert_chain()
            print("\n>> Server: %s\n" % host[0])
            print ("\n>> Certificate Chain:\n")
            i = 0
            for cert in reversed(chain):
                if cert.get_not_after().get_datetime().replace(tzinfo=None) <= utc_now:
                    try:
                        reports['error'].append((host[0], cert))
                    except KeyError:
                        reports['error'] = [(host[0], cert), ]
                elif cert.get_not_after().get_datetime().replace(tzinfo=None) <= (utc_now - warning_duration):
                    try:
                        reports['warn'].append((host[0], cert))
                    except KeyError:
                        reports['warn'] = [(host[0], cert), ]

                i += 1
                print (" [+] " + "*"*i + "\t\t%s" % cert.get_subject().as_text())

            print ("\n>> Certificate Information:\n")

            for cert in reversed(chain):
                pkey = cert.get_pubkey()

                print ("." * 80)
                print ("- [Subject]:\t\t%s"          % cert.get_subject().as_text())
                print ("- [Issuer]:\t\t%s"           % cert.get_issuer().as_text())
                print ("- [Valid from]:\t\t%s"       % cert.get_not_before())
                print ("- [Valid until]:\t%s"        % cert.get_not_after())
                if cert.check_ca():
                    print ("- [Authority]:\t\tIs a CA")
                else:
                    print ("- [Authority]:\t\tIs not a CA")
                print ("- [Version]:\t\t%s"          % cert.get_version())
                print ("- [Serial No.]:\t\t%s"       % cert.get_serial_number())
                print ("- [X.509 Extension Details]:")
                for k in range(0, cert.get_ext_count()):
                    ext = cert.get_ext_at(k)
                    print ("  `-- [x509_" + ext.get_name() + "]:\n\t   %s\n" % ext.get_value().replace('\n', ' '))
                print ("- [Fingerprint]:\t(hex) %s"  % cert.get_fingerprint())
                print ("- [Keysize]:\t\t%s Bits"     % (pkey.size() * 8))
                print ("- [RSA Modulus]:\t(hex) %s"  % pkey.get_modulus())
                print ("- [RSA Key]:\n%s"            % pkey.get_rsa().as_pem())

        if len(reports):
            if reports.get('error'):
                printable = CRITICAL[1] + "Certificate Expired!\n"
                for server, cert in reports.get('error', []):
                    printable += "Server: %s; Expired On: %s \n" % (server, cert.get_not_after())
                print (printable)
                sys.exit(CRITICAL[0])

            if reports.get('warn'):
                printable = CRITICAL[1] + "Certificate Will Expire Soon!\n"
                for server, cert in reports.get('warn', []):
                    printable += "Server: %s; Expired On: %s \n" % (server, cert.get_not_after())
                print (printable)
                sys.exit(WARNING[0])

        print (OK[1] + "All Certificates are updated.")
    except Exception as exc:
        print(WARNING[1] + str(exc))
        sys.exit(UNKNOWN[0])

if __name__ == '__main__':
    main()

