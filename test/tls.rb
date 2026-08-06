##
# mruby-tls -- certificate verification tests.
#
# These cover the security critical contract of the gem: a certificate that
# does not check out is REJECTED, and each Tls::Config#noverify axis waives
# exactly one check and leaves the others enforced.  A regression here is the
# difference between a verified connection and a silently accepted MITM, so
# every case asserts the failure direction as well as the success direction.
#
# Everything runs in process: a Tls::Server and a Tls::Client talk to each
# other over a loopback socket, driven by the non-blocking handshake API, so
# the tests need no external tooling, no network and no fixtures on disk
# beyond the CA file written below (Tls::Config only takes a trust anchor as
# a path, so that one has to be a real file).
#
# The leaf/CA fixtures are pinned with long validity windows; the "expired"
# leaf is expired for good and never needs regenerating.

TLS_TEST_CA_PEM = <<'PEM'
-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIUGW0f98VEFQoLrxBYEQNei2WgwCMwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRbXJ1YnktdGxzIHRlc3QgQ0EwHhcNMjYwNzMxMTQyMzA5
WhcNNDgwNjI1MTQyMzA5WjAcMRowGAYDVQQDDBFtcnVieS10bHMgdGVzdCBDQTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALU5wIaIoI/xX0OQgL0gTb64
EQYvZqn0IHIlciZtym/tu9609/4z+xX4mt+leQ/f0ezfBFyDor/R1uVwXpMUNBTF
O7aVhiFupomzZ3dMVA8z2irEZszDqjOnXgYn25zIq532HY68Er5maBF6m2uehLsg
tFxGJ1izNnhUXWTupws7kJxfSWHFFy2CD/GkfZESbuQZZ43yJ4yyyIehYieYSsx1
q7NiQB2kv+5jGZssOGAhszwvPNiuI3F8DQ9LjmcD7DCuXGZJEI15O3F6KmQ0Huc0
S0iMRnsFAQ7f7KXRTSObJCimpkLGAimNmxzqSTzvKCAXPD0QpFQ8LumRKf7/bwcC
AwEAAaNTMFEwHQYDVR0OBBYEFJXSW3amFaYXguflZwHBghjKqmBvMB8GA1UdIwQY
MBaAFJXSW3amFaYXguflZwHBghjKqmBvMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBACC1kNHhrxuwnNOo6eYmRm4tZNaAvVQ1jcxdAN5XWGA26ETe
fMGtdfE+FjRbHDAxzI6RQzo8+oStbt4F1Nv015Pm3km8ZQYgMY9b1MasxlmKJYxe
hBg1x/oQ9IQSeksSstnCqKnlHimvG/hyU1LiQIC0JRhKj335QmqGzNzHAjM5LNiD
NXPidD2n47OyvHRNKfxOqzFZBQ9yGGaRbnABuEa2U9EDJTZD9QTmAKwB6OvENMZA
ZGkHoM+NEf4aGnvwH/tI/ZibxOHJgEmVtN2WdNSSNHcp/0tr/HsagNuF0xgKqypB
GFiBZAxyOO2bbkL8Gg6OxjPN8BDjCwdEwwVEWQI=
-----END CERTIFICATE-----
PEM

TLS_TEST_CERT_PEM = <<'PEM'
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0d:dd:99:a4:7d:95:19:e2:8c:56:b7:11:80:25:11:2f:a1:b7:1c:ba
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=mruby-tls test CA
        Validity
            Not Before: Jan  1 00:00:00 2025 GMT
            Not After : Dec 31 23:59:59 2049 GMT
        Subject: CN=localhost
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a1:13:f5:08:ed:6d:73:2b:02:7b:34:1b:83:6b:
                    71:3c:54:e7:34:ee:fa:d1:6d:60:c0:8f:79:b7:ec:
                    26:b6:1f:b4:31:34:7a:a1:cb:d6:ce:d0:c0:9b:a0:
                    29:2f:ff:eb:ab:4b:09:cf:9c:8d:9e:36:ea:ce:67:
                    41:69:39:95:41:2e:c8:d5:68:fe:6c:96:33:3d:87:
                    9a:f7:ef:95:10:3e:1b:0d:65:33:d7:bd:a6:bf:88:
                    cc:4a:00:74:55:66:a9:ad:50:02:71:fd:41:99:c1:
                    2c:a0:cd:a2:cb:d0:79:19:3a:f3:b4:5b:d6:3e:36:
                    b3:b5:3a:3c:94:8b:0d:2a:52:94:a2:1c:fa:22:69:
                    14:83:1a:d6:76:bc:e4:52:cb:35:1d:b4:f9:e8:a5:
                    8b:e2:52:0c:80:56:45:79:7a:4b:15:0b:f0:e0:d4:
                    38:12:41:b7:3f:09:c4:be:56:55:37:ca:a2:6e:bc:
                    18:18:b6:c0:3c:90:d3:49:f6:3b:74:78:fc:4f:88:
                    14:f2:f5:9b:66:ae:5a:58:3c:e2:cb:69:ae:26:94:
                    eb:cb:01:3b:4c:ff:12:47:63:fc:80:72:51:cf:cc:
                    60:bd:d2:e8:77:43:2c:25:2c:c0:ba:eb:3f:a9:69:
                    46:03:2e:2a:69:b0:e3:88:6c:3f:f6:de:dc:57:56:
                    e6:2d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:localhost
            X509v3 Subject Key Identifier: 
                67:67:6F:52:E5:87:5D:56:F0:58:45:76:76:87:F7:9B:BA:1D:14:39
            X509v3 Authority Key Identifier: 
                95:D2:5B:76:A6:15:A6:17:82:E7:E5:67:01:C1:82:18:CA:AA:60:6F
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        0e:c6:4f:86:58:10:19:9d:d9:f4:50:7c:8a:6e:a1:b9:2f:18:
        82:e6:29:c6:54:c6:c8:23:dd:3d:1c:ad:85:75:09:17:34:e0:
        6f:63:2c:f0:3c:a9:59:c4:e0:d1:fa:19:39:00:f7:cf:22:f0:
        8d:be:43:76:dd:93:b3:3c:86:87:3b:8f:cc:05:89:35:ce:39:
        13:55:f0:63:a5:19:ae:55:24:11:af:d4:e6:39:06:31:63:80:
        9e:35:a6:22:5f:d8:63:78:72:49:d3:c4:c3:5e:41:74:ee:74:
        fa:4f:be:fa:cd:24:46:c9:0d:2e:b4:62:65:24:eb:2e:2e:c7:
        f2:a3:37:f3:8d:5b:c3:dd:12:0d:1d:dc:7c:9a:f6:96:0c:f7:
        0e:f9:87:71:c5:57:49:79:a9:38:05:86:bb:30:f9:fe:30:46:
        0b:eb:96:da:88:8e:44:a1:b3:4c:a3:1e:34:f3:11:8f:0a:8e:
        86:db:f8:cd:d5:15:dd:8e:68:b3:60:4b:5a:b6:8b:ec:17:ea:
        ed:8e:8f:39:10:b5:51:81:81:e5:7c:f2:d6:06:8e:8e:eb:47:
        e0:60:7b:70:ac:65:81:c0:29:20:18:2d:f2:2c:fd:35:9f:e4:
        79:f1:c2:98:c3:93:b0:28:83:80:4c:89:07:28:6a:08:b6:d8:
        95:50:bc:51
-----BEGIN CERTIFICATE-----
MIIDLjCCAhagAwIBAgIUDd2ZpH2VGeKMVrcRgCURL6G3HLowDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRbXJ1YnktdGxzIHRlc3QgQ0EwHhcNMjUwMTAxMDAwMDAw
WhcNNDkxMjMxMjM1OTU5WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQChE/UI7W1zKwJ7NBuDa3E8VOc07vrRbWDA
j3m37Ca2H7QxNHqhy9bO0MCboCkv/+urSwnPnI2eNurOZ0FpOZVBLsjVaP5sljM9
h5r375UQPhsNZTPXvaa/iMxKAHRVZqmtUAJx/UGZwSygzaLL0HkZOvO0W9Y+NrO1
OjyUiw0qUpSiHPoiaRSDGtZ2vORSyzUdtPnopYviUgyAVkV5eksVC/Dg1DgSQbc/
CcS+VlU3yqJuvBgYtsA8kNNJ9jt0ePxPiBTy9ZtmrlpYPOLLaa4mlOvLATtM/xJH
Y/yAclHPzGC90uh3QywlLMC66z+paUYDLippsOOIbD/23txXVuYtAgMBAAGjcDBu
MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAd
BgNVHQ4EFgQUZ2dvUuWHXVbwWEV2dof3m7odFDkwHwYDVR0jBBgwFoAUldJbdqYV
pheC5+VnAcGCGMqqYG8wDQYJKoZIhvcNAQELBQADggEBAA7GT4ZYEBmd2fRQfIpu
obkvGILmKcZUxsgj3T0crYV1CRc04G9jLPA8qVnE4NH6GTkA988i8I2+Q3bdk7M8
hoc7j8wFiTXOORNV8GOlGa5VJBGv1OY5BjFjgJ41piJf2GN4cknTxMNeQXTudPpP
vvrNJEbJDS60YmUk6y4ux/KjN/ONW8PdEg0d3Hya9pYM9w75h3HFV0l5qTgFhrsw
+f4wRgvrltqIjkShs0yjHjTzEY8Kjobb+M3VFd2OaLNgS1q2i+wX6u2OjzkQtVGB
geV88tYGjo7rR+Bge3CsZYHAKSAYLfIs/TWf5HnxwpjDk7Aog4BMiQcoagi22JVQ
vFE=
-----END CERTIFICATE-----
PEM

TLS_TEST_EXPIRED_PEM = <<'PEM'
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3a:ca:7b:a7:bc:fa:94:6f:b0:b6:af:82:3f:38:1c:7b:cc:20:95:d1
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=mruby-tls test CA
        Validity
            Not Before: Jan  1 00:00:00 2020 GMT
            Not After : Feb  1 00:00:00 2020 GMT
        Subject: CN=localhost
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:a1:13:f5:08:ed:6d:73:2b:02:7b:34:1b:83:6b:
                    71:3c:54:e7:34:ee:fa:d1:6d:60:c0:8f:79:b7:ec:
                    26:b6:1f:b4:31:34:7a:a1:cb:d6:ce:d0:c0:9b:a0:
                    29:2f:ff:eb:ab:4b:09:cf:9c:8d:9e:36:ea:ce:67:
                    41:69:39:95:41:2e:c8:d5:68:fe:6c:96:33:3d:87:
                    9a:f7:ef:95:10:3e:1b:0d:65:33:d7:bd:a6:bf:88:
                    cc:4a:00:74:55:66:a9:ad:50:02:71:fd:41:99:c1:
                    2c:a0:cd:a2:cb:d0:79:19:3a:f3:b4:5b:d6:3e:36:
                    b3:b5:3a:3c:94:8b:0d:2a:52:94:a2:1c:fa:22:69:
                    14:83:1a:d6:76:bc:e4:52:cb:35:1d:b4:f9:e8:a5:
                    8b:e2:52:0c:80:56:45:79:7a:4b:15:0b:f0:e0:d4:
                    38:12:41:b7:3f:09:c4:be:56:55:37:ca:a2:6e:bc:
                    18:18:b6:c0:3c:90:d3:49:f6:3b:74:78:fc:4f:88:
                    14:f2:f5:9b:66:ae:5a:58:3c:e2:cb:69:ae:26:94:
                    eb:cb:01:3b:4c:ff:12:47:63:fc:80:72:51:cf:cc:
                    60:bd:d2:e8:77:43:2c:25:2c:c0:ba:eb:3f:a9:69:
                    46:03:2e:2a:69:b0:e3:88:6c:3f:f6:de:dc:57:56:
                    e6:2d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:localhost
            X509v3 Subject Key Identifier: 
                67:67:6F:52:E5:87:5D:56:F0:58:45:76:76:87:F7:9B:BA:1D:14:39
            X509v3 Authority Key Identifier: 
                95:D2:5B:76:A6:15:A6:17:82:E7:E5:67:01:C1:82:18:CA:AA:60:6F
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        56:11:2a:68:16:3d:20:d7:8d:70:78:8e:b9:73:10:2f:5b:36:
        78:68:7a:d8:1d:97:43:ae:9c:f6:0e:15:11:a7:76:d9:1d:07:
        46:93:2f:45:5b:30:36:dc:04:a2:e5:0f:38:8b:bc:a7:fc:d0:
        c5:2a:bc:bf:a1:6c:91:06:e4:79:dd:63:7f:cd:ea:9b:50:67:
        06:7d:e2:c3:f5:9c:11:75:f9:04:ee:ea:2a:5e:dc:88:7b:8e:
        07:81:7b:ca:9e:c1:7a:46:cc:98:5a:65:9b:de:9e:d8:d3:bb:
        b9:ad:81:66:bc:40:7b:f6:ae:56:58:93:92:a8:c4:ff:ec:b8:
        db:e6:20:d4:ec:63:2d:b7:61:d9:5c:bd:a3:66:c8:6d:6e:71:
        91:f2:03:61:8c:66:cf:43:68:f4:7d:29:5e:39:e8:09:77:e3:
        20:7b:09:77:b0:3a:5e:aa:ae:a0:90:53:71:78:48:f2:a0:b3:
        df:66:30:a5:27:07:1a:9a:74:10:7c:9c:5c:1d:74:50:81:af:
        f2:57:0b:5e:f0:c4:59:e3:9b:60:81:09:03:17:9b:e4:45:b4:
        95:50:f4:d0:d0:5a:10:ca:f8:a1:3c:f9:f8:e8:f3:de:79:cb:
        fb:4e:44:19:ba:fd:15:33:60:7b:48:b3:dd:ec:4f:78:7d:74:
        38:24:21:58
-----BEGIN CERTIFICATE-----
MIIDLjCCAhagAwIBAgIUOsp7p7z6lG+wtq+CPzgce8wgldEwDQYJKoZIhvcNAQEL
BQAwHDEaMBgGA1UEAwwRbXJ1YnktdGxzIHRlc3QgQ0EwHhcNMjAwMTAxMDAwMDAw
WhcNMjAwMjAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQChE/UI7W1zKwJ7NBuDa3E8VOc07vrRbWDA
j3m37Ca2H7QxNHqhy9bO0MCboCkv/+urSwnPnI2eNurOZ0FpOZVBLsjVaP5sljM9
h5r375UQPhsNZTPXvaa/iMxKAHRVZqmtUAJx/UGZwSygzaLL0HkZOvO0W9Y+NrO1
OjyUiw0qUpSiHPoiaRSDGtZ2vORSyzUdtPnopYviUgyAVkV5eksVC/Dg1DgSQbc/
CcS+VlU3yqJuvBgYtsA8kNNJ9jt0ePxPiBTy9ZtmrlpYPOLLaa4mlOvLATtM/xJH
Y/yAclHPzGC90uh3QywlLMC66z+paUYDLippsOOIbD/23txXVuYtAgMBAAGjcDBu
MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAd
BgNVHQ4EFgQUZ2dvUuWHXVbwWEV2dof3m7odFDkwHwYDVR0jBBgwFoAUldJbdqYV
pheC5+VnAcGCGMqqYG8wDQYJKoZIhvcNAQELBQADggEBAFYRKmgWPSDXjXB4jrlz
EC9bNnhoetgdl0OunPYOFRGndtkdB0aTL0VbMDbcBKLlDziLvKf80MUqvL+hbJEG
5HndY3/N6ptQZwZ94sP1nBF1+QTu6ipe3Ih7jgeBe8qewXpGzJhaZZventjTu7mt
gWa8QHv2rlZYk5KoxP/suNvmINTsYy23YdlcvaNmyG1ucZHyA2GMZs9DaPR9KV45
6Al34yB7CXewOl6qrqCQU3F4SPKgs99mMKUnBxqadBB8nFwddFCBr/JXC17wxFnj
m2CBCQMXm+RFtJVQ9NDQWhDK+KE8+fjo8955y/tORBm6/RUzYHtIs93sT3h9dDgk
IVg=
-----END CERTIFICATE-----
PEM

TLS_TEST_KEY_PEM = <<'PEM'
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQChE/UI7W1zKwJ7
NBuDa3E8VOc07vrRbWDAj3m37Ca2H7QxNHqhy9bO0MCboCkv/+urSwnPnI2eNurO
Z0FpOZVBLsjVaP5sljM9h5r375UQPhsNZTPXvaa/iMxKAHRVZqmtUAJx/UGZwSyg
zaLL0HkZOvO0W9Y+NrO1OjyUiw0qUpSiHPoiaRSDGtZ2vORSyzUdtPnopYviUgyA
VkV5eksVC/Dg1DgSQbc/CcS+VlU3yqJuvBgYtsA8kNNJ9jt0ePxPiBTy9ZtmrlpY
POLLaa4mlOvLATtM/xJHY/yAclHPzGC90uh3QywlLMC66z+paUYDLippsOOIbD/2
3txXVuYtAgMBAAECggEACNUxE+D/JjhWzb48/v8iibonJowvRVIv4sdLV6ZTtht1
dFhKHDqzCArC8RW+hHMOb4lxG4kca+9bf1+CovxFHrqrySYVg4tV+nsH6K4i2K3r
KlghGGS+MtUTzMALIQ684bPYOnt2gDGrWpMEKRSAu30z1XFOxYEW6CpuHYAlg+tG
j0YHzXGJ8flbvP9zNQSFedCd+hjtcNBG2N8q9WYBE40paqlM83XZJkHE0fhU1Kxw
VdBRz3dpe/NICPdSIFpOZQKg9WMRYX1ExIDwYyT9v9xBo9FyZlVMINJu6X3Lr2MA
lHqMceM7S+GfoW3BFacEqdfe8vMxoGoeFLclmKqfUQKBgQDUuGcYmkqzgtu2NPRw
VmMhkxHFBMD8iCsRP0hK7R3WyDbblEJNL3HeOOVLAg9+7MkifxGIyR0KfU09L5ls
4kJS8OS/hj63zZW6OUInwOaK2zpAi1TrkIRiOR6b73fX5OszA4i4MKaSJAok6mH6
gCte+h/+7+e9v8Id3Anbcng2UQKBgQDB2b9Zi96q1bvBAiy8rvC0ghm9AS1XZdrb
C6Cgqb+Gnw5Sl2eK6gVa5TPEiGOhT9AUenTJWM86hVA7R2AYTfmz30Ax5SuozrUg
t0zfQgxlpG7PgH2Vb/WEXM2PuqdeSIEe8qUpLLkeNUjlgNUrfNQYqQdGXJ9qlsPZ
a+82p2oPHQKBgQC6CjC4drCggPDxUSz7VsJKKdrfqYGzGtA3vFXYmbqADwjTT74Q
zU7UIISA7mNpCWP7lJBcRi/s7ZtwyMFxVgzVhzM4Qgt2KwopHUy7gdzfUk6HBpSV
lQYC9ZvMm0n/+oitTAj1ti7oHzb0BDz+nbvQzAbRqzXNYPk/riK810dFkQKBgB7O
avFhIAbIJqlanh9yMcCN+Gcn+7uq7SfoZiOCNnS/bDhF5WeXHzi9ugdeoW6uT2Qh
vdONsIkdTI3PHv9dzPP/46TKRbDzAKftWWMVjQDOK+oAAnUwMLVTRju0Lwr1vMdd
SlAL0nNxhl8qpTXfBZnRqt1MtOzsfr1bwM1Pt7QlAoGBAKHUZQEnXWyXwOQNkn2q
EfpWlQAUPr6KTCePIs/fqv1cO4pTuQs1kKwU1nanVX6WLy1SaKy+AEt2xbt3giNi
TtMMjD+WlET4QIKU2aofjS0t5oipB8w2AnZNqnNTVQRTovNq2IkGPT1DktUiHeU0
8fwq/rpadmBYg2UieeIPUGbB
-----END PRIVATE KEY-----
PEM

TLS_TEST_CA_FILE = '/tmp/mruby-tls-test-ca.pem'

File.open(TLS_TEST_CA_FILE, 'w') { |f| f.write(TLS_TEST_CA_PEM) }

# Server config presenting +cert+ (exercises cert_mem=/key_mem= too).
def tls_test_server_config(cert)
  cfg = Tls::Config.new
  cfg.cert_mem = cert
  cfg.key_mem  = TLS_TEST_KEY_PEM
  cfg
end

def tls_test_client_config(ca: true, noverify: [])
  cfg = Tls::Config.new
  cfg.ca_file = TLS_TEST_CA_FILE if ca
  noverify.each { |mode| cfg.noverify(mode) }
  cfg
end

# Runs a full handshake between an in-process server and client.  Returns nil
# when the client accepted the peer, or the exception it rejected it with.
def tls_test_handshake(server_cfg, client_cfg, hostname)
  listener = TCPServer.new('127.0.0.1', 0)
  csock = TCPSocket.new('127.0.0.1', listener.addr[1])
  ssock = listener.accept
  csock._setnonblock(true)
  ssock._setnonblock(true)

  sconn  = Tls::Server.new(server_cfg).accept_socket(ssock)
  client = Tls::Client.new(client_cfg)
  client.connect_socket(csock, hostname)

  client_err = nil
  cdone = false
  sdone = false

  # Both ends are non-blocking, so step them alternately.  The iteration cap
  # keeps a stalled peer from hanging the suite.
  1000.times do
    unless sdone
      begin
        sdone = !sconn.handshake_nonblock.is_a?(Symbol)
      rescue StandardError
        # The server legitimately errors out when the client rejects it.
        sdone = true
      end
    end
    unless cdone
      begin
        cdone = !client.handshake_nonblock.is_a?(Symbol)
      rescue StandardError => e
        client_err = e
        cdone = true
      end
    end
    break if cdone && sdone
  end

  raise 'handshake did not settle' unless cdone
  yield client if client_err.nil? && block_given?
  client_err
ensure
  sconn.close rescue nil
  client.close rescue nil
  ssock.close rescue nil
  csock.close rescue nil
  listener.close rescue nil
end

def tls_test_accepts(server_cfg, client_cfg, hostname)
  tls_test_handshake(server_cfg, client_cfg, hostname).nil?
end

assert('Tls verification: valid chain and matching name is accepted') do
  assert_true tls_test_accepts(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_test_client_config, 'localhost')
end

assert('Tls verification: hostname mismatch is rejected') do
  err = tls_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                           tls_test_client_config, 'wrong.example')
  assert_kind_of Tls::Error, err
end

assert('Tls verification: untrusted issuer is rejected') do
  err = tls_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                           tls_test_client_config(ca: false), 'localhost')
  assert_kind_of Tls::Error, err
end

assert('Tls verification: expired certificate is rejected') do
  err = tls_test_handshake(tls_test_server_config(TLS_TEST_EXPIRED_PEM),
                           tls_test_client_config, 'localhost')
  assert_kind_of Tls::Error, err
end

assert('Tls verification: noverify("name") waives only the hostname check') do
  # Name mismatch now tolerated ...
  assert_true tls_test_accepts(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_test_client_config(noverify: ['name']),
                               'wrong.example')
  # ... but an untrusted chain is still refused.
  err = tls_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                           tls_test_client_config(ca: false, noverify: ['name']),
                           'wrong.example')
  assert_kind_of Tls::Error, err
end

assert('Tls verification: noverify("time") waives only the validity period') do
  assert_true tls_test_accepts(tls_test_server_config(TLS_TEST_EXPIRED_PEM),
                               tls_test_client_config(noverify: ['time']),
                               'localhost')
  # Expiry tolerated, but the name is still checked.
  err = tls_test_handshake(tls_test_server_config(TLS_TEST_EXPIRED_PEM),
                           tls_test_client_config(noverify: ['time']),
                           'wrong.example')
  assert_kind_of Tls::Error, err
end

# This is the one configuration that cannot be expressed with mbedTLS'
# authmode alone: the chain is not validated (VERIFY_OPTIONAL, which does NOT
# abort the handshake by itself) while the hostname still has to match.  If
# the explicit post-handshake check ever stops running, the second half of
# this test is what catches it.
assert('Tls verification: noverify("cert") still enforces the hostname') do
  assert_true tls_test_accepts(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_test_client_config(ca: false, noverify: ['cert']),
                               'localhost')
  err = tls_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                           tls_test_client_config(ca: false, noverify: ['cert']),
                           'wrong.example')
  assert_kind_of Tls::Error, err
end

assert('Tls verification: noverify("cert") and noverify("name") accept anything') do
  assert_true tls_test_accepts(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_test_client_config(ca: false,
                                                      noverify: ['cert', 'name']),
                               'wrong.example')
end

assert('Tls::Config#verify re-enables every axis') do
  cfg = tls_test_client_config(ca: false)
  cfg.noverify('cert')
  cfg.noverify('name')
  cfg.verify
  err = tls_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                           cfg, 'wrong.example')
  assert_kind_of Tls::Error, err
end

assert('Tls::Config#noverify rejects an unknown mode') do
  assert_raise(ArgumentError) { Tls::Config.new.noverify('everything') }
end

assert('Tls negotiates a modern protocol version') do
  version = nil
  cipher  = nil
  err = tls_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                           tls_test_client_config, 'localhost') do |client|
    version = client.version
    cipher  = client.cipher
  end
  assert_nil err
  # mbedTLS 3.x cannot negotiate anything older, and must not silently do so.
  assert_include ['TLSv1.2', 'TLSv1.3'], version
  assert_kind_of String, cipher
end

# The API master established, pinned so a backend swap cannot quietly
# change it again.
#
# This exists because the OpenSSL rewrite renamed the symbols the
# _nonblock methods return - :tls_want_pollin/:tls_want_pollout became
# :wait_readable/:wait_writable - and that break is invisible at runtime.
# A caller written as `case conn.read_nonblock(n) when :tls_want_pollin`
# simply stops matching: no exception, no warning, the connection just
# stalls. Nothing in the suite noticed.
assert('nonblock methods return master\'s :tls_want_poll* symbols') do
  # Both ends non-blocking and the client silent, so the server's first
  # handshake step has nothing to read and must say so - with the name
  # callers actually match on.
  listener = TCPServer.new('127.0.0.1', 0)
  csock    = TCPSocket.new('127.0.0.1', listener.addr[1])
  ssock    = listener.accept
  csock._setnonblock(true)
  ssock._setnonblock(true)

  sconn = Tls::Server.new(tls_test_server_config(TLS_TEST_CERT_PEM)).accept_socket(ssock)
  got   = sconn.handshake_nonblock

  # The exact name is the contract. tls_test_handshake only asks
  # `is_a?(Symbol)`, which is why the rename from :tls_want_pollin to
  # :wait_readable passed the whole suite without a murmur.
  assert_equal :tls_want_pollin, got
ensure
  sconn.close rescue nil
  ssock.close rescue nil
  csock.close rescue nil
  listener.close rescue nil
end

assert('every method master defined is still callable') do
  # Names only - a missing one is a NoMethodError for somebody's code
  # that this gem promised would keep working.
  %i[ca_file= ca_path= cert_file= cert_mem= ciphers= clear_keys
     ecdhecurve= key_file= key_mem= noverify parse_protocols
     protocols= verify verify_depth=].each do |m|
    assert_true Tls::Config.method_defined?(m), "Tls::Config##{m} is gone"
  end
  %i[cipher close close_nonblock configure handshake handshake_nonblock
     read read_nonblock reset version write write_nonblock].each do |m|
    assert_true Tls::Context.method_defined?(m), "Tls::Context##{m} is gone"
  end
  %i[connect connect_fds connect_socket].each do |m|
    assert_true Tls::Client.method_defined?(m), "Tls::Client##{m} is gone"
  end
  assert_true Tls::Server.method_defined?(:accept_socket)
  assert_true Tls.respond_to?(:load_file)
  %i[TLSv1 TLSv1_0 TLSv1_1 TLSv1_2 TLSv1_3 All Default].each do |c|
    assert_true Tls::Protocol.const_defined?(c), "Tls::Protocol::#{c} is gone"
  end
end
