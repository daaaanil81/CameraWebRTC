"""
    :Authors:
        Petrov D.M. GROUP: CIT-26b
    :Version: 0.0.1 of 2018/12/15
    :platform: Unix, Windows
    |
    |
    |
"""
import socket
from datetime import datetime
import bitstring
import base64

def SessionFrame(fr):
    """
    :param fr: String frame with part of photo.
    >>> P = frame[2]
    P: False
    >>> X = frame[3]
    X: False
    >>>version = frame[0:2].uint
    Version: 2  CC(size sender): 0
    >>> CC = frame[4:8].uint  # size sender
    CC(size sender): 0
    >>> M = frame[8]
    M: False
    >>> PT = frame[9:16].uint  # type encoding name
    PT: 96
    >>> SN = frame[16:32].uint  # number of packege
    NUMBER Package: 51196
    >>> TimeMarker = frame[32:64].uint
    TimeMarker: 3395095627
    >>> SSRC = frame[64:96]
    SSRC: 0x90ea0a57
    :return:  data with part of photo.
    """
    start_bytes2 = b'\x00\x00\x01'
    frame = bitstring.BitArray(fr)
    version = frame[0:2].uint

    P = frame[2]
    X = frame[3]
    CC = frame[4:8].uint  # size sender

    rtp_first_byte = frame[0:8].uint

    M = frame[8]
    PT = frame[9:16].uint  # type encoding name
    SN = frame[16:32].uint  # number of packege
    TimeMarker = frame[32:64].uint
    SSRC = frame[64:96]
    cont1 = frame[96:99]

    F = frame[96]  # 1 - error 0 - OK
    NRI = frame[97:99]  # 0 <  need frame, 0 - not need frame
    TypeFrame = frame[99:104].uint
    FU_INDICATOR = frame[96:104].uint

    S = frame[104]  # 1 - start
    E = frame[105]  # 1 - end
    R = frame[106]  # continue
    TypeNAL = frame[107:112].uint

    print(f"Version: {version} X: {X} CC(size sender): {CC}")
    print(f"First byte of RTP: {rtp_first_byte}")
    print(f"P: {P} M: {M} PT: {PT} ")
    print(f"NUMBER Package: {SN}")
    print(f"TimeMarker: {TimeMarker}")
    print(f"SSRC: {SSRC}")
    print(f"F: {F}")
    print(f"NRI: {NRI}")
    print(f"TypeFrame: {TypeFrame}")
    print(f"FU INDIcator: {FU_INDICATOR}")

    print(f"S: {S}")
    print(f"E: {E}")
    print(f"TypeNAL: {TypeNAL}")


host = '0.0.0.0'

size = 2048
"""Size data for read."""
port = 9011
"""TCP port."""
address = (host, port)

print("Starting the serverUDP: ", datetime.now())
serverUDP = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverUDP.bind(address)

NumFrame = 1
while NumFrame <= 50:
    dataUDP, ser = serverUDP.recvfrom(size)
    print(f"NumFrame: {NumFrame}")
    SessionFrame(dataUDP)
    NumFrame += 1
    print()
print('\n')

serverUDP.close()
