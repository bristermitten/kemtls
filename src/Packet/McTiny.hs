module Packet.McTiny where

import Packet.Generic (KEMTLSPacket)

class (KEMTLSPacket a) => McTinyPacket a
