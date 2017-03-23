#!/usr/bin/env python

"""
   ieee15dot4 - a python module defining IEEE 802.15.4 MAC frames

   Copyright (c) 2014, Andrew Dodd (andrew.john.dodd@gmail.com)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
"""

import binascii
from datetime import datetime
import struct


# http://stackoverflow.com/questions/36932/how-can-i-represent-an-enum-in-python
# Usage: Numbers = enum('ZERO', 'ONE', 'TWO')
#        Numbers = enum(ONE=1, TWO=2, THREE='three')
#        Numbers.ONE
#        Numbers.fromValue['three']
def enum(*sequential, **named):
    """Build a new type that mocks an ENUM"""
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.items())
    enums['fromValue'] = reverse
    return type('Enum', (), enums)


def check_and_unpack(fmt, buffer, offset, default):
    """Checks that there are enough bytes in the buffer before unpacking
    
    This function uses the provided format string to check if there are
    enough bytes to unpack from the buffer. If not it returns the default
    provided."""

    if len(buffer[offset:]) < struct.calcsize(fmt):
        return default

    return struct.unpack_from(fmt, buffer, offset)


class FrameType(object):
    BEACON = 0
    DATA = 1
    ACK = 2
    MAC_CMD = 3
    LLDN = 4
    MULTIPURPOSE = 5
    UNKNOWN = 255
    MASK = 7

    @staticmethod
    def classify(value):
        masked_value = (FrameType.MASK & value)
        if masked_value is FrameType.BEACON:
            return FrameType.BEACON
        if masked_value is FrameType.DATA:
            return FrameType.DATA
        if masked_value is FrameType.ACK:
            return FrameType.ACK
        if masked_value is FrameType.MAC_CMD:
            return FrameType.MAC_CMD
        if masked_value is FrameType.LLDN:
            return FrameType.LLDN
        if masked_value is FrameType.MULTIPURPOSE:
            return FrameType.MULTIPURPOSE

        return FrameType.UNKNOWN

    @staticmethod
    def to_string(value):
        if value is FrameType.BEACON:
            return "Beacon"
        if value is FrameType.DATA:
            return "Data"
        if value is FrameType.ACK:
            return "Acknowledgment"
        if value is FrameType.MAC_CMD:
            return "MAC Command"
        if value is FrameType.LLDN:
            return "LLDN"
        if value is FrameType.MULTIPURPOSE:
            return "Multipurpose"

        return "Unknown"


class AddressingMode(object):
    NONE = 0
    SIMPLE = 1
    SHORT = 2
    EXTENDED = 3
    UNKNOWN = 255
    MASK = 3

    @staticmethod
    def classify(value):
        if AddressingMode.NONE == (AddressingMode.MASK & value):
            return AddressingMode.NONE
        if AddressingMode.SIMPLE == (AddressingMode.MASK & value):
            return AddressingMode.SIMPLE
        if AddressingMode.SHORT == (AddressingMode.MASK & value):
            return AddressingMode.SHORT
        if AddressingMode.EXTENDED == (AddressingMode.MASK & value):
            return AddressingMode.EXTENDED

        return AddressingMode.UNKNOWN

    @staticmethod
    def to_string(value):
        if AddressingMode.NONE == value:
            return "None"
        if AddressingMode.SIMPLE == value:
            return "Simple"
        if AddressingMode.SHORT == value:
            return "Short"
        if AddressingMode.EXTENDED == value:
            return "Extended"

        raise ValueError(value)


class FCF(object):
    def __init__(self, frametype, security_enabled, frame_pending, ack_requested, pan_id_compression,
                 dest_addressing_mode, frame_version, source_addressing_mode):
        self.frametype = frametype
        self.securityEnabled = security_enabled
        self.framePending = frame_pending
        self.ackRequested = ack_requested
        self.panIdCompression = pan_id_compression
        self.destAddressingMode = dest_addressing_mode
        self.frameVersion = frame_version
        self.sourceAddressingMode = source_addressing_mode

    @staticmethod
    def parse(fcf):
        return FCF(FrameType.classify(fcf),  # FrameType.MASK & value
                   bool((fcf >> 3) & 0x01),
                   bool((fcf >> 4) & 0x01),
                   bool((fcf >> 5) & 0x01),
                   bool((fcf >> 6) & 0x01),
                   # 7-9: reserved
                   AddressingMode.classify(fcf >> 10),
                   (fcf >> 12) & 0x03,
                   AddressingMode.classify(fcf >> 14))


class SFS(object):
    def __init__(self, beacon_order, super_frame_order, final_cap_slot, ble, is_pan_coordinator,
                 is_association_permitted):
        self.beaconOrder = beacon_order
        self.superFrameOrder = super_frame_order
        self.finalCAPSlot = final_cap_slot
        self.ble = ble
        self.isPANCoordinator = is_pan_coordinator
        self.isAssociationPermitted = is_association_permitted

    def __repr__(self, *args, **kwargs):
        return "SFS[BO[{}] SO[{}]]".format(self.beaconOrder, self.superFrameOrder)

    @staticmethod
    def parse(sfs):
        return SFS(0x0F & sfs,
                   0x0F & (sfs >> 4),
                   0x0F & (sfs >> 8),
                   bool(0x01 & (sfs >> 12)),
                   bool(0x01 & (sfs >> 14)),
                   bool(0x01 & (sfs >> 15)))


class SimpleAddress(object):
    def __init__(self, pan_id, simple_address):
        self.panId = pan_id
        self.address = simple_address

    def __repr__(self, *args, **kwargs):
        return "PAN[{:x}] SimpleAddr[{:x}]".format(self.panId, self.address)


class ShortAddress(object):
    def __init__(self, pan_id, short_address):
        self.panId = pan_id
        self.address = short_address

    def __repr__(self, *args, **kwargs):
        return "PAN[{:x}] ShortAddr[{:x}]".format(self.panId, self.address)


class ExtendedAddress(object):
    def __init__(self, pan_id, ext_address):
        self.panId = pan_id
        self.address = ext_address

    def __repr__(self, *args, **kwargs):
        return "PAN[{:x}] ExtAddr[{:x}]".format(self.panId, self.address)


class AddressingFields(object):
    def __init__(self, length, destination_address, source_address):
        self.length = length
        self.destinationAddress = destination_address
        self.sourceAddress = source_address

    def __repr__(self, *args, **kwargs):
        output = []
        if self.destinationAddress is not None:
            output.append("Destination[{}]".format(self.destinationAddress))
        if self.sourceAddress is not None:
            output.append("Source[{}]".format(self.sourceAddress))

        return "Addresses[{}]".format(" ".join(output))

    @staticmethod
    def parse(fcf, byte_stream_at_addresses):
        length = 0

        if fcf.destAddressingMode is AddressingMode.NONE:
            destination_address = None
            dest_pan_id = None
        else:
            destination_address = None
            (dest_pan_id,) = struct.unpack_from("<H", byte_stream_at_addresses, length)
            length += 2

        if fcf.destAddressingMode is AddressingMode.SIMPLE:
            (destSimpleId,) = struct.unpack_from("<B", byte_stream_at_addresses, length)
            destination_address = SimpleAddress(dest_pan_id, destSimpleId)
            length += 1
        if fcf.destAddressingMode is AddressingMode.SHORT:
            (destShortId,) = struct.unpack_from("<H", byte_stream_at_addresses, length)
            destination_address = ShortAddress(dest_pan_id, destShortId)
            length += 2
        if fcf.destAddressingMode is AddressingMode.EXTENDED:
            (destExtId,) = struct.unpack_from("<Q", byte_stream_at_addresses, length)
            destination_address = ExtendedAddress(dest_pan_id, destExtId)
            length += 8

        if fcf.sourceAddressingMode is AddressingMode.NONE:
            source_address = None
            src_pan_id = None
        else:
            source_address = None
            if False is fcf.panIdCompression:
                (src_pan_id,) = struct.unpack_from("<H", byte_stream_at_addresses, length)
                length += 2
            else:
                if fcf.destAddressingMode is AddressingMode.NONE:
                    print("error, pan compression but no destination address!")
                    dest_pan_id = None

                src_pan_id = dest_pan_id

        if fcf.sourceAddressingMode is AddressingMode.SIMPLE:
            (srcSimpleId,) = struct.unpack_from("<B", byte_stream_at_addresses, length)
            source_address = SimpleAddress(src_pan_id, srcSimpleId)
            length += 1
        if fcf.sourceAddressingMode is AddressingMode.SHORT:
            (srcShortId,) = struct.unpack_from("<H", byte_stream_at_addresses, length)
            source_address = ShortAddress(src_pan_id, srcShortId)
            length += 2
        if fcf.sourceAddressingMode is AddressingMode.EXTENDED:
            (srcExtId,) = struct.unpack_from("<Q", byte_stream_at_addresses, length)
            source_address = ExtendedAddress(src_pan_id, srcExtId)
            length += 8

        return AddressingFields(length, destination_address, source_address)


class IEEE15dot4Frame(object):
    def __init__(self, timestamp, fcf, sequence_number, addressing, msdu, *args, **kwargs):
        self.time = datetime.now()
        self.timestamp = timestamp
        self.fcf = fcf
        self.sequenceNumber = sequence_number
        self.addressing = addressing
        self.msdu = msdu

    def __repr__(self, *args, **kwargs):
        output = ["{} -".format(FrameType.to_string(self.fcf.frametype)), "Time[{}]".format(self.time),
                  "{}".format(self.addressing), "MSDU[{}]".format(binascii.hexlify(self.msdu))]

        return " ".join(output)


class IEEE15dot4AckFrame(IEEE15dot4Frame):
    def __init__(self, *args, **kwargs):
        super(IEEE15dot4AckFrame, self).__init__(*args, **kwargs)

    def __repr__(self, *args, **kwargs):
        output = ["{} -".format(FrameType.to_string(self.fcf.frametype)), "SeqNum[{}]".format(self.sequenceNumber)]

        return " ".join(output)


class IEEE15dot4BeaconFrame(IEEE15dot4Frame):
    def __init__(self, sfs, gts, pending_short_addresses, pending_ext_addresses, beacon_payload, *args, **kwargs):
        super(IEEE15dot4BeaconFrame, self).__init__(*args, **kwargs)
        self.sfs = sfs
        self.gts = gts
        self.pendingShortAddresses = pending_short_addresses
        self.pendingExtAddresses = pending_ext_addresses
        self.beaconPayload = beacon_payload

    def __repr__(self, *args, **kwargs):
        output = ["{} -".format(FrameType.to_string(self.fcf.frametype)), "Time[{}]".format(self.time),
                  "{}".format(self.sfs), "{}".format(self.addressing)]

        if len(self.pendingShortAddresses) > 0:
            addresses = ["{:x}".format(addr) for addr in self.pendingShortAddresses]
            output.append("PendingShort[{}]".format(",".join(addresses)))

        if len(self.pendingExtAddresses) > 0:
            addresses = ["{:x}".format(addr) for addr in self.pendingExtAddresses]
            output.append("PendingExt[{}]".format(",".join(addresses)))

        output.append("Payload[{}]".format(binascii.hexlify(self.beaconPayload)))

        return " ".join(output)


CommandFrameType = enum(
    AssociationRequest=1,
    AssociationResponse=2,
    DisassociationNotification=3,
    DataRequest=4,
    PANIdConflictNotification=5,
    OrphanNotification=6,
    BeaconRequest=7,
    CoordinatorRealignment=8,
    GTSRequest=9)


class IEEE15dot4CommandFrame(IEEE15dot4Frame):
    def __init__(self, command_id, payload, *args, **kwargs):
        super(IEEE15dot4CommandFrame, self).__init__(*args, **kwargs)
        self.commandId = command_id
        # noinspection PyUnresolvedReferences
        self.command = CommandFrameType.fromValue[command_id]
        self.additionalInfo = {}

        # noinspection PyUnresolvedReferences
        if self.commandId is CommandFrameType.AssociationRequest:
            fmt = "<B"
            (capabilityInfo,) = check_and_unpack(fmt, payload, 0, 0)

            self.additionalInfo["allocateAddress"] = bool(0x01 & (capabilityInfo >> 7))
            self.additionalInfo["securityCapable"] = bool(0x01 & (capabilityInfo >> 6))
            self.additionalInfo["rxOnWhenIdle"] = bool(0x01 & (capabilityInfo >> 3))
            self.additionalInfo["isPowered"] = bool(0x01 & (capabilityInfo >> 2))
            self.additionalInfo["isFullFunctionDevice"] = bool(0x01 & (capabilityInfo >> 1))

        elif self.commandId is CommandFrameType.AssociationResponse:
            fmt = "<HB"
            (shortAddress, associationStatus) = check_and_unpack(fmt, payload, 0, 0)

            self.additionalInfo["shortAddress"] = shortAddress

            self.additionalInfo["associationStatus"] = {0: "Successful",
                                                        1: "PAN At Capacity",
                                                        2: "PAN Access Denied",
                                                        }.get(associationStatus, "Reserved")

        elif self.commandId is CommandFrameType.DisassociationNotification:
            fmt = "<B"
            (disassociationReason,) = check_and_unpack(fmt, payload, 0, 0)

            self.additionalInfo["disassociationReason"] = {0: "Reserved",
                                                           1: "Coord requested leave",
                                                           2: "Device requested leave",
                                                           }.get(disassociationReason, "Reserved")

        elif self.commandId is CommandFrameType.CoordinatorRealignment:
            fmt = "<HHBH"
            (panId, coordShortAddress, channelNumber, shortAddress,) = check_and_unpack(fmt, payload, 0, 0)
            # NB: Channel Page not decoded

            self.additionalInfo["panId"] = panId
            self.additionalInfo["coordShortAddress"] = coordShortAddress
            self.additionalInfo["channelNumber"] = channelNumber
            self.additionalInfo["shortAddress"] = shortAddress

    def __repr__(self, *args, **kwargs):
        output = ["{} -".format(FrameType.to_string(self.fcf.frametype)), "Time[{}]".format(self.time),
                  "SeqNum[{}]".format(self.sequenceNumber), "{}".format(self.addressing),
                  "Command[{}]".format(self.command), "AdditionalInfo[{}]".format(self.additionalInfo)]

        return " ".join(output)


class IEEE15dot4FrameFactory(object):
    @staticmethod
    def parse(packet):
        byte_stream = packet.get_mac_pdu()
        offset = 0
        (fcfVal, seqNum) = struct.unpack_from("<HB", byte_stream, offset)
        offset += 3

        fcf = FCF.parse(fcfVal)

        addressing_fields = AddressingFields.parse(fcf, byte_stream[offset:])
        offset += addressing_fields.length

        frame = IEEE15dot4Frame(packet.get_timestamp(), fcf, seqNum, addressing_fields, byte_stream[offset:])

        if fcf.frametype is FrameType.ACK:
            return IEEE15dot4AckFrame(**frame.__dict__)
        elif fcf.frametype is FrameType.BEACON:
            return IEEE15dot4FrameFactory.__parse_beacon(frame)
        elif fcf.frametype is FrameType.MAC_CMD:
            return IEEE15dot4FrameFactory.__parse_mac_command(frame)

        return frame

    # noinspection PyUnusedLocal
    @staticmethod
    def __parse_beacon(frame, **kwargs):
        byte_stream = frame.msdu
        offset = 0
        fmt = "<HB"
        (super_frameSpecification, gts) = check_and_unpack(fmt, byte_stream, offset, (0, 0))
        offset += struct.calcsize(fmt)

        fmt = "<B"
        (pendingAddressesSpec,) = check_and_unpack(fmt, byte_stream, offset, 0)
        offset += struct.calcsize(fmt)

        pending_short_count = 0x07 & pendingAddressesSpec
        pending_ext_count = 0x07 & (pendingAddressesSpec >> 4)

        pending_short_addresses = []
        pending_ext_addresses = []

        fmt = "<H"
        for i in range(pending_short_count):
            (nextShortAddress,) = check_and_unpack(fmt, byte_stream, offset, 0)
            offset += struct.calcsize(fmt)
            pending_short_addresses.append(nextShortAddress)

        fmt = "<Q"
        for i in range(pending_ext_count):
            (nextExtAddress,) = check_and_unpack(fmt, byte_stream, offset, 0)
            offset += struct.calcsize(fmt)
            pending_ext_addresses.append(nextExtAddress)

        return IEEE15dot4BeaconFrame(SFS.parse(super_frameSpecification),
                                     gts,
                                     pending_short_addresses,
                                     pending_ext_addresses,
                                     byte_stream[offset:],
                                     **frame.__dict__)

    # noinspection PyUnusedLocal
    @staticmethod
    def __parse_mac_command(frame, **kwargs):
        byte_stream = frame.msdu
        offset = 0
        fmt = "<B"
        (commandId,) = check_and_unpack(fmt, byte_stream, offset, (0, 0))
        offset += struct.calcsize(fmt)

        return IEEE15dot4CommandFrame(commandId,
                                      byte_stream[offset:],
                                      **frame.__dict__)
