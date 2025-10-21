# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

DELIMITER = 0x7E
APIESC = 0x7D

# parser status
PS_IDLE = 0
PS_LENH = 1
PS_LENL = 2
PS_DATA = 3
PS_CHECKSUM = 4

# XBee API frame types
FT_LOCAL_AT_COMMAND_REQUEST = 0x08
FT_TRANSMIT_REQUEST = 0x10
FT_LOCAL_AT_COMMAND_RESPONSE = 0x88
FT_MODEM_STATUS = 0x8A
FT_RECEIVE_PACKET = 0x90

ftnames = {
    FT_LOCAL_AT_COMMAND_REQUEST: 'Local AT command request',
    FT_TRANSMIT_REQUEST: 'Transmit request',
    FT_LOCAL_AT_COMMAND_RESPONSE: 'Local AT command response',
    FT_MODEM_STATUS: 'Modem status',
    FT_RECEIVE_PACKET: 'Receive packet'
}

at_dict = {
    "BC": "Bytes Transmitted",
    "CH": "Channel",
    "CM": "Channel Mask",
    "EE": "Encryption Enable",
    "HV": "Hardware Version",
    "NP": "Maximum Packet Payload Bytes",
    "ID": "Network ID",
    "KY": "AES Encryption Key",
    "SL": "Serial Number Low",
    "SH": "Serial Number High",
    "VR": "Firmware Version"
    
}

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    apimode_setting = ChoicesSetting(choices=('1', '2'))

    result_types = {
        'frame': {
            'format': '{{{data.frame_type}}}',
            'payload': '{{{data.payload}}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.
        '''

        self.state = PS_IDLE #IDLE
        self.apiframe_starttime = None
        self.apiframe_endtime = None
        self.esc = False # ESC status for API mode 2
        self.apiframelen = 0
        self.checksum = 0
        self.framedata = bytearray()
        self.apiesc = False

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.
        The type and data values in `frame` will depend on the input analyzer.
        '''

        b = frame.data['data'][0]
        payload = '-'

        if self.apimode_setting == "2":
            if self.apiesc:
                b = b ^ 0x20
                self.apiesc = False
            else:
                if b == APIESC:
                    self.apiesc = True
                    return
                elif b == DELIMITER:
                    self.state = PS_IDLE

        if self.state == PS_IDLE:
            if b == DELIMITER:
                self.checksum = 0
                self.apiframe_starttime = frame.start_time
                self.state = PS_LENH

        elif self.state == PS_LENH:
            self.apiframelen = b * 10
            self.state = PS_LENL

        elif self.state == PS_LENL:
            self.apiframelen += b
            self.state = PS_DATA
            self.framedata = bytearray()

        elif self.state == PS_DATA:
            self.framedata.append(b)
            self.checksum += b
            self.apiframelen -= 1
            if self.apiframelen == 0:
                self.state = PS_CHECKSUM

        elif self.state == PS_CHECKSUM:
            self.checksum += b
            self.checksum &= 0xFF
            frametype = self.framedata[0]
            if frametype in ftnames:
                ftname = ftnames[frametype]
            else:
                ftname = 'Unknown frame type ' + hex(frametype)

            if frametype == FT_LOCAL_AT_COMMAND_REQUEST:
                at = chr(self.framedata[2]) + chr(self.framedata[3])
                frmstr = '"' + at + '" '
                if at in at_dict:
                    frmstr += f"({at_dict[at]}) "
                for c in self.framedata[4:]:
                    frmstr += f'{c:02x} '

            elif frametype == FT_LOCAL_AT_COMMAND_RESPONSE:
                at = chr(self.framedata[2]) + chr(self.framedata[3])
                frmstr = '"'+ at + '"' + '" '
                if at in at_dict:
                    frmstr += f"({at_dict[at]}) "
                for c in self.framedata[5:]:
                    frmstr += f'{c:02x} '
                frmstr += ', cmd status ' + str(self.framedata[4])

            elif frametype == FT_MODEM_STATUS:
                frmstr = hex(self.framedata[1])

            elif frametype == FT_RECEIVE_PACKET:
                frmstr = f' {len(self.framedata) - 12} bytes payload, receive options 0x{self.framedata[11]:02X}'
                payload = ''.join('{:02x} '.format(a) for a in self.framedata[12:])

            elif frametype == FT_TRANSMIT_REQUEST:
                frmstr = f' {len(self.framedata) - 14} bytes payload, transmit options 0x{self.framedata[13]:02X}'
                payload = ''.join('{:02x} '.format(a) for a in self.framedata[14:])

            else:
                frmstr = ''

            if self.checksum != 0xFF:
                frmstr += ", CRC FAILURE!"

            self.state = PS_IDLE

            return AnalyzerFrame('frame', self.apiframe_starttime, frame.end_time, {
                'frame_type': ftname + ', ' + frmstr,
                'payload': payload
            })


