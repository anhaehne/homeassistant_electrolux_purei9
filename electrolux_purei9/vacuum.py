"""Platform for electrolux purei9 integration."""

import socket
import ssl
import struct
import time
import sys
import json
import sys
import base64
import hashlib
import logging
import requests
import requests.auth
import homeassistant.helpers.config_validation as cv
import voluptuous as vol

from homeassistant.components.vacuum import (
    ATTR_STATUS,
    STATE_CLEANING,
    STATE_DOCKED,
    STATE_ERROR,
    STATE_IDLE,
    STATE_PAUSED,
    STATE_RETURNING,
    SUPPORT_BATTERY,
    SUPPORT_LOCATE,
    SUPPORT_PAUSE,
    SUPPORT_RETURN_HOME,
    SUPPORT_SEND_COMMAND,
    SUPPORT_START,
    SUPPORT_STATE,
    SUPPORT_STATUS,
    SUPPORT_STOP,
    StateVacuumEntity,
)
from homeassistant.components.vacuum import PLATFORM_SCHEMA
from homeassistant.const import CONF_IP_ADDRESS, CONF_NAME, CONF_PASSWORD, CONF_EMAIL

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_NAME): cv.string,
        vol.Required(CONF_EMAIL): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Required(CONF_IP_ADDRESS): cv.string,
    }
)


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the vacuum platform."""

    name = config[CONF_NAME]
    email = config[CONF_EMAIL]
    password = config.get(CONF_PASSWORD)
    ip = config.get(CONF_IP_ADDRESS)

    client = CloudClient(email, password)

    robot = next(r for r in client.getRobots() if r.name == name)

    add_entities([PureI9(robot, ip)])


""" Code taken from https://github.com/Phype/purei9-cli/blob/master/purei9.py """


class CloudClient:
    def __init__(self, email, password):
        password = CloudClient.chksum(password)
        self.apiurl = "https://mobile.rvccloud.electrolux.com/api/v1"
        self.credentials = {
            "AccountPassword": password,
            "Email": email,
        }
        self.httpauth = requests.auth.HTTPBasicAuth(email, password)

    @staticmethod
    def chksum(pw):
        buf = pw + "947X6kdLJyrhlCDzUyzFwT4s4NZL3O8eLs0PE4Hi7hU="
        buf = buf.encode("utf-16")[2:]
        return base64.b64encode(hashlib.sha256(buf).digest()).decode("ascii")

    def getRobots(self):
        r = requests.post(
            self.apiurl + "/accounts/ConnectToAccount", json=self.credentials
        )
        try:
            return list(
                map(lambda r: CloudRobot(self, r["RobotID"], r), r.json()["RobotList"])
            )
        except:
            _LOGGER.error("Cannot login: " + str(r))

            for k in r.headers:
                _LOGGER.debug(k + ": " + r.headers[k])
            _LOGGER.debug(r.text)

    def getRobot(self, id):
        return CloudRobot(self, id)


class CloudRobot:
    def __init__(self, cloudclient, id, info=None):
        self.cloudclient = cloudclient
        self.id = id
        self.info = info

        if info:

            self.name = info["RobotName"]
            self.is_connected = info["Connected"]
            self.firmware = info["FirmwareVersion"]
            self.robot_status = info["RobotStatus"]
            self.battery_status = info["BatteryStatus"]
            self.local_pw = info["LocalRobotPassword"]

    def getMaps(self):
        r = requests.get(
            self.cloudclient.apiurl + "/robots/" + self.id + "/interactivemaps",
            auth=self.cloudclient.httpauth,
        )

        return list(map(lambda x: CloudMap(self, x["Id"]), r.json()))


class CloudMap:
    def __init__(self, cloudrobot, id):

        self.cloudclient = cloudrobot.cloudclient
        self.robot = cloudrobot
        self.id = id
        self.info = None
        self.image = None

    def get(self):
        r = requests.get(
            self.cloudclient.apiurl
            + "/robots/"
            + self.robot.id
            + "/interactivemaps/"
            + self.id,
            auth=self.cloudclient.httpauth,
        )

        js = r.json()

        self.image = base64.b64decode(js["PngImage"])

        del js["PngImage"]
        self.info = js

        return self.info


class RobotClient:

    MSG_HELLO = 3000
    MSG_LOGIN = 3005
    MSG_PING = 1000
    MSG_GETNAME = 1011
    MSG_GETFIRMWARE = 1010
    MSG_GETSETTINGS = 1023
    MSG_STARTCLEAN = 1014
    MSG_GETSTATUS = 1012

    CLEAN_PLAY = 1
    CLEAN_SPOT = 2
    CLEAN_HOME = 3
    CLEAN_PAUSE = 4  # Unused by App?
    CLEAN_STOP = 5  # Unused by App?

    STATES = {
        1: "Cleaning",
        2: "Paused Cleaning",
        3: "Spot Cleaning",
        4: "Paused Spot Cleaning",
        5: "Return",
        6: "Paused Return",
        7: "Return for Pitstop",
        8: "Paused Return for Pitstop",
        9: "Charging",
        10: "Sleeping",
        11: "Error",
        12: "Pitstop",
        13: "Manual Steering",
        14: "Firmware Upgrade",
    }

    STATE_CLEANING = 1
    STATE_PAUSED = 2
    STATE_SPOTCLEAN = 3
    STATE_PAUSEDSPOTCLEAN = 4
    STATE_RETURN = 5
    STATE_PAUSEDRETURN = 6
    STATE_RETURNPITSTOP = 7
    STATE_PAUSEDRETURNPITSTOP = 8
    STATE_CHARGING = 9
    STATE_SLEEPING = 10
    STATE_ERROR = 11
    STATE_PITSTOP = 12

    PROTOCOL_VERSION = 2016100701  # 2019041001

    def __init__(self, addr, localpw):
        self.port = 3002
        self.addr = addr
        self.localpw = localpw

        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

        self.robot_id = None

    def send(self, minor, data=None, user1=0, user2=0):

        if data != None:
            major = 2
            length = len(data)
        else:
            major = 1
            length = 0

        magic = 30194250

        _LOGGER.debug(
            "send "
            + str(minor)
            + " user1="
            + str(user1)
            + " user2="
            + str(user2)
            + " len="
            + str(length),
        )

        pkt = struct.pack("<IIIIII", magic, major, minor, user1, user2, length)

        if data:
            pkt += data

        self.sock.send(pkt)

    def recv(self):
        hdr = self.sock.recv(24)
        if len(hdr) != 24:
            raise Exception("Cannot read")

        magic, major, minor, user1, user2, length = struct.unpack("<IIIIII", hdr)
        data = self.sock.recv(length)

        _LOGGER.debug(
            "recv "
            + str(minor)
            + " user1="
            + str(user1)
            + " user2="
            + str(user2)
            + " len="
            + str(length),
        )

        return minor, data, user1, user2

    def sendrecv(self, minor, data=None, user1=0, user2=0):
        self.send(minor, data, user1, user2)
        return self.recv()

    def connect(self):
        _LOGGER.debug("Connecting to " + self.addr + ":" + str(self.port))
        self.conn = socket.create_connection((self.addr, self.port))
        self.sock = self.ctx.wrap_socket(self.conn)
        _LOGGER.debug("Connnected")

        _LOGGER.debug(
            "Server Cert\n-----BEGIN CERTIFICATE-----\n"
            + base64.b64encode(self.sock.getpeercert(binary_form=True)).decode("ascii")
            + "\n-----END CERTIFICATE-----",
        )

        self.sock.do_handshake()

        minor, data, user1, user2 = self.sendrecv(
            RobotClient.MSG_HELLO,
            "purei9-cli".encode("utf-8"),
            user1=RobotClient.PROTOCOL_VERSION,
        )
        assert user1 == RobotClient.PROTOCOL_VERSION, "Protocol version mismatch"

        self.robot_id = data.decode("utf-8")
        _LOGGER.debug("Hello from Robot ID: " + self.robot_id)

        minor, data, user1, user2 = self.sendrecv(
            RobotClient.MSG_LOGIN, self.localpw.encode("utf-8")
        )

        # weird protocol: login response does not indicate sucess, connection will just
        #                 be closed afterwards ...

        try:
            minor, data, user1, user2 = self.sendrecv(RobotClient.MSG_PING)
        except:
            _LOGGER.error(
                "Exception after login. This normally indicates a bad localpw."
            )
            return False

        _LOGGER.debug("Connection Still alive, seems we are authenticated")
        return True

    def info(self):
        return {
            "id": self.robot_id,
            "name": self.getname(),
            "status": self.getstatus(),
            "settings": self.getsettings(),
        }

    def getname(self):
        minor, data, user1, user2 = self.sendrecv(RobotClient.MSG_GETNAME)
        return data.decode("utf-8")

    def getfirmware(self):
        minor, data, user1, user2 = self.sendrecv(RobotClient.MSG_GETFIRMWARE)

        lst = []
        while len(data) > 4:
            l = struct.unpack("<I", data[:4])[0]
            data = data[4:]
            value = data[:l]
            data = data[l:]
            lst.append(value)

        i = 0
        obj = {}
        while i + 1 < len(lst):
            obj[lst[i].decode("utf-8")] = lst[i + 1].decode("utf-8")
            i += 2

        return obj

    def getsettings(self):
        minor, data, user1, user2 = self.sendrecv(RobotClient.MSG_GETSETTINGS)
        data = json.loads(data.decode("utf-8"))
        return data

    def getstatus(self):
        minor, data, user1, user2 = self.sendrecv(RobotClient.MSG_GETSTATUS)
        return user1

    def startclean(self):
        minor, data, user1, user2 = self.sendrecv(
            RobotClient.MSG_STARTCLEAN, user1=RobotClient.CLEAN_PLAY
        )
        return {
            "minor": minor,
            "data": data.decode("ascii"),
            "user1": user1,
            "user2": user2,
        }

    def gohome(self):
        minor, data, user1, user2 = self.sendrecv(
            RobotClient.MSG_STARTCLEAN, user1=RobotClient.CLEAN_HOME
        )
        return {
            "minor": minor,
            "data": data.decode("ascii"),
            "user1": user1,
            "user2": user2,
        }


class PureI9(StateVacuumEntity):
    def __init__(self, cloudRobot: CloudRobot, ip_address: str):
        self.is_on = False
        self._name = cloudRobot.name
        self._state = STATE_DOCKED
        self._robot = RobotClient(ip_address, cloudRobot.local_pw)
        self._robot.connect()

    @property
    def name(self):
        """Return the display name of this light."""
        return self._name

    @property
    def state(self):
        """Return the state of the vacuum cleaner."""
        return self._state

    @property
    def supported_features(self):
        """Flag vacuum cleaner features that are supported."""
        return SUPPORT_START | SUPPORT_STATE | SUPPORT_STATUS | SUPPORT_RETURN_HOME

    def start(self):
        """Start or resume the cleaning task."""
        self._robot.startclean()

    def return_to_base(self):
        """Set the vacuum cleaner to return to the dock."""
        self._robot.gohome()

    def stop(self):
        """Set the vacuum cleaner to return to the dock."""
        self._robot.gohome()

    def update(self):
        """Fetch new state data for this vacuum."""
        self._state = self.getHomeassistantState(self._robot.getstatus())

    def getHomeassistantState(self, state: str):
        switcher = {
            RobotClient.STATE_CLEANING: STATE_CLEANING,
            RobotClient.STATE_PAUSED: STATE_PAUSED,
            RobotClient.STATE_PAUSEDRETURN: STATE_RETURNING,
            RobotClient.STATE_PAUSEDRETURNPITSTOP: STATE_RETURNING,
            RobotClient.STATE_RETURN: STATE_RETURNING,
            RobotClient.STATE_RETURNPITSTOP: STATE_RETURNING,
            RobotClient.STATE_SPOTCLEAN: STATE_CLEANING,
            RobotClient.STATE_CHARGING: STATE_DOCKED,
            RobotClient.STATE_SLEEPING: STATE_DOCKED,
            RobotClient.STATE_ERROR: STATE_ERROR,
            RobotClient.STATE_PITSTOP: STATE_DOCKED,
        }
        return switcher.get(state, STATE_IDLE)
