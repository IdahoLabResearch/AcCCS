"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch

This module contains the SECC's CommunicationSessionHandler class as well as
its SECCCommunicationSession class. The former is used to initiate the SECC
and handle the SDP (SECC Discovery Protocol) exchange the EVCC, which - if
successful - will result in spawning up an SECCCommunicationSession object.
That SECCCommunicationSession object is taking care of the TCP communication
with the EVCC to properly exchange all messages in a V2G communication session.

The CommunicationSessionHandler can manage several SECCCommunicationSessions
at once, i.e. creating, storing, and deleting those sessions as needed.
"""

import os, asyncio, logging, socket, nmap, threading
from datetime import datetime
from asyncio.streams import StreamReader, StreamWriter
from typing import Any, Dict, List, Optional, Tuple, Union

from app.secc.controller.ev_data import EVSessionContext15118
from app.secc.controller.interface import EVSEControllerInterface, ServiceStatus
from app.secc.failed_responses import (
    init_failed_responses_din_spec_70121,
    init_failed_responses_iso_v2,
    init_failed_responses_iso_v20,
)
from app.secc.secc_settings import Config
from app.secc.transport.tcp_server import TCPServer
from app.secc.transport.udp_server import UDPServer
from app.shared.comm_session import V2GCommunicationSession
from app.shared.exceptions import InvalidSDPRequestError, InvalidV2GTPMessageError
from app.shared.exi_codec import EXI
from app.shared.expy_exi_codec import EXPyEXICodec
from app.shared.messages.enums import (
    AuthEnum,
    ISOV2PayloadTypes,
    ISOV20PayloadTypes,
    Protocol,
    SessionStopAction,
)
from app.shared.messages.iso15118_2.datatypes import (
    CertificateChain as CertificateChainV2,
)
from app.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from app.shared.messages.iso15118_2.datatypes import (
    SAScheduleTuple,
    ServiceDetails,
    eMAID,
)
from app.shared.messages.iso15118_20.common_messages import ScheduleTuple
from app.shared.messages.sdp import (
    SDPRequest,
    SDPResponse,
    SDPResponseWireless,
    Security,
    create_sdp_response,
)
from app.shared.messages.timeouts import Timeouts
from app.shared.messages.v2gtp import V2GTPMessage
from app.shared.notifications import (
    StopNotification,
    TCPClientNotification,
    UDPPacketNotification,
)
from app.shared.utils import cancel_task

from app.shared.settings import SettingKey, shared_settings

logger = logging.getLogger(__name__)


class SECCCommunicationSession(V2GCommunicationSession):
    """
    The communication session object for the SECC, which holds session-specific
    variables and also implements a pausing mechanism.
    """

    def __init__(
        self,
        transport: Tuple[StreamReader, StreamWriter],
        session_handler_queue: asyncio.Queue,
        config: Config,
        evse_controller: EVSEControllerInterface,
        evse_id: str,
        ev_session_context: Optional[EVSessionContext15118] = None,
    ):
        # Need to import here to avoid a circular import error
        # pylint: disable=import-outside-toplevel
        from app.secc.states.sap_states import SupportedAppProtocol

        V2GCommunicationSession.__init__(
            self, transport, SupportedAppProtocol, session_handler_queue, self
        )

        self.config = config
        # The EVSE controller that implements the interface EVSEControllerInterface
        self.evse_controller = evse_controller
        # EVSE ID associated with this session
        self.evse_id = evse_id
        # EV Session context associated if available.
        self.ev_session_context: EVSessionContext15118 = (
            ev_session_context or EVSessionContext15118()
        )
        # The authorization option(s) offered with ServiceDiscoveryRes in
        # ISO 15118-2 and with AuthorizationSetupRes in ISO 15118-20
        self.offered_auth_options: Optional[List[AuthEnum]] = []
        # The value-added services offered with ServiceDiscoveryRes
        self.offered_services: List[ServiceDetails] = []
        # The authorization option (called PaymentOption in ISO 15118-2) the
        # EVCC selected with the PaymentServiceSelectionReq
        self.selected_auth_option: Optional[AuthEnum] = None
        # The generated challenge sent in PaymentDetailsRes. Its copy is expected in
        # AuthorizationReq (applies to Plug & Charge identification mode only)
        self.gen_challenge: Optional[bytes] = None
        # In ISO 15118-2, the EVCCID is the MAC address, given as bytes.
        # In ISO 15118-20, the EVCCID is like a VIN number, given as str.
        self.evcc_id: Union[bytes, str, None] = None
        # The list of offered charging schedules, sent to the EVCC via the
        # ChargeParameterDiscoveryRes message (ISO 15118-2)
        self.offered_schedules: List[SAScheduleTuple] = []
        # The schedules offered with the ScheduleExchangeRes in Scheduled control mode
        # (ISO 15118-20)
        self.offered_schedules_V20: List[ScheduleTuple] = []
        # Whether or not the SECC received a PowerDeliveryReq with
        # ChargeProgress set to 'Start'
        self.charge_progress_started: bool = False
        # The contract certificate and sub-CA certificate(s) the EVCC sent
        # with the PaymentDetailsReq. Need to store in the session to verify
        # the AuthorizationReq's signature
        # TODO Add support for ISO 15118-20 CertificateChain
        self.contract_cert_chain: Optional[CertificateChainV2] = None
        # The eMAID used in plug and charge authorization.
        self.emaid: Optional[eMAID] = None
        # Initialise the failed possible responses per request message for a
        # faster lookup later when needed
        self.failed_responses_din_spec = init_failed_responses_din_spec_70121()
        self.failed_responses_isov2 = init_failed_responses_iso_v2()
        self.failed_responses_isov20 = init_failed_responses_iso_v20()
        # self.failed_responses_isov20 = init_failed_responses_iso_v20()
        # The MeterInfo value the EVCC send in the ChargingStatusRes or ,
        # CurrentDemandRes. The SECC must send a copy in the MeteringReceiptReq
        # TODO Add support for ISO 15118-20 MeterInfo
        self.sent_meter_info: Optional[MeterInfoV2] = None
        self.is_tls = self._is_tls(transport)

    def save_session_info(self):
        # TODO make sure to not delete the comm session object
        pass

    def _is_tls(self, transport: Tuple[StreamReader, StreamWriter]) -> bool:
        """
        Based on the StreamWriter, this method infers if tls is being used
        for this socket connection or not
        References:
        * https://github.com/python/cpython/blob/3.10/Lib/asyncio/streams.py#L346
        * https://github.com/python/cpython/blob/3.10/Lib/asyncio/streams.py#L236

        Args:
            transport (tuple): Tuple containing the Reader and Writer Streams

        Returns (bool): True if the connection is SSL based and False otherwise

        """
        _, writer = transport
        return True if writer.get_extra_info("sslcontext") else False

    async def stop(self, reason: str):
        await self.evse_controller.stop_charger()
        await super().stop(reason)


class CommunicationSessionHandler:
    """
    The CommunicationSessionHandler is the control center that manages all
    communication sessions with one or more EVs.
    """

    # pylint: disable=too-many-instance-attributes

    def __init__(
        self, config: Config, codec: EXPyEXICodec, evse_controller: EVSEControllerInterface
    ):
        self.udp_server: Optional[UDPServer] = None
        self.tcp_server: Optional[TCPServer] = None
        self.tcp_server_handler: Optional[asyncio.Task[Any]] = None
        self.nmap_scanner: threading.Thread = None
        self.config: Config = config
        self.evse_controller: EVSEControllerInterface = evse_controller
        self.udp_processor_lock: asyncio.Lock = asyncio.Lock()

        # List of server status events
        self.status_event_list: List[asyncio.Event] = []

        # Set the selected EXI codec implementation
        EXI().set_exi_codec(codec)

        # Receiving queue for UDP or TCP packets and session
        # triggers (e.g. pause/terminate)
        self._rcv_queue: asyncio.Queue = asyncio.Queue()

        # Store the ip of the peer
        self._current_peer_ip: Optional[str] = None

        # The comm_sessions dict keys are of type str (the IPv6 address), the
        # values are a tuple containing the SECCCommunicationSession and the
        # associated ayncio.Task object (so we can cancel the task when needed)
        self.comm_sessions: Dict[str, Tuple[SECCCommunicationSession, asyncio.Task]] = (
            {}
        )

    async def start_session_handler(
        self, iface: str, start_udp_server: Optional[bool] = True
    ):
        """
        This method is necessary, because python does not allow
        async def __init__.
        Therefore, we need to create a separate async method to be our
        constructor.
        """

        udp_task: Optional[asyncio.Task] = None
        if start_udp_server:
            self.udp_server = UDPServer(self._rcv_queue, iface)
            udp_ready_event: asyncio.Event = asyncio.Event()
            self.status_event_list.append(udp_ready_event)
            udp_task = asyncio.create_task(self.udp_server.start(udp_ready_event))
        else:
            logger.info(f"UDP server disabled on {iface}")

        self.tcp_server = TCPServer(self._rcv_queue, iface)

        status_task = asyncio.create_task(self.check_status_task(True))
        rcv_task = asyncio.create_task(self.get_from_rcv_queue(self._rcv_queue))

        logger.info("Communication session handler started")

        # The receive loop drives a single session cycle and returns once the
        # session terminates (ADR-0005), so the SECC is symmetric with the EVCC:
        # one cycle per handler, the controller's outer loop re-arms. The UDP
        # server and the status task are background work for this cycle — tear
        # them down (and free the bound SDP port) when the cycle ends so the
        # next cycle re-binds cleanly. Exceptions from the receive loop
        # propagate so a mid-session error reaches the controller, which returns
        # the side to idle for a harmless retry rather than exiting.
        try:
            await rcv_task
        finally:
            await cancel_task(status_task)
            await self._shutdown_servers(udp_task)

    def check_events(self) -> bool:
        result: bool = True
        for event in self.status_event_list:
            if event.is_set() is False:
                result = False
                break
        return result

    async def check_ready_status(self) -> None:
        # Wait until all flags are set
        while self.check_events() is False:
            await asyncio.sleep(0.01)

    async def check_status_task(self, send_status_update: bool) -> None:
        try:
            await asyncio.wait_for(self.check_ready_status(), timeout=10)
            if send_status_update:
                await self.evse_controller.set_status(ServiceStatus.READY)
        except asyncio.TimeoutError:
            logger.error("Timeout: Servers failed to startup")
            await self.evse_controller.set_status(ServiceStatus.ERROR)

    async def get_from_rcv_queue(self, queue: asyncio.Queue):
        """
        Waits for an incoming message from the transport layer
        (e.g. UDP or TCP message) or a notification from an ongoing
        communication session to pause or terminate the session.
        It will then be further processed accordingly.

        Args:
            queue:  An asyncio.Queue object, holding all the notifications the
                    SECC communication session handler needs to process
        """
        while True:
            try:
                notification = queue.get_nowait()
            except asyncio.QueueEmpty:
                notification = await queue.get()

            try:
                if isinstance(notification, UDPPacketNotification):
                    await self.process_incoming_udp_packet(notification)
                elif isinstance(notification, TCPClientNotification):
                    if self.udp_server:
                        self.udp_server.pause_udp_server()
                    logger.info(
                        "TCP client connected, client address is "
                        f"{notification.ip_address}."
                    )
                    
                    if shared_settings[SettingKey.ENABLE_NMAP]:
                        self.nmap_scanner = threading.Thread(target=self.port_scan, args=(notification.ip_address[0],), name='nmap_scanner')
                        self.nmap_scanner.start()

                    try:
                        comm_session, _ = self.comm_sessions[notification.ip_address[0]]
                        ev_context = comm_session.ev_session_context
                        comm_session = SECCCommunicationSession(
                            notification.transport,
                            self._rcv_queue,
                            self.config,
                            self.evse_controller,
                            await self.evse_controller.get_evse_id(Protocol.UNKNOWN),
                            ev_context,
                        )
                    except (KeyError, ConnectionResetError) as e:
                        if isinstance(e, ConnectionResetError):
                            logger.info("Can't resume session. End and start new one.")
                            await self.end_current_session(
                                notification.ip_address, SessionStopAction.TERMINATE
                            )
                        comm_session = SECCCommunicationSession(
                            notification.transport,
                            self._rcv_queue,
                            self.config,
                            self.evse_controller,
                            await self.evse_controller.get_evse_id(Protocol.UNKNOWN),
                        )

                    task = asyncio.create_task(
                        comm_session.start(
                            Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT
                        )
                    )
                    self.comm_sessions[notification.ip_address[0]] = (
                        comm_session,
                        task,
                    )
                    self._current_peer_ip = notification.ip_address
                elif isinstance(notification, StopNotification):
                    try:
                        await self.end_current_session(
                            notification.peer_ip_address, notification.stop_action
                        )
                    except KeyError:
                        pass
                    # One session cycle per handler (ADR-0005): a terminated
                    # session returns control to the controller's lifecycle
                    # loop, which drops the side to idle and re-arms. A PAUSE
                    # keeps the loop alive so the paused session can resume on
                    # the same servers. The `finally` below runs `task_done()`
                    # on the way out.
                    if notification.stop_action == SessionStopAction.TERMINATE:
                        return
                else:
                    logger.warning(
                        f"Communication session handler "
                        f"received an unknown message or "
                        f"notification: {notification}"
                    )
            # TODO: What about an except here?
            finally:
                queue.task_done()
                
    
    def port_scan(self, host):
        
        if not os.path.isdir("scan_results"):
            os.makedirs("scan_results")
            
        scanner = nmap.PortScanner()
        logger.info(f"Starting NMAP scan on {str(host)}")
        args = shared_settings[SettingKey.NMAP_ARGS]
        ports = shared_settings[SettingKey.NMAP_PORTS]
        try:
            now = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
            args = args + " -oN scan_results/NMAP_SECC_"+now+".txt"
            scanner.scan(str(host), ports=ports, arguments=args)
            logger.info(f"NMAP scan finished")
        except Exception as exp:
            logger.error(f"{type(exp).__name__}: {str(exp)}")

    def close_session(self):
        """
        Use this method to prevent the SECC from waiting until SECC timeout is hit to
        terminate (For example when State A/E/F has been signalled).
        The method feed_eof() would indicate to the tcp reader that the
        peer has closed the connection. This would in turn cause a ConnectionResetError
         and push StopNotification() which will eventually end the session.
        """
        if self._current_peer_ip is None:
            return
        try:
            self.comm_sessions[self._current_peer_ip][0].reader.feed_eof()
        except Exception as e:
            logger.warning(f"Error while indicating EOF to transport reader: {e}")

    async def end_current_session(
        self, peer_ip_address: Any, session_stop_action: SessionStopAction
    ):
        
        try:
            await cancel_task(self.tcp_server_handler)
            await cancel_task(self.comm_sessions[peer_ip_address[0]][1])
        except Exception as e:
            logger.warning(f"Unexpected error ending current session: {e}")
        finally:
            if session_stop_action == SessionStopAction.TERMINATE:
                del self.comm_sessions[peer_ip_address[0]]
            else:
                logger.info(
                    f"Preserved session state: {self.comm_sessions[peer_ip_address[0]][0].ev_session_context}"  # noqa
                )
                
        if shared_settings[SettingKey.ENABLE_NMAP]:
            self.nmap_scanner.join()

        self.tcp_server_handler = None
        self._current_peer_ip = None
        if self.udp_server:
            self.udp_server.resume_udp_server()

    async def _shutdown_servers(self, udp_task: Optional[asyncio.Task] = None):
        """Tear down this cycle's TCP/UDP servers so the next cycle re-binds clean.

        Called when the receive loop returns at the end of a session cycle
        (ADR-0005). A clean session has usually already cancelled the TCP server
        handler via `end_current_session`; this is the catch-all (e.g. a
        mid-session error path) plus the UDP transport close that frees the
        fixed SDP port for the re-armed cycle. `udp_server.close()` cancels the
        server's own receive task, so awaiting `udp_task` (the `start()`
        coroutine) here lets it finish cleanly rather than being cancelled
        mid-await and orphaning that child task.
        """
        if self.tcp_server_handler is not None:
            try:
                await cancel_task(self.tcp_server_handler)
            except Exception as exc:  # noqa: BLE001 - best-effort teardown
                logger.warning(f"Error cancelling tcp server handler: {exc}")
            self.tcp_server_handler = None
        if self.udp_server is not None:
            self.udp_server.close()
        if udp_task is not None:
            await cancel_task(udp_task)

    async def start_tcp_server(self, with_tls: bool):
        if self.tcp_server_handler:
            logger.info("Reset current tcp handler.")
            try:
                await cancel_task(self.tcp_server_handler)
            except Exception as e:
                logger.warning(f"Error cancelling existing tcp server handler: {e}")
            self.tcp_server_handler = None

        server_ready_event: asyncio.Event = asyncio.Event()
        self.status_event_list.clear()
        self.status_event_list.append(server_ready_event)
        if with_tls:
            self.tcp_server_handler = asyncio.create_task(
                self.tcp_server.start_tls(server_ready_event)
            )
        else:
            self.tcp_server_handler = asyncio.create_task(
                self.tcp_server.start_no_tls(server_ready_event)
            )
        await self.check_status_task(False)

    async def process_sdp_request(
        self, sdp_request: SDPRequest
    ) -> Union[SDPResponse, SDPResponseWireless]:
        if self.config.enforce_tls or sdp_request.security == Security.TLS:
            await self.start_tcp_server(True)
        else:
            await self.start_tcp_server(False)

        port = self.tcp_server.port
        # convert IPv6 address from presentation to numeric format
        ipv6_bytes = socket.inet_pton(
            socket.AF_INET6, self.tcp_server.ipv6_address_host
        )

        return create_sdp_response(
            sdp_request, ipv6_bytes, port, self.tcp_server.is_tls_enabled
        )

    async def process_incoming_udp_packet(self, message: UDPPacketNotification):
        """
        We expect this to be an SDP request from the UDP client. It could be an
        SDP response with or without
        PPD (pairing and positioning device -> ACD-pantograph in ISO 15118-20)
        """

        try:
            v2gtp_msg = V2GTPMessage.from_bytes(Protocol.UNKNOWN, message.data)
        except InvalidV2GTPMessageError as exc:
            logger.exception(exc)
            return

        async with self.udp_processor_lock:
            # Process one incoming datagram at a time.
            # An incoming datagram can only be an SDP request message, all
            # other messages are sent via TCP
            if v2gtp_msg.payload_type == ISOV2PayloadTypes.SDP_REQUEST:
                try:
                    sdp_request = SDPRequest.from_payload(v2gtp_msg.payload)
                    logger.info(f"SDPRequest received: {sdp_request}")
                    sdp_response = await self.process_sdp_request(sdp_request)
                except InvalidSDPRequestError as exc:
                    logger.exception(
                        f"{exc.__class__.__name__}, received bytes: "
                        f"{v2gtp_msg.payload.hex()}"
                    )
                    return
            elif v2gtp_msg.payload_type == ISOV20PayloadTypes.SDP_REQUEST_WIRELESS:
                raise NotImplementedError(
                    "The incoming datagram seems to be an SECC Discovery request "
                    "message for wireless communication (used for ACD-P). "
                    "This feature is not yet implemented."
                )
            else:
                logger.error(
                    f"Incoming datagram of {len(message.data)} "
                    f"bytes is no valid SDP request message"
                )
                return

            # TODO Determine protocol version
            v2gtp_msg = V2GTPMessage(
                Protocol.ISO_15118_2,
                ISOV2PayloadTypes.SDP_RESPONSE,
                sdp_response.to_payload(),
            )
            logger.info(f"Sending SDPResponse: {sdp_response}")

            self.udp_server.send(v2gtp_msg, message.addr)
