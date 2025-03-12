"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

# need to do this to import the custom SECC and V2G scapy layer
import xml.etree.ElementTree as ET
import xml.dom.minidom

from .EXIProcessor import EXIProcessor
from .EmulatorEnum import Protocol

# Used to build and encode XML tree into EXI string for layer 3 communication


class XMLBuilder:
    def __init__(self, exi: EXIProcessor):
        self.exi = exi
        self.protocol = exi.protocol

    def SupportedAppProtocolRequest(self):
        self._cleanup()
        self.root = ET.Element("ns4:supportedAppProtocolReq")
        self.root.set("xmlns:ns4", "urn:iso:15118:2:2010:AppProtocol")
        self.root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
        self.root.set("xmlns:ns3", "http://www.w3.org/2001/XMLSchema")
        self.AppProtocol = ET.SubElement(self.root, "AppProtocol")
        self.ProtocolNamespace = ET.SubElement(self.AppProtocol, "ProtocolNamespace")
        self.VersionNumberMajor = ET.SubElement(self.AppProtocol, "VersionNumberMajor")
        self.VersionNumberMinor = ET.SubElement(self.AppProtocol, "VersionNumberMinor")
        self.SchemaID = ET.SubElement(self.AppProtocol, "SchemaID")
        self.Priority = ET.SubElement(self.AppProtocol, "Priority")

        # Default Values
        if self.protocol == Protocol.DIN:
            self.ProtocolNamespace.text = "urn:din:70121:2012:MsgDef"
            self.VersionNumberMajor.text = "1"
        elif self.protocol == Protocol.ISO_2:
            self.ProtocolNamespace.text = "urn:iso:15118:2:2013:MsgDef"
            self.VersionNumberMajor.text = "2"
        self.VersionNumberMinor.text = "0"
        self.SchemaID.text = "1"
        self.Priority.text = "1"

    def SupportedAppProtocolResponse(self):
        self._cleanup()
        self.EXITries = 0
        self.root = ET.Element("ns4:supportedAppProtocolRes")
        self.root.set("xmlns:ns4", "urn:iso:15118:2:2010:AppProtocol")
        self.root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
        self.root.set("xmlns:ns3", "http://www.w3.org/2001/XMLSchema")
        self.ResponseCode = ET.SubElement(self.root, "ResponseCode")
        self.SchemaID = ET.SubElement(self.root, "SchemaID")

        # Default Values
        self.ResponseCode.text = "OK_SuccessfulNegotiation"
        self.SchemaID.text = "1"

    def _V2GDINHeader(self):
        self._cleanup()
        self.EXITries = 0
        self.root = ET.Element("ns1:V2G_Message")
        if self.protocol == Protocol.DIN:
            self.root.set("xmlns:ns1", "urn:din:70121:2012:MsgDef")
            self.root.set("xmlns:ns2", "urn:din:70121:2012:MsgHeader")
            self.root.set("xmlns:ns3", "urn:din:70121:2012:MsgBody")
            self.root.set("xmlns:ns4", "urn:din:70121:2012:MsgDataTypes")
        elif self.protocol == Protocol.ISO_2:
            self.root.set("xmlns:ns1", "urn:iso:15118:2:2013:MsgDef")
            self.root.set("xmlns:ns2", "urn:iso:15118:2:2013:MsgHeader")
            self.root.set("xmlns:ns3", "urn:iso:15118:2:2013:MsgBody")
            self.root.set("xmlns:ns4", "urn:iso:15118:2:2013:MsgDataTypes")
        self.Header = ET.SubElement(self.root, "ns1:Header")
        self.SessionID = ET.SubElement(self.Header, "ns2:SessionID")
        self.Body = ET.SubElement(self.root, "ns1:Body")

        # Default Value
        self.SessionID.text = "4142423030303031"

    def SessionSetupRequest(self):
        self._V2GDINHeader()
        self.SessionSetupReq = ET.SubElement(self.Body, "ns3:SessionSetupReq")
        self.EVCCID = ET.SubElement(self.SessionSetupReq, "ns3:EVCCID")

        # Default Values
        self.EVCCID.text = "A44E24C150B8"
        self.SessionID.text = "00"

    def SessionSetupResponse(self):
        self._V2GDINHeader()
        self.SessionSetupRes = ET.SubElement(self.Body, "ns3:SessionSetupRes")
        self.ResponseCode = ET.SubElement(self.SessionSetupRes, "ns3:ResponseCode")
        self.EVSEID = ET.SubElement(self.SessionSetupRes, "ns3:EVSEID")

        # Default Values
        self.ResponseCode.text = "OK"
        if self.protocol == Protocol.DIN:
            # For DIN 70121, EVSEID's type is hexbinary
            self.EVSEID.text = "DEADBEEF"
        elif self.protocol == Protocol.ISO_2:
            # For ISO 15118-2, EVSEID's type is string
            self.EVSEID.text = "FR*A23*ANUEVO"

    def ServiceDiscoveryRequest(self):
        self._V2GDINHeader()
        self.ServiceDiscoveryReq = ET.SubElement(self.Body, "ns3:ServiceDiscoveryReq")
        # self.ServiceScope = ET.SubElement(self.ServiceDiscoveryReq, "ns3:ServiceScope")
        self.ServiceCategory = ET.SubElement(self.ServiceDiscoveryReq, "ns3:ServiceCategory")

        # Default Values
        self.ServiceCategory.text = "EVCharging"

    def ServiceDiscoveryResponse(self):
        self._V2GDINHeader()
        self.ServiceDiscoveryRes = ET.SubElement(self.Body, "ns3:ServiceDiscoveryRes")
        self.ResponseCode = ET.SubElement(self.ServiceDiscoveryRes, "ns3:ResponseCode")
        if self.protocol == Protocol.DIN:
            self.PaymentOptions = ET.SubElement(self.ServiceDiscoveryRes, "ns3:PaymentOptions")
            self.PaymentOption = ET.SubElement(self.PaymentOptions, "ns4:PaymentOption")
        elif self.protocol == Protocol.ISO_2:
            self.PaymentOptionList = ET.SubElement(self.ServiceDiscoveryRes, "ns3:PaymentOptionList")
            self.PaymentOption = ET.SubElement(self.PaymentOptionList, "ns4:PaymentOption")
        self.ChargeService = ET.SubElement(self.ServiceDiscoveryRes, "ns3:ChargeService")
        if self.protocol == Protocol.DIN:
            self.ServiceTag = ET.SubElement(self.ChargeService, "ns4:ServiceTag")
            self.ServiceID = ET.SubElement(self.ServiceTag, "ns4:ServiceID")
            self.ServiceCategory = ET.SubElement(self.ServiceTag, "ns4:ServiceCategory")
        elif self.protocol == Protocol.ISO_2:
            self.ServiceID = ET.SubElement(self.ChargeService, "ns4:ServiceID")
            self.ServiceCategory = ET.SubElement(self.ChargeService, "ns4:ServiceCategory")
        self.FreeService = ET.SubElement(self.ChargeService, "ns4:FreeService")
        if self.protocol == Protocol.DIN:
            self.EnergyTransferType = ET.SubElement(self.ChargeService, "ns4:EnergyTransferType")
        elif self.protocol == Protocol.ISO_2:
            self.SupportedEnergyTransferMode = ET.SubElement(self.ChargeService, "ns4:SupportedEnergyTransferMode")
            self.EnergyTransferMode = ET.SubElement(self.SupportedEnergyTransferMode, "ns4:EnergyTransferMode")

        # Default Values
        self.ResponseCode.text = "OK"
        self.PaymentOption.text = "ExternalPayment"
        self.ServiceID.text = "1"
        self.ServiceCategory.text = "EVCharging"
        self.FreeService.text = "false"
        if self.protocol == Protocol.DIN:
            self.EnergyTransferType.text = "DC_extended"
        elif self.protocol == Protocol.ISO_2:
            self.EnergyTransferMode.text = "DC_extended"
            
    def ServicePaymentSelectionRequest(self):
        if self.protocol != Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.ServicePaymentSelectionReq = ET.SubElement(self.Body, "ns3:ServicePaymentSelectionReq")
        self.SelectedPaymentOption = ET.SubElement(self.ServicePaymentSelectionReq, "ns3:SelectedPaymentOption")
        self.SelectedServiceList = ET.SubElement(self.ServicePaymentSelectionReq, "ns3:SelectedServiceList")
        self.SelectedService = ET.SubElement(self.SelectedServiceList, "ns4:SelectedService")
        self.ServiceID = ET.SubElement(self.SelectedService, "ns4:ServiceID")

        # Default Values
        self.SelectedPaymentOption.text = "ExternalPayment"
        self.ServiceID.text = "1"

    def ServicePaymentSelectionResponse(self):
        if self.protocol != Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.ServicePaymentSelectionRes = ET.SubElement(self.Body, "ns3:ServicePaymentSelectionRes")
        self.ResponseCode = ET.SubElement(self.ServicePaymentSelectionRes, "ns3:ResponseCode")

        # Default Values
        self.ResponseCode.text = "OK"

    def PaymentServiceSelectionRequest(self):
        if self.protocol == Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.PaymentServiceSelectionReq = ET.SubElement(self.Body, "ns3:PaymentServiceSelectionReq")
        self.SelectedPaymentOption = ET.SubElement(self.PaymentServiceSelectionReq, "ns3:SelectedPaymentOption")
        self.SelectedServiceList = ET.SubElement(self.PaymentServiceSelectionReq, "ns3:SelectedServiceList")
        self.SelectedService = ET.SubElement(self.SelectedServiceList, "ns4:SelectedService")
        self.ServiceID = ET.SubElement(self.SelectedService, "ns4:ServiceID")

        # Default Values
        self.SelectedPaymentOption.text = "ExternalPayment"
        self.ServiceID.text = "1"

    def PaymentServiceSelectionResponse(self):
        if self.protocol == Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.PaymentServiceSelectionRes = ET.SubElement(self.Body, "ns3:PaymentServiceSelectionRes")
        self.ResponseCode = ET.SubElement(self.PaymentServiceSelectionRes, "ns3:ResponseCode")

        # Default Values
        self.ResponseCode.text = "OK"

    def ContractAuthenticationRequest(self):
        if self.protocol != Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.ContractAuthenticationReq = ET.SubElement(self.Body, "ns3:ContractAuthenticationReq")

    def ContractAuthenticationResponse(self):
        if self.protocol != Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.ContractAuthenticationRes = ET.SubElement(self.Body, "ns3:ContractAuthenticationRes")
        self.ResponseCode = ET.SubElement(self.ContractAuthenticationRes, "ns3:ResponseCode")
        self.EVSEProcessing = ET.SubElement(self.ContractAuthenticationRes, "ns3:EVSEProcessing")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEProcessing.text = "Finished"
        
    def PaymentDetailsRequest(self):
        if self.protocol == Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.PaymentDetailsReq = ET.SubElement(self.Body, "ns3:PaymentDetailsReq")
        self.eMAID = ET.SubElement(self.PaymentDetailsReq, "ns3:eMAID")
        self.ContractSignatureCertChain = ET.SubElement(self.PaymentDetailsReq, "ns3:ContractSignatureCertChain")
        self.MOLeaf = ET.SubElement(self.ContractSignatureCertChain, "ns4:Certificate")
        self.SubCertificates = ET.SubElement(self.ContractSignatureCertChain, "ns4:SubCertificates")
        self.MOSubCA2 = ET.SubElement(self.SubCertificates, "ns4:Certificate")
        self.MOSubCA1 = ET.SubElement(self.SubCertificates, "ns4:Certificate")
        
        # Default Values
        self.eMAID.text = "DEICECPWRELVLD3"
        self.MOLeaf.text = "MIIB+jCCAaCgAwIBAgIQYXk+S2seKdtB4TYtvitQ3jAKBggqhkjOPQQDAjBDMQswCQYDVQQGEwJERTEVMBMGA1UEChMMSHViamVjdCBHbWJIMR0wGwYDVQQDExRNTyBTdWIyIENBIFFBIEcxLjIuMTAeFw0yNTAyMjgxNDI5MDdaFw0yNTA0MjcyMzAwMDBaMC8xEzARBgNVBAoTCkVWU0UgQ0hFQ0sxGDAWBgNVBAMTD0RFSUNFQ1BXUkVMVkxEMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGqm6Mv6CqkUnV7yzmPfeG3y1IFYCiuF79gtdf9SXrrCJ29IUzLnuxWb20dBo+Tdq9Wpc7yO4/SN43ibt5gB1gGjgYkwgYYwDwYDVR0TAQH/BAUwAwEBADARBgNVHQ4ECgQITzeOHVB7h7IwEwYDVR0jBAwwCoAIRS5poTYibEgwOwYIKwYBBQUHAQEELzAtMCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC1xYS5odWJqZWN0LmNvbTo4MDgwMA4GA1UdDwEB/wQEAwID6DAKBggqhkjOPQQDAgNIADBFAiEAhkagqgK/o1POI15fURvuevFCEG8+fMz7bAd54LVuAecCIGahCG4zARbtnasfY9PnEU500rtc+AwW1YXLB2yaF4TM"
        self.MOSubCA2.text = "MIICDzCCAbWgAwIBAgIQXd9CzQy8+VxpQt9IwNrOETAKBggqhkjOPQQDAjBBMQswCQYDVQQGEwJERTEVMBMGA1UEChMMSHViamVjdCBHbWJIMRswGQYDVQQDExJNTyBTdWIxIENBIFFBIEcxLjIwHhcNMjIwNDEwMjE1OTU5WhcNMzIwNDEwMjE1OTU5WjBDMQswCQYDVQQGEwJERTEVMBMGA1UEChMMSHViamVjdCBHbWJIMR0wGwYDVQQDExRNTyBTdWIyIENBIFFBIEcxLjIuMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGRsp5TTDIGpB+PEwmeG8D7Pgo/WN3U35Rxhe5ttLLlyF2jlmtOPHeHxWgGb0AO7H3L6nso0A7Nn2KfDP8tG+OujgYwwgYkwEgYDVR0TAQH/BAgwBgEB/wIBADARBgNVHQ4ECgQIRS5poTYibEgwEwYDVR0jBAwwCoAISw94EhgPO18wOwYIKwYBBQUHAQEELzAtMCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC1xYS5odWJqZWN0LmNvbTo4MDgwMA4GA1UdDwEB/wQEAwIBxjAKBggqhkjOPQQDAgNIADBFAiBqFxXTwnpm0eEgBPj/Px0kaEvZWdyZPm7BLJVJM6fT3QIhAKZPDhuau2DcN9xrrRPqqZLjfqPSMWw1D0VlCTqCuv2k"
        self.MOSubCA1.text = "MIICIjCCAcegAwIBAgIQIOuk+8fAbyXQizBVpSI55zAKBggqhkjOPQQDAjBVMQswCQYDVQQGEwJERTEVMBMGA1UEChMMSHViamVjdCBHbWJIMRMwEQYKCZImiZPyLGQBGRYDVjJHMRowGAYDVQQDExFWMkcgUm9vdCBDQSBRQSBHMTAeFw0yMjA0MDcxNDEzMDdaFw00MjA0MDcxNDEzMDdaMEExCzAJBgNVBAYTAkRFMRUwEwYDVQQKEwxIdWJqZWN0IEdtYkgxGzAZBgNVBAMTEk1PIFN1YjEgQ0EgUUEgRzEuMjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLWnWSw4NPNInduDQp6H0IFgeY0WtO0F3utqV191XLIespoAoSIz7s4Vhf+BhbbeX+UyftbGDp2m9EjGIBhog+mjgYwwgYkwEgYDVR0TAQH/BAgwBgEB/wIBATARBgNVHQ4ECgQISw94EhgPO18wEwYDVR0jBAwwCoAIS0X/giX8EJYwOwYIKwYBBQUHAQEELzAtMCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC1xYS5odWJqZWN0LmNvbTo4MDgwMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNJADBGAiEAsApDKLvPUVuDCtsIAnn/+prsGu5aekwd59tLiCHAFwACIQCFGJHvTz7JUrq/QJhQzehduW/+oaROsqOp8L3JdEO6XA=="

    def PaymentDetailsResponse(self):
        if self.protocol == Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.PaymentDetailsRes = ET.SubElement(self.Body, "ns3:PaymentDetailsRes")
        self.ResponseCode = ET.SubElement(self.PaymentDetailsRes, "ns3:ResponseCode")
        self.GenChallenge = ET.SubElement(self.PaymentDetailsRes, "ns3:GenChallenge")
        self.EVSETimeStamp = ET.SubElement(self.PaymentDetailsRes, "ns3:EVSETimeStamp")
        
        # Default Values
        self.ResponseCode.text = "OK"
        self.GenChallenge.text = "MzM1OTA4MzY4OTI3ODgzAA=="
        self.EVSETimeStamp.text = "1451782216"

    def AuthorizationRequest(self):
        if self.protocol == Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.AuthorizationReq = ET.SubElement(self.Body, "ns3:AuthorizationReq")
        self.GenChallenge = ET.SubElement(self.AuthorizationReq, "ns3:GenChallenge")
        
        # Default Values
        self.GenChallenge.text = "MzM1OTA4MzY4OTI3ODgzAA=="

    def AuthorizationResponse(self):
        if self.protocol == Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.AuthorizationRes = ET.SubElement(self.Body, "ns3:AuthorizationRes")
        self.ResponseCode = ET.SubElement(self.AuthorizationRes, "ns3:ResponseCode")
        self.EVSEProcessing = ET.SubElement(self.AuthorizationRes, "ns3:EVSEProcessing")
        
        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEProcessing.text = "Finished"

    def ChargeParameterDiscoveryRequest(self):
        self._V2GDINHeader()
        self.ChargeParameterDiscoverReq = ET.SubElement(self.Body, "ns3:ChargeParameterDiscoveryReq")
        if self.protocol == Protocol.DIN:
            self.EVRequestedEnergyTransferType = ET.SubElement(self.ChargeParameterDiscoverReq, "ns3:EVRequestedEnergyTransferType")
        elif self.protocol == Protocol.ISO_2:
            self.RequestedEnergyTransferMode = ET.SubElement(self.ChargeParameterDiscoverReq, "ns3:RequestedEnergyTransferMode")
        self.DC_EVChargeParameter = ET.SubElement(self.ChargeParameterDiscoverReq, "ns4:DC_EVChargeParameter")
        self.DC_EVStatus = ET.SubElement(self.DC_EVChargeParameter, "ns4:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns4:EVReady")
        # self.EVCabinConditioning = ET.SubElement(self.DC_EVStatus, "ns4:EVCabinConditioning")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns4:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns4:EVRESSSOC")
        self.EVMaximumCurrentLimit = ET.SubElement(self.DC_EVChargeParameter, "ns4:EVMaximumCurrentLimit")
        self.CurrentLimitMultiplier = ET.SubElement(self.EVMaximumCurrentLimit, "ns4:Multiplier")
        self.CurrentLimitUnit = ET.SubElement(self.EVMaximumCurrentLimit, "ns4:Unit")
        self.CurrentLimitValue = ET.SubElement(self.EVMaximumCurrentLimit, "ns4:Value")
        self.EVMaximumPowerLimit = ET.SubElement(self.DC_EVChargeParameter, "ns4:EVMaximumPowerLimit")
        self.PowerLimitMultiplier = ET.SubElement(self.EVMaximumPowerLimit, "ns4:Multiplier")
        self.PowerLimitUnit = ET.SubElement(self.EVMaximumPowerLimit, "ns4:Unit")
        self.PowerLimitValue = ET.SubElement(self.EVMaximumPowerLimit, "ns4:Value")
        self.EVMaximumVoltageLimit = ET.SubElement(self.DC_EVChargeParameter, "ns4:EVMaximumVoltageLimit")
        self.VoltageLimitMultiplier = ET.SubElement(self.EVMaximumVoltageLimit, "ns4:Multiplier")
        self.VoltageLimitUnit = ET.SubElement(self.EVMaximumVoltageLimit, "ns4:Unit")
        self.VoltageLimitValue = ET.SubElement(self.EVMaximumVoltageLimit, "ns4:Value")

        # Default Values
        if self.protocol == Protocol.DIN:
            self.EVRequestedEnergyTransferType.text = "DC_extended"
        elif self.protocol == Protocol.ISO_2:
            self.RequestedEnergyTransferMode.text = "DC_extended"
        self.EVReady.text = "true"
        # self.EVCabinConditioning.text = "true"
        self.EVErrorCode.text = "NO_ERROR"
        self.EVRESSSOC.text = "10"
        self.CurrentLimitMultiplier.text = "-1"
        self.CurrentLimitUnit.text = "A"
        self.CurrentLimitValue.text = "5000"
        self.PowerLimitMultiplier.text = "1"
        self.PowerLimitUnit.text = "W"
        self.PowerLimitValue.text = "21100"
        self.VoltageLimitMultiplier.text = "-1"
        self.VoltageLimitUnit.text = "V"
        self.VoltageLimitValue.text = "4220"

    def ChargeParameterDiscoveryResponse(self):
        self._V2GDINHeader()
        self.ChargeParameterDiscoveryRes = ET.SubElement(self.Body, "ns3:ChargeParameterDiscoveryRes")
        self.ResponseCode = ET.SubElement(self.ChargeParameterDiscoveryRes, "ns3:ResponseCode")
        self.EVSEProcessing = ET.SubElement(self.ChargeParameterDiscoveryRes, "ns3:EVSEProcessing")
        if self.protocol == Protocol.DIN:
            self.SAScheduleList = ET.SubElement(self.ChargeParameterDiscoveryRes, "ns4:SAScheduleList")
            self.SAScheduleTuple = ET.SubElement(self.SAScheduleList, "ns4:SAScheduleTuple")
            self.SAScheduleTupleID = ET.SubElement(self.SAScheduleTuple, "ns4:SAScheduleTupleID")
            self.PMaxSchedule = ET.SubElement(self.SAScheduleTuple, "ns4:PMaxSchedule")
            self.PMaxScheduleID = ET.SubElement(self.PMaxSchedule, "ns4:PMaxScheduleID")
            self.PMaxScheduleEntry = ET.SubElement(self.PMaxSchedule, "ns4:PMaxScheduleEntry")
            self.RelativeTimeInterval = ET.SubElement(self.PMaxScheduleEntry, "ns4:RelativeTimeInterval")
            self.start = ET.SubElement(self.RelativeTimeInterval, "ns4:start")
            self.PMax = ET.SubElement(self.PMaxScheduleEntry, "ns4:PMax")
        self.DC_EVSEChargeParameter = ET.SubElement(self.ChargeParameterDiscoveryRes, "ns4:DC_EVSEChargeParameter")
        self.DC_EVSEStatus = ET.SubElement(self.DC_EVSEChargeParameter, "ns4:DC_EVSEStatus")
        if self.protocol == Protocol.DIN:
            self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
            self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")
            self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
            self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
        elif self.protocol == Protocol.ISO_2:
            self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
            self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
            self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
            self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")
        self.EVSEMaximumCurrentLimit = ET.SubElement(self.DC_EVSEChargeParameter, "ns4:EVSEMaximumCurrentLimit")
        self.MaxCurrentLimitMultiplier = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns4:Multiplier")
        self.MaxCurrentLimitUnit = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns4:Unit")
        self.MaxCurrentLimitValue = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns4:Value")
        self.EVSEMaximumPowerLimit = ET.SubElement(self.DC_EVSEChargeParameter, "ns4:EVSEMaximumPowerLimit")
        self.MaxPowerLimitMultiplier = ET.SubElement(self.EVSEMaximumPowerLimit, "ns4:Multiplier")
        self.MaxPowerLimitUnit = ET.SubElement(self.EVSEMaximumPowerLimit, "ns4:Unit")
        self.MaxPowerLimitValue = ET.SubElement(self.EVSEMaximumPowerLimit, "ns4:Value")
        self.EVSEMaximumVoltageLimit = ET.SubElement(self.DC_EVSEChargeParameter, "ns4:EVSEMaximumVoltageLimit")
        self.MaxVoltageLimitMultiplier = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns4:Multiplier")
        self.MaxVoltageLimitUnit = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns4:Unit")
        self.MaxVoltageLimitValue = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns4:Value")
        self.EVSEMinimumCurrentLimit = ET.SubElement(self.DC_EVSEChargeParameter, "ns4:EVSEMinimumCurrentLimit")
        self.MinCurrentLimitMultiplier = ET.SubElement(self.EVSEMinimumCurrentLimit, "ns4:Multiplier")
        self.MinCurrentLimitUnit = ET.SubElement(self.EVSEMinimumCurrentLimit, "ns4:Unit")
        self.MinCurrentLimitValue = ET.SubElement(self.EVSEMinimumCurrentLimit, "ns4:Value")
        self.EVSEMinimumVoltageLimit = ET.SubElement(self.DC_EVSEChargeParameter, "ns4:EVSEMinimumVoltageLimit")
        self.MinVoltageLimitMultiplier = ET.SubElement(self.EVSEMinimumVoltageLimit, "ns4:Multiplier")
        self.MinVoltageLimitUnit = ET.SubElement(self.EVSEMinimumVoltageLimit, "ns4:Unit")
        self.MinVoltageLimitValue = ET.SubElement(self.EVSEMinimumVoltageLimit, "ns4:Value")
        self.EVSEPeakCurrentRipple = ET.SubElement(self.DC_EVSEChargeParameter, "ns4:EVSEPeakCurrentRipple")
        self.CurrentRippleMultiplier = ET.SubElement(self.EVSEPeakCurrentRipple, "ns4:Multiplier")
        self.CurrentRippleUnit = ET.SubElement(self.EVSEPeakCurrentRipple, "ns4:Unit")
        self.CurrentRippleValue = ET.SubElement(self.EVSEPeakCurrentRipple, "ns4:Value")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEProcessing.text = "Finished"
        if self.protocol == Protocol.DIN:
            self.SAScheduleTupleID.text = "1"
            self.PMaxScheduleID.text = "1"
            self.start.text = "0"
            self.PMax.text = "32767"
        self.EVSEIsolationStatus.text = "Invalid"
        self.EVSEStatusCode.text = "EVSE_IsolationMonitoringActive"
        self.NotificationMaxDelay.text = "0"
        self.EVSENotification.text = "None"
        self.MaxCurrentLimitMultiplier.text = "0"
        self.MaxCurrentLimitUnit.text = "A"
        self.MaxCurrentLimitValue.text = "125"
        self.MaxPowerLimitMultiplier.text = "1"
        self.MaxPowerLimitUnit.text = "W"
        self.MaxPowerLimitValue.text = "5000"
        self.MaxVoltageLimitMultiplier.text = "0"
        self.MaxVoltageLimitUnit.text = "V"
        self.MaxVoltageLimitValue.text = "440"
        self.MinCurrentLimitMultiplier.text = "0"
        self.MinCurrentLimitUnit.text = "A"
        self.MinCurrentLimitValue.text = "1"
        self.MinVoltageLimitMultiplier.text = "0"
        self.MinVoltageLimitUnit.text = "V"
        self.MinVoltageLimitValue.text = "50"
        self.CurrentRippleMultiplier.text = "0"
        self.CurrentRippleUnit.text = "A"
        self.CurrentRippleValue.text = "3"

    def CableCheckRequest(self):
        self._V2GDINHeader()
        self.CableCheckReq = ET.SubElement(self.Body, "ns3:CableCheckReq")
        self.DC_EVStatus = ET.SubElement(self.CableCheckReq, "ns3:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns4:EVReady")
        # self.EVCabinConditioning = ET.SubElement(self.DC_EVStatus, "ns4:EVCabinConditioning")
        # self.EVRESSConditioning = ET.SubElement(self.DC_EVStatus, "ns4:EVRESSConditioning")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns4:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns4:EVRESSSOC")

        # Default Values
        self.EVReady.text = "true"
        # self.EVCabinConditioning.text = "true"
        # self.EVRESSConditioning.text = "true"
        self.EVErrorCode.text = "NO_ERROR"
        self.EVRESSSOC.text = "10"

    def CableCheckResponse(self):
        self._V2GDINHeader()
        self.CableCheckRes = ET.SubElement(self.Body, "ns3:CableCheckRes")
        self.ResponseCode = ET.SubElement(self.CableCheckRes, "ns3:ResponseCode")
        self.DC_EVSEStatus = ET.SubElement(self.CableCheckRes, "ns3:DC_EVSEStatus")
        if self.protocol == Protocol.DIN:
            self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
            self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")
            self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
            self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
        elif self.protocol == Protocol.ISO_2:
            self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
            self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
            self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
            self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")
        self.EVSEProcessing = ET.SubElement(self.CableCheckRes, "ns3:EVSEProcessing")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEIsolationStatus.text = "Valid"
        self.EVSEStatusCode.text = "EVSE_Ready"
        self.NotificationMaxDelay.text = "0"
        self.EVSENotification.text = "None"
        self.EVSEProcessing.text = "Finished"

    def PreChargeRequest(self):
        self._V2GDINHeader()
        self.PreChargeReq = ET.SubElement(self.Body, "ns3:PreChargeReq")
        self.DC_EVStatus = ET.SubElement(self.PreChargeReq, "ns3:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns4:EVReady")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns4:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns4:EVRESSSOC")
        self.EVTargetVoltage = ET.SubElement(self.PreChargeReq, "ns3:EVTargetVoltage")
        self.TargetVoltageMultiplier = ET.SubElement(self.EVTargetVoltage, "ns4:Multiplier")
        self.TargetVoltageUnit = ET.SubElement(self.EVTargetVoltage, "ns4:Unit")
        self.TargetVoltageValue = ET.SubElement(self.EVTargetVoltage, "ns4:Value")
        self.EVTargetCurrent = ET.SubElement(self.PreChargeReq, "ns3:EVTargetCurrent")
        self.TargetCurrentMultiplier = ET.SubElement(self.EVTargetCurrent, "ns4:Multiplier")
        self.TargetCurrentUnit = ET.SubElement(self.EVTargetCurrent, "ns4:Unit")
        self.TargetCurrentValue = ET.SubElement(self.EVTargetCurrent, "ns4:Value")

        # Default Values
        self.EVReady.text = "true"
        self.EVErrorCode.text = "NO_ERROR"
        self.EVRESSSOC.text = "10"
        self.TargetVoltageMultiplier.text = "0"
        self.TargetVoltageUnit.text = "V"
        self.TargetVoltageValue.text = "400"
        self.TargetCurrentMultiplier.text = "0"
        self.TargetCurrentUnit.text = "A"
        self.TargetCurrentValue.text = "0"

    def PreChargeResponse(self):
        self._V2GDINHeader()
        self.PreChargeRes = ET.SubElement(self.Body, "ns3:PreChargeRes")
        self.ResponseCode = ET.SubElement(self.PreChargeRes, "ns3:ResponseCode")
        self.DC_EVSEStatus = ET.SubElement(self.PreChargeRes, "ns3:DC_EVSEStatus")
        if self.protocol == Protocol.DIN:
            self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
            self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")
            self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
            self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
        elif self.protocol == Protocol.ISO_2:
            self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
            self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
            self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
            self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")
        self.EVSEPresentVoltage = ET.SubElement(self.PreChargeRes, "ns3:EVSEPresentVoltage")
        self.Multiplier = ET.SubElement(self.EVSEPresentVoltage, "ns4:Multiplier")
        self.Unit = ET.SubElement(self.EVSEPresentVoltage, "ns4:Unit")
        self.Value = ET.SubElement(self.EVSEPresentVoltage, "ns4:Value")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEIsolationStatus.text = "Valid"
        self.EVSEStatusCode.text = "EVSE_Ready"
        self.NotificationMaxDelay.text = "0"
        self.EVSENotification.text = "None"
        self.Multiplier.text = "0"
        self.Unit.text = "V"
        self.Value.text = "370"

    def PowerDeliveryRequest(self, complete: bool = False):
        self._V2GDINHeader()
        self.PowerDeliveryReq = ET.SubElement(self.Body, "ns3:PowerDeliveryReq")
        if self.protocol == Protocol.DIN:
            self.ReadyToChargeState = ET.SubElement(self.PowerDeliveryReq, "ns3:ReadyToChargeState")
        elif self.protocol == Protocol.ISO_2:
            self.ChargeProgress = ET.SubElement(self.PowerDeliveryReq, "ns3:ChargeProgress")
            self.SAScheduleTupleID = ET.SubElement(self.PowerDeliveryReq, "ns3:SAScheduleTupleID")
        self.DC_EVPowerDeliveryParameter = ET.SubElement(self.PowerDeliveryReq, "ns4:DC_EVPowerDeliveryParameter")
        self.DC_EVStatus = ET.SubElement(self.DC_EVPowerDeliveryParameter, "ns4:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns4:EVReady")
        if self.protocol == Protocol.DIN:
            self.EVCabinConditioning = ET.SubElement(self.DC_EVStatus, "ns4:EVCabinConditioning")
            self.EVRESSConditioning = ET.SubElement(self.DC_EVStatus, "ns4:EVRESSConditioning")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns4:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns4:EVRESSSOC")
        self.ChargingComplete = ET.SubElement(self.DC_EVPowerDeliveryParameter, "ns4:ChargingComplete")

        # Default Values
        if self.protocol == Protocol.DIN:
            self.ReadyToChargeState.text = "true"
        elif self.protocol == Protocol.ISO_2:
            if complete:
                self.ChargeProgress.text = "Stop"
            else:
                self.ChargeProgress.text = "Start"
            self.SAScheduleTupleID.text = "1"
        self.EVReady.text = "true"
        if self.protocol == Protocol.DIN:
            self.EVCabinConditioning.text = "false"
            self.EVRESSConditioning.text = "true"
        self.EVErrorCode.text = "NO_ERROR"
        if complete:
            self.EVRESSSOC.text = "100"
            self.ChargingComplete.text = "true"
        else:
            self.EVRESSSOC.text = "10"
            self.ChargingComplete.text = "false"

    def PowerDeliveryResponse(self):
        self._V2GDINHeader()
        self.PowerDeliveryRes = ET.SubElement(self.Body, "ns3:PowerDeliveryRes")
        self.ResponseCode = ET.SubElement(self.PowerDeliveryRes, "ns3:ResponseCode")
        self.DC_EVSEStatus = ET.SubElement(self.PowerDeliveryRes, "ns4:DC_EVSEStatus")
        if self.protocol == Protocol.DIN:
            self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
            self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")
            self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
            self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
        elif self.protocol == Protocol.ISO_2:
            self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
            self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
            self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
            self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEIsolationStatus.text = "Valid"
        self.EVSEStatusCode.text = "EVSE_Ready"
        self.NotificationMaxDelay.text = "0"
        self.EVSENotification.text = "None"

    def CurrentDemandRequest(self):
        self._V2GDINHeader()
        self.CurrentDemandReq = ET.SubElement(self.Body, "ns3:CurrentDemandReq")
        self.DC_EVStatus = ET.SubElement(self.CurrentDemandReq, "ns3:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns4:EVReady")
        if self.protocol == Protocol.DIN:
            self.EVCabinConditioning = ET.SubElement(self.DC_EVStatus, "ns4:EVCabinConditioning")
            self.EVRESSConditioning = ET.SubElement(self.DC_EVStatus, "ns4:EVRESSConditioning")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns4:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns4:EVRESSSOC")
        self.EVTargetCurrent = ET.SubElement(self.CurrentDemandReq, "ns3:EVTargetCurrent")
        self.TargetCurrentMultiplier = ET.SubElement(self.EVTargetCurrent, "ns4:Multiplier")
        self.TargetCurrentUnit = ET.SubElement(self.EVTargetCurrent, "ns4:Unit")
        self.TargetCurrentValue = ET.SubElement(self.EVTargetCurrent, "ns4:Value")
        self.EVMaximumVoltageLimit = ET.SubElement(self.CurrentDemandReq, "ns3:EVMaximumVoltageLimit")
        self.VoltageLimitMultiplier = ET.SubElement(self.EVMaximumVoltageLimit, "ns4:Multiplier")
        self.VoltageLimitUnit = ET.SubElement(self.EVMaximumVoltageLimit, "ns4:Unit")
        self.VoltageLimitValue = ET.SubElement(self.EVMaximumVoltageLimit, "ns4:Value")
        self.EVMaximumCurrentLimit = ET.SubElement(self.CurrentDemandReq, "ns3:EVMaximumCurrentLimit")
        self.CurrentLimitMultiplier = ET.SubElement(self.EVMaximumCurrentLimit, "ns4:Multiplier")
        self.CurrentLimitUnit = ET.SubElement(self.EVMaximumCurrentLimit, "ns4:Unit")
        self.CurrentLimitValue = ET.SubElement(self.EVMaximumCurrentLimit, "ns4:Value")
        self.BulkChargingComplete = ET.SubElement(self.CurrentDemandReq, "ns3:BulkChargingComplete")
        self.ChargingComplete = ET.SubElement(self.CurrentDemandReq, "ns3:ChargingComplete")
        self.RemainingTimeToFullSoC = ET.SubElement(self.CurrentDemandReq, "ns3:RemainingTimeToFullSoC")
        self.TimeToFullSoCMultiplier = ET.SubElement(self.RemainingTimeToFullSoC, "ns4:Multiplier")
        self.TimeToFullSoCUnit = ET.SubElement(self.RemainingTimeToFullSoC, "ns4:Unit")
        self.TimeToFullSoCValue = ET.SubElement(self.RemainingTimeToFullSoC, "ns4:Value")
        self.RemainingTimeToBulkSoC = ET.SubElement(self.CurrentDemandReq, "ns3:RemainingTimeToBulkSoC")
        self.TimeToBulkSoCMultiplier = ET.SubElement(self.RemainingTimeToBulkSoC, "ns4:Multiplier")
        self.TimeToBulkSoCUnit = ET.SubElement(self.RemainingTimeToBulkSoC, "ns4:Unit")
        self.TimeToBulkSoCValue = ET.SubElement(self.RemainingTimeToBulkSoC, "ns4:Value")
        self.EVTargetVoltage = ET.SubElement(self.CurrentDemandReq, "ns3:EVTargetVoltage")
        self.TargetVoltageMultiplier = ET.SubElement(self.EVTargetVoltage, "ns4:Multiplier")
        self.TargetVoltageUnit = ET.SubElement(self.EVTargetVoltage, "ns4:Unit")
        self.TargetVoltageValue = ET.SubElement(self.EVTargetVoltage, "ns4:Value")

        # Default Values
        self.EVReady.text = "true"
        if self.protocol == Protocol.DIN:
            self.EVCabinConditioning.text = "true"
            self.EVRESSConditioning.text = "true"
        self.EVErrorCode.text = "NO_ERROR"
        self.EVRESSSOC.text = "10"
        self.TargetCurrentMultiplier.text = "0"
        self.TargetCurrentUnit.text = "A"
        self.TargetCurrentValue.text = "0"
        self.VoltageLimitMultiplier.text = "-1"
        self.VoltageLimitUnit.text = "V"
        self.VoltageLimitValue.text = "4000"
        self.CurrentLimitMultiplier.text = "0"
        self.CurrentLimitUnit.text = "A"
        self.CurrentLimitValue.text = "125"
        self.BulkChargingComplete.text = "false"
        self.ChargingComplete.text = "false"
        self.TimeToFullSoCMultiplier.text = "1"
        self.TimeToFullSoCUnit.text = "s"
        self.TimeToFullSoCValue.text = "0"
        self.TimeToBulkSoCMultiplier.text = "1"
        self.TimeToBulkSoCUnit.text = "s"
        self.TimeToBulkSoCValue.text = "0"
        self.TargetVoltageMultiplier.text = "-1"
        self.TargetVoltageUnit.text = "V"
        self.TargetVoltageValue.text = "4000"

    def CurrentDemandResponse(self):
        self._V2GDINHeader()
        self.CurrentDemandRes = ET.SubElement(self.Body, "ns3:CurrentDemandRes")
        self.ResponseCode = ET.SubElement(self.CurrentDemandRes, "ns3:ResponseCode")
        self.DC_EVSEStatus = ET.SubElement(self.CurrentDemandRes, "ns3:DC_EVSEStatus")
        if self.protocol == Protocol.DIN:
            self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
            self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")
            self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
            self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
        elif self.protocol == Protocol.ISO_2:
            self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
            self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
            self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
            self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")
        self.EVSEPresentVoltage = ET.SubElement(self.CurrentDemandRes, "ns3:EVSEPresentVoltage")
        self.VoltageMultiplier = ET.SubElement(self.EVSEPresentVoltage, "ns4:Multiplier")
        self.VoltageUnit = ET.SubElement(self.EVSEPresentVoltage, "ns4:Unit")
        self.VoltageValue = ET.SubElement(self.EVSEPresentVoltage, "ns4:Value")
        self.EVSEPresentCurrent = ET.SubElement(self.CurrentDemandRes, "ns3:EVSEPresentCurrent")
        self.CurrentMultiplier = ET.SubElement(self.EVSEPresentCurrent, "ns4:Multiplier")
        self.CurrentUnit = ET.SubElement(self.EVSEPresentCurrent, "ns4:Unit")
        self.CurrentValue = ET.SubElement(self.EVSEPresentCurrent, "ns4:Value")
        self.EVSECurrentLimitAchieved = ET.SubElement(self.CurrentDemandRes, "ns3:EVSECurrentLimitAchieved")
        self.EVSEVoltageLimitAchieved = ET.SubElement(self.CurrentDemandRes, "ns3:EVSEVoltageLimitAchieved")
        self.EVSEPowerLimitAchieved = ET.SubElement(self.CurrentDemandRes, "ns3:EVSEPowerLimitAchieved")
        self.EVSEMaximumVoltageLimit = ET.SubElement(self.CurrentDemandRes, "ns3:EVSEMaximumVoltageLimit")
        self.VoltageLimitMultiplier = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns4:Multiplier")
        self.VoltageLimitUnit = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns4:Unit")
        self.VoltageLimitValue = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns4:Value")
        self.EVSEMaximumCurrentLimit = ET.SubElement(self.CurrentDemandRes, "ns3:EVSEMaximumCurrentLimit")
        self.CurrentLimitMultiplier = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns4:Multiplier")
        self.CurrentLimitUnit = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns4:Unit")
        self.CurrentLimitValue = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns4:Value")
        self.EVSEMaximumPowerLimit = ET.SubElement(self.CurrentDemandRes, "ns3:EVSEMaximumPowerLimit")
        self.PowerLimitMultiplier = ET.SubElement(self.EVSEMaximumPowerLimit, "ns4:Multiplier")
        self.PowerLimitUnit = ET.SubElement(self.EVSEMaximumPowerLimit, "ns4:Unit")
        self.PowerLimitValue = ET.SubElement(self.EVSEMaximumPowerLimit, "ns4:Value")
        if self.protocol == Protocol.ISO_2:
            self.EVSEID = ET.SubElement(self.CurrentDemandRes, "ns3:EVSEID")
            self.SAScheduleTupleID = ET.SubElement(self.CurrentDemandRes, "ns3:SAScheduleTupleID")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEIsolationStatus.text = "Valid"
        self.EVSEStatusCode.text = "EVSE_Ready"
        self.NotificationMaxDelay.text = "0"
        self.EVSENotification.text = "None"
        self.VoltageMultiplier.text = "0"
        self.VoltageUnit.text = "V"
        self.VoltageValue.text = "0"
        self.CurrentMultiplier.text = "0"
        self.CurrentUnit.text = "A"
        self.CurrentValue.text = "0"
        self.EVSECurrentLimitAchieved.text = "false"
        self.EVSEVoltageLimitAchieved.text = "false"
        self.EVSEPowerLimitAchieved.text = "false"
        self.VoltageLimitMultiplier.text = "0"
        self.VoltageLimitUnit.text = "V"
        self.VoltageLimitValue.text = "440"
        self.CurrentLimitMultiplier.text = "0"
        self.CurrentLimitUnit.text = "A"
        self.CurrentLimitValue.text = "125"
        self.PowerLimitMultiplier.text = "1"
        self.PowerLimitUnit.text = "W"
        self.PowerLimitValue.text = "5000"
        if self.protocol == Protocol.ISO_2:
            self.EVSEID.text = "FR*A23*ANUEVO"
            self.SAScheduleTupleID.text = "1"
            
    def WeldingDetectionRequest(self):
        if self.protocol == Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.WeldingDetectionReq = ET.SubElement(self.Body, "ns3:WeldingDetectionReq")
        self.DC_EVStatus = ET.SubElement(self.WeldingDetectionReq, "ns3:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns4:EVReady")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns4:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns4:EVRESSSOC")
        
        # Default Values
        self.EVReady.text = "true"
        self.EVErrorCode.text = "NO_ERROR"
        self.EVRESSSOC.text = "100"
            
    def WeldingDetectionResponse(self):
        if self.protocol == Protocol.DIN:
            raise Exception("Wrong message type for selected protocol.")
        self._V2GDINHeader()
        self.WeldingDetectionRes = ET.SubElement(self.Body, "ns3:WeldingDetectionRes")
        self.ResponseCode = ET.SubElement(self.WeldingDetectionRes, "ns3:ResponseCode")
        self.DC_EVSEStatus = ET.SubElement(self.WeldingDetectionRes, "ns3:DC_EVSEStatus")
        self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns4:NotificationMaxDelay")
        self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSENotification")
        self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEIsolationStatus")
        self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns4:EVSEStatusCode")
        self.EVSEPresentVoltage = ET.SubElement(self.WeldingDetectionRes, "ns3:EVSEPresentVoltage")
        self.Multiplier = ET.SubElement(self.EVSEPresentVoltage, "ns4:Multiplier")
        self.Unit = ET.SubElement(self.EVSEPresentVoltage, "ns4:Unit")
        self.Value = ET.SubElement(self.EVSEPresentVoltage, "ns4:Value")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEIsolationStatus.text = "Valid"
        self.EVSEStatusCode.text = "EVSE_Ready"
        self.NotificationMaxDelay.text = "0"
        self.EVSENotification.text = "None"
        self.Multiplier.text = "0"
        self.Unit.text = "V"
        self.Value.text = "0"

    def SessionStopRequest(self):
        self._V2GDINHeader()
        self.SessionStopReq = ET.SubElement(self.Body, "ns3:SessionStopReq")
        
        if self.protocol == Protocol.ISO_2:
            self.ChargingSession = ET.SubElement(self.SessionStopReq, "ns3:ChargingSession")
            
        # Default Values
        if self.protocol == Protocol.ISO_2:
            self.ChargingSession.text = "Terminate"

    def SessionStopResponse(self):
        self._V2GDINHeader()
        self.SessionStopRes = ET.SubElement(self.Body, "ns3:SessionStopRes")
        self.ResponseCode = ET.SubElement(self.SessionStopRes, "ns3:ResponseCode")

        # Default Values
        self.ResponseCode.text = "OK"

    def show(self):
        s = ET.tostring(self.root, "UTF-8")
        r = xml.dom.minidom.parseString(s)
        print(r.toprettyxml())

    def getString(self):
        return ET.tostring(self.root, encoding="UTF-8", method="xml").decode().replace("\n", "").replace("'", '"')

    def getEXI(self):
        return self.exi.encode(self.getString())

    def _cleanup(self):
        for name in self.__dict__.copy().keys():
            if name != "exi" and name != "protocol":
                delattr(self, name)


if __name__ == "__main__":
    x = XMLBuilder(EXIProcessor(protocol=Protocol.DIN))
    x.CurrentDemandRequest()
    x.show()
    print(x.getString() + "\n")
    # exi = x.getEXI()
    # print(binascii.unhexlify(exi))
