"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

# need to do this to import the custom SECC and V2G scapy layer
import sys, os

sys.path.append("./external_libs/HomePlugPWN")
sys.path.append("./external_libs/V2GInjector/core")

import xml.etree.ElementTree as ET
import xml.dom.minidom
from layers.V2G import *
from EXIProcessor import EXIProcessor
from EmulatorEnum import *

# Used to build and encode XML tree into EXI string for layer 3 communication


class XMLBuilder:
    def __init__(self, exi: EXIProcessor):
        self.exi = exi

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
        self.ProtocolNamespace.text = "urn:din:70121:2012:MsgDef"
        # self.ProtocolNamespace.text = "urn:iso:15118:2:2013:MsgDef"
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
        self.root = ET.Element("ns7:V2G_Message")
        self.root.set("xmlns:ns7", "urn:din:70121:2012:MsgDef")
        self.root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
        self.root.set("xmlns:ns3", "http://www.w3.org/2001/XMLSchema")
        self.root.set("xmlns:ns4", "http://www.w3.org/2000/09/xmldsig#")
        self.root.set("xmlns:ns5", "urn:din:70121:2012:MsgBody")
        self.root.set("xmlns:ns6", "urn:din:70121:2012:MsgDataTypes")
        self.root.set("xmlns:ns8", "urn:din:70121:2012:MsgHeader")
        self.Header = ET.SubElement(self.root, "ns7:Header")
        self.SessionID = ET.SubElement(self.Header, "ns8:SessionID")
        self.Body = ET.SubElement(self.root, "ns7:Body")

        # Default Value
        self.SessionID.text = "4142423030303031"

    def SessionSetupRequest(self):
        self._V2GDINHeader()
        self.SessionSetupReq = ET.SubElement(self.Body, "ns5:SessionSetupReq")
        self.EVCCID = ET.SubElement(self.SessionSetupReq, "ns5:EVCCID")

        # Default Values
        self.SessionID.text = None
        self.EVCCID.text = "0000F07F0C006B1C"
        self.SessionID.text = "00"

    def SessionSetupResponse(self):
        self._V2GDINHeader()
        self.SessionSetupRes = ET.SubElement(self.Body, "ns5:SessionSetupRes")
        self.ResponseCode = ET.SubElement(self.SessionSetupRes, "ns5:ResponseCode")
        self.EVSEID = ET.SubElement(self.SessionSetupRes, "ns5:EVSEID")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEID.text = "00"

    def ServiceDiscoveryRequest(self):
        self._V2GDINHeader()
        self.ServiceDiscoveryReq = ET.SubElement(self.Body, "ns5:ServiceDiscoveryReq")
        # self.ServiceScope = ET.SubElement(self.ServiceDiscoveryReq, "ns5:ServiceScope")
        self.ServiceCategory = ET.SubElement(self.ServiceDiscoveryReq, "ns5:ServiceCategory")

        # Default Values
        self.ServiceCategory.text = "EVCharging"

    def ServiceDiscoveryResponse(self):
        self._V2GDINHeader()
        self.ServiceDiscoveryRes = ET.SubElement(self.Body, "ns5:ServiceDiscoveryRes")
        self.ResponseCode = ET.SubElement(self.ServiceDiscoveryRes, "ns5:ResponseCode")
        self.PaymentOptions = ET.SubElement(self.ServiceDiscoveryRes, "ns5:PaymentOptions")
        self.PaymentOption = ET.SubElement(self.PaymentOptions, "ns6:PaymentOption")
        self.ChargeService = ET.SubElement(self.ServiceDiscoveryRes, "ns5:ChargeService")
        self.ServiceTag = ET.SubElement(self.ChargeService, "ns6:ServiceTag")
        self.ServiceID = ET.SubElement(self.ServiceTag, "ns6:ServiceID")
        self.ServiceCategory = ET.SubElement(self.ServiceTag, "ns6:ServiceCategory")
        self.FreeService = ET.SubElement(self.ChargeService, "ns6:FreeService")
        self.EnergyTransferType = ET.SubElement(self.ChargeService, "ns6:EnergyTransferType")

        # Default Values
        self.ResponseCode.text = "OK"
        self.PaymentOption.text = "ExternalPayment"
        self.ServiceID.text = "1"
        self.ServiceCategory.text = "EVCharging"
        self.FreeService.text = "false"
        self.EnergyTransferType.text = "DC_extended"

    def ServicePaymentSelectionRequest(self):
        self._V2GDINHeader()
        self.ServicePaymentSelectionReq = ET.SubElement(self.Body, "ns5:ServicePaymentSelectionReq")
        self.SelectedPaymentOption = ET.SubElement(self.ServicePaymentSelectionReq, "ns5:SelectedPaymentOption")
        self.SelectedServiceList = ET.SubElement(self.ServicePaymentSelectionReq, "ns5:SelectedServiceList")
        self.SelectedService = ET.SubElement(self.SelectedServiceList, "ns6:SelectedService")
        self.ServiceID = ET.SubElement(self.SelectedService, "ns6:ServiceID")

        # Default Values
        self.SelectedPaymentOption.text = "ExternalPayment"
        self.ServiceID.text = "1"

    def ServicePaymentSelectionResponse(self):
        self._V2GDINHeader()
        self.ServicePaymentSelectionRes = ET.SubElement(self.Body, "ns5:ServicePaymentSelectionRes")
        self.ResponseCode = ET.SubElement(self.ServicePaymentSelectionRes, "ns5:ResponseCode")

        # Default Values
        self.ResponseCode.text = "OK"

    def ContractAuthenticationRequest(self):
        self._V2GDINHeader()
        self.ContractAuthenticationReq = ET.SubElement(self.Body, "ns5:ContractAuthenticationReq")

    def ContractAuthenticationResponse(self):
        self._V2GDINHeader()
        self.ContractAuthenticationRes = ET.SubElement(self.Body, "ns5:ContractAuthenticationRes")
        self.ResponseCode = ET.SubElement(self.ContractAuthenticationRes, "ns5:ResponseCode")
        self.EVSEProcessing = ET.SubElement(self.ContractAuthenticationRes, "ns5:EVSEProcessing")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEProcessing.text = "Finished"

    def ChargeParameterDiscoveryRequest(self):
        self._V2GDINHeader()
        self.ChargeParameterDiscoverReq = ET.SubElement(self.Body, "ns5:ChargeParameterDiscoveryReq")
        self.EVRequestedEnergyTransferType = ET.SubElement(self.ChargeParameterDiscoverReq, "ns5:EVRequestedEnergyTransferType")
        self.DC_EVChargeParameter = ET.SubElement(self.ChargeParameterDiscoverReq, "ns6:DC_EVChargeParameter")
        self.DC_EVStatus = ET.SubElement(self.DC_EVChargeParameter, "ns6:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns6:EVReady")
        # self.EVCabinConditioning = ET.SubElement(self.DC_EVStatus, "ns6:EVCabinConditioning")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns6:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns6:EVRESSSOC")
        self.EVMaximumCurrentLimit = ET.SubElement(self.DC_EVChargeParameter, "ns6:EVMaximumCurrentLimit")
        self.CurrentLimitMultiplier = ET.SubElement(self.EVMaximumCurrentLimit, "ns6:Multiplier")
        self.CurrentLimitUnit = ET.SubElement(self.EVMaximumCurrentLimit, "ns6:Unit")
        self.CurrentLimitValue = ET.SubElement(self.EVMaximumCurrentLimit, "ns6:Value")
        self.EVMaximumPowerLimit = ET.SubElement(self.DC_EVChargeParameter, "ns6:EVMaximumPowerLimit")
        self.PowerLimitMultiplier = ET.SubElement(self.EVMaximumPowerLimit, "ns6:Multiplier")
        self.PowerLimitUnit = ET.SubElement(self.EVMaximumPowerLimit, "ns6:Unit")
        self.PowerLimitValue = ET.SubElement(self.EVMaximumPowerLimit, "ns6:Value")
        self.EVMaximumVoltageLimit = ET.SubElement(self.DC_EVChargeParameter, "ns6:EVMaximumVoltageLimit")
        self.VoltageLimitMultiplier = ET.SubElement(self.EVMaximumVoltageLimit, "ns6:Multiplier")
        self.VoltageLimitUnit = ET.SubElement(self.EVMaximumVoltageLimit, "ns6:Unit")
        self.VoltageLimitValue = ET.SubElement(self.EVMaximumVoltageLimit, "ns6:Value")

        # Default Values
        self.EVRequestedEnergyTransferType.text = "DC_extended"
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
        self.ChargeParameterDiscoveryRes = ET.SubElement(self.Body, "ns5:ChargeParameterDiscoveryRes")
        self.ResponseCode = ET.SubElement(self.ChargeParameterDiscoveryRes, "ns5:ResponseCode")
        self.EVSEProcessing = ET.SubElement(self.ChargeParameterDiscoveryRes, "ns5:EVSEProcessing")
        self.SAScheduleList = ET.SubElement(self.ChargeParameterDiscoveryRes, "ns6:SAScheduleList")
        self.SAScheduleTuple = ET.SubElement(self.SAScheduleList, "ns6:SAScheduleTuple")
        self.SAScheduleTupleID = ET.SubElement(self.SAScheduleTuple, "ns6:SAScheduleTupleID")
        self.PMaxSchedule = ET.SubElement(self.SAScheduleTuple, "ns6:PMaxSchedule")
        self.PMaxScheduleID = ET.SubElement(self.PMaxSchedule, "ns6:PMaxScheduleID")
        self.PMaxScheduleEntry = ET.SubElement(self.PMaxSchedule, "ns6:PMaxScheduleEntry")
        self.RelativeTimeInterval = ET.SubElement(self.PMaxScheduleEntry, "ns6:RelativeTimeInterval")
        self.start = ET.SubElement(self.RelativeTimeInterval, "ns6:start")
        self.PMax = ET.SubElement(self.PMaxScheduleEntry, "ns6:PMax")
        self.DC_EVSEChargeParameter = ET.SubElement(self.ChargeParameterDiscoveryRes, "ns6:DC_EVSEChargeParameter")
        self.DC_EVSEStatus = ET.SubElement(self.DC_EVSEChargeParameter, "ns6:DC_EVSEStatus")
        self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSEIsolationStatus")
        self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSEStatusCode")
        self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns6:NotificationMaxDelay")
        self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSENotification")
        self.EVSEMaximumCurrentLimit = ET.SubElement(self.DC_EVSEChargeParameter, "ns6:EVSEMaximumCurrentLimit")
        self.MaxCurrentLimitMultiplier = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns6:Multiplier")
        self.MaxCurrentLimitUnit = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns6:Unit")
        self.MaxCurrentLimitValue = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns6:Value")
        self.EVSEMaximumPowerLimit = ET.SubElement(self.DC_EVSEChargeParameter, "ns6:EVSEMaximumPowerLimit")
        self.MaxPowerLimitMultiplier = ET.SubElement(self.EVSEMaximumPowerLimit, "ns6:Multiplier")
        self.MaxPowerLimitUnit = ET.SubElement(self.EVSEMaximumPowerLimit, "ns6:Unit")
        self.MaxPowerLimitValue = ET.SubElement(self.EVSEMaximumPowerLimit, "ns6:Value")
        self.EVSEMaximumVoltageLimit = ET.SubElement(self.DC_EVSEChargeParameter, "ns6:EVSEMaximumVoltageLimit")
        self.MaxVoltageLimitMultiplier = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns6:Multiplier")
        self.MaxVoltageLimitUnit = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns6:Unit")
        self.MaxVoltageLimitValue = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns6:Value")
        self.EVSEMinimumCurrentLimit = ET.SubElement(self.DC_EVSEChargeParameter, "ns6:EVSEMinimumCurrentLimit")
        self.MinCurrentLimitMultiplier = ET.SubElement(self.EVSEMinimumCurrentLimit, "ns6:Multiplier")
        self.MinCurrentLimitUnit = ET.SubElement(self.EVSEMinimumCurrentLimit, "ns6:Unit")
        self.MinCurrentLimitValue = ET.SubElement(self.EVSEMinimumCurrentLimit, "ns6:Value")
        self.EVSEMinimumVoltageLimit = ET.SubElement(self.DC_EVSEChargeParameter, "ns6:EVSEMinimumVoltageLimit")
        self.MinVoltageLimitMultiplier = ET.SubElement(self.EVSEMinimumVoltageLimit, "ns6:Multiplier")
        self.MinVoltageLimitUnit = ET.SubElement(self.EVSEMinimumVoltageLimit, "ns6:Unit")
        self.MinVoltageLimitValue = ET.SubElement(self.EVSEMinimumVoltageLimit, "ns6:Value")
        self.EVSEPeakCurrentRipple = ET.SubElement(self.DC_EVSEChargeParameter, "ns6:EVSEPeakCurrentRipple")
        self.CurrentRippleMultiplier = ET.SubElement(self.EVSEPeakCurrentRipple, "ns6:Multiplier")
        self.CurrentRippleUnit = ET.SubElement(self.EVSEPeakCurrentRipple, "ns6:Unit")
        self.CurrentRippleValue = ET.SubElement(self.EVSEPeakCurrentRipple, "ns6:Value")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEProcessing.text = "Finished"
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
        self.CableCheckReq = ET.SubElement(self.Body, "ns5:CableCheckReq")
        self.DC_EVStatus = ET.SubElement(self.CableCheckReq, "ns5:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns6:EVReady")
        # self.EVCabinConditioning = ET.SubElement(self.DC_EVStatus, "ns6:EVCabinConditioning")
        # self.EVRESSConditioning = ET.SubElement(self.DC_EVStatus, "ns6:EVRESSConditioning")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns6:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns6:EVRESSSOC")

        # Default Values
        self.EVReady.text = "true"
        # self.EVCabinConditioning.text = "true"
        # self.EVRESSConditioning.text = "true"
        self.EVErrorCode.text = "NO_ERROR"
        self.EVRESSSOC.text = "10"

    def CableCheckResponse(self):
        self._V2GDINHeader()
        self.CableCheckRes = ET.SubElement(self.Body, "ns5:CableCheckRes")
        self.ResponseCode = ET.SubElement(self.CableCheckRes, "ns5:ResponseCode")
        self.DC_EVSEStatus = ET.SubElement(self.CableCheckRes, "ns5:DC_EVSEStatus")
        self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSEIsolationStatus")
        self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSEStatusCode")
        self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns6:NotificationMaxDelay")
        self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSENotification")
        self.EVSEProcessing = ET.SubElement(self.CableCheckRes, "ns5:EVSEProcessing")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEIsolationStatus.text = "Valid"
        self.EVSEStatusCode.text = "EVSE_Ready"
        self.NotificationMaxDelay.text = "0"
        self.EVSENotification.text = "None"
        self.EVSEProcessing.text = "Finished"

    def PreChargeRequest(self):
        self._V2GDINHeader()
        self.PreChargeReq = ET.SubElement(self.Body, "ns5:PreChargeReq")
        self.DC_EVStatus = ET.SubElement(self.PreChargeReq, "ns5:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns6:EVReady")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns6:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns6:EVRESSSOC")
        self.EVTargetVoltage = ET.SubElement(self.PreChargeReq, "ns5:EVTargetVoltage")
        self.TargetVoltageMultiplier = ET.SubElement(self.EVTargetVoltage, "ns6:Multiplier")
        self.TargetVoltageUnit = ET.SubElement(self.EVTargetVoltage, "ns6:Unit")
        self.TargetVoltageValue = ET.SubElement(self.EVTargetVoltage, "ns6:Value")
        self.EVTargetCurrent = ET.SubElement(self.PreChargeReq, "ns5:EVTargetCurrent")
        self.TargetCurrentMultiplier = ET.SubElement(self.EVTargetCurrent, "ns6:Multiplier")
        self.TargetCurrentUnit = ET.SubElement(self.EVTargetCurrent, "ns6:Unit")
        self.TargetCurrentValue = ET.SubElement(self.EVTargetCurrent, "ns6:Value")

        # Default Values
        self.EVReady.text = "true"
        self.EVErrorCode.text = "NO_ERROR"
        self.EVRESSSOC.text = "10"
        self.TargetVoltageMultiplier.text = "-1"
        self.TargetVoltageUnit.text = "V"
        self.TargetVoltageValue.text = "4000"
        self.TargetCurrentMultiplier.text = "0"
        self.TargetCurrentUnit.text = "A"
        self.TargetCurrentValue.text = "0"

    def PreChargeResponse(self):
        self._V2GDINHeader()
        self.PreChargeRes = ET.SubElement(self.Body, "ns5:PreChargeRes")
        self.ResponseCode = ET.SubElement(self.PreChargeRes, "ns5:ResponseCode")
        self.DC_EVSEStatus = ET.SubElement(self.PreChargeRes, "ns5:DC_EVSEStatus")
        self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSEIsolationStatus")
        self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSEStatusCode")
        self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns6:NotificationMaxDelay")
        self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSENotification")
        self.EVSEPresentVoltage = ET.SubElement(self.PreChargeRes, "ns5:EVSEPresentVoltage")
        self.Multiplier = ET.SubElement(self.EVSEPresentVoltage, "ns6:Multiplier")
        self.Unit = ET.SubElement(self.EVSEPresentVoltage, "ns6:Unit")
        self.Value = ET.SubElement(self.EVSEPresentVoltage, "ns6:Value")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEIsolationStatus.text = "Valid"
        self.EVSEStatusCode.text = "EVSE_Ready"
        self.NotificationMaxDelay.text = "0"
        self.EVSENotification.text = "None"
        self.Multiplier.text = "0"
        self.Unit.text = "V"
        self.Value.text = "370"

    def PowerDeliveryRequest(self):
        self._V2GDINHeader()
        self.PowerDeliveryReq = ET.SubElement(self.Body, "ns5:PowerDeliveryReq")
        self.ReadyToChargeState = ET.SubElement(self.PowerDeliveryReq, "ns5:ReadyToChargeState")
        self.DC_EVPowerDeliveryParameter = ET.SubElement(self.PowerDeliveryReq, "ns6:DC_EVPowerDeliveryParameter")
        self.DC_EVStatus = ET.SubElement(self.DC_EVPowerDeliveryParameter, "ns6:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns6:EVReady")
        self.EVCabinConditioning = ET.SubElement(self.DC_EVStatus, "ns6:EVCabinConditioning")
        self.EVRESSConditioning = ET.SubElement(self.DC_EVStatus, "ns6:EVRESSConditioning")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns6:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns6:EVRESSSOC")
        self.ChargingComplete = ET.SubElement(self.DC_EVPowerDeliveryParameter, "ns6:ChargingComplete")

        # Default Values
        self.ReadyToChargeState.text = "true"
        self.EVReady.text = "true"
        self.EVCabinConditioning.text = "false"
        self.EVRESSConditioning.text = "true"
        self.EVErrorCode.text = "NO_ERROR"
        self.EVRESSSOC.text = "10"
        self.ChargingComplete.text = "false"

    def PowerDeliveryResponse(self):
        self._V2GDINHeader()
        self.PowerDeliveryRes = ET.SubElement(self.Body, "ns5:PowerDeliveryRes")
        self.ResponseCode = ET.SubElement(self.PowerDeliveryRes, "ns5:ResponseCode")
        self.DC_EVSEStatus = ET.SubElement(self.PowerDeliveryRes, "ns6:DC_EVSEStatus")
        self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSEIsolationStatus")
        self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSEStatusCode")
        self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns6:NotificationMaxDelay")
        self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSENotification")

        # Default Values
        self.ResponseCode.text = "OK"
        self.EVSEIsolationStatus.text = "Valid"
        self.EVSEStatusCode.text = "EVSE_Ready"
        self.NotificationMaxDelay.text = "0"
        self.EVSENotification.text = "None"

    def CurrentDemandRequest(self):
        self._V2GDINHeader()
        self.CurrentDemandReq = ET.SubElement(self.Body, "ns5:CurrentDemandReq")
        self.DC_EVStatus = ET.SubElement(self.CurrentDemandReq, "ns5:DC_EVStatus")
        self.EVReady = ET.SubElement(self.DC_EVStatus, "ns6:EVReady")
        self.EVCabinConditioning = ET.SubElement(self.DC_EVStatus, "ns6:EVCabinConditioning")
        self.EVRESSConditioning = ET.SubElement(self.DC_EVStatus, "ns6:EVRESSConditioning")
        self.EVErrorCode = ET.SubElement(self.DC_EVStatus, "ns6:EVErrorCode")
        self.EVRESSSOC = ET.SubElement(self.DC_EVStatus, "ns6:EVRESSSOC")
        self.EVTargetCurrent = ET.SubElement(self.CurrentDemandReq, "ns5:EVTargetCurrent")
        self.TargetCurrentMultiplier = ET.SubElement(self.EVTargetCurrent, "ns6:Multiplier")
        self.TargetCurrentUnit = ET.SubElement(self.EVTargetCurrent, "ns6:Unit")
        self.TargetCurrentValue = ET.SubElement(self.EVTargetCurrent, "ns6:Value")
        self.EVMaximumVoltageLimit = ET.SubElement(self.CurrentDemandReq, "ns5:EVMaximumVoltageLimit")
        self.VoltageLimitMultiplier = ET.SubElement(self.EVMaximumVoltageLimit, "ns6:Multiplier")
        self.VoltageLimitUnit = ET.SubElement(self.EVMaximumVoltageLimit, "ns6:Unit")
        self.VoltageLimitValue = ET.SubElement(self.EVMaximumVoltageLimit, "ns6:Value")
        self.EVMaximumCurrentLimit = ET.SubElement(self.CurrentDemandReq, "ns5:EVMaximumCurrentLimit")
        self.CurrentLimitMultiplier = ET.SubElement(self.EVMaximumCurrentLimit, "ns6:Multiplier")
        self.CurrentLimitUnit = ET.SubElement(self.EVMaximumCurrentLimit, "ns6:Unit")
        self.CurrentLimitValue = ET.SubElement(self.EVMaximumCurrentLimit, "ns6:Value")
        self.BulkChargingComplete = ET.SubElement(self.CurrentDemandReq, "ns5:BulkChargingComplete")
        self.ChargingComplete = ET.SubElement(self.CurrentDemandReq, "ns5:ChargingComplete")
        self.RemainingTimeToFullSoC = ET.SubElement(self.CurrentDemandReq, "ns5:RemainingTimeToFullSoC")
        self.TimeToFullSoCMultiplier = ET.SubElement(self.RemainingTimeToFullSoC, "ns6:Multiplier")
        self.TimeToFullSoCUnit = ET.SubElement(self.RemainingTimeToFullSoC, "ns6:Unit")
        self.TimeToFullSoCValue = ET.SubElement(self.RemainingTimeToFullSoC, "ns6:Value")
        self.RemainingTimeToBulkSoC = ET.SubElement(self.CurrentDemandReq, "ns5:RemainingTimeToBulkSoC")
        self.TimeToBulkSoCMultiplier = ET.SubElement(self.RemainingTimeToBulkSoC, "ns6:Multiplier")
        self.TimeToBulkSoCUnit = ET.SubElement(self.RemainingTimeToBulkSoC, "ns6:Unit")
        self.TimeToBulkSoCValue = ET.SubElement(self.RemainingTimeToBulkSoC, "ns6:Value")
        self.EVTargetVoltage = ET.SubElement(self.CurrentDemandReq, "ns5:EVTargetVoltage")
        self.TargetVoltageMultiplier = ET.SubElement(self.EVTargetVoltage, "ns6:Multiplier")
        self.TargetVoltageUnit = ET.SubElement(self.EVTargetVoltage, "ns6:Unit")
        self.TargetVoltageValue = ET.SubElement(self.EVTargetVoltage, "ns6:Value")

        # Default Values
        self.EVReady.text = "true"
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
        self.CurrentDemandRes = ET.SubElement(self.Body, "ns5:CurrentDemandRes")
        self.ResponseCode = ET.SubElement(self.CurrentDemandRes, "ns5:ResponseCode")
        self.DC_EVSEStatus = ET.SubElement(self.CurrentDemandRes, "ns5:DC_EVSEStatus")
        self.EVSEIsolationStatus = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSEIsolationStatus")
        self.EVSEStatusCode = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSEStatusCode")
        self.NotificationMaxDelay = ET.SubElement(self.DC_EVSEStatus, "ns6:NotificationMaxDelay")
        self.EVSENotification = ET.SubElement(self.DC_EVSEStatus, "ns6:EVSENotification")
        self.EVSEPresentVoltage = ET.SubElement(self.CurrentDemandRes, "ns5:EVSEPresentVoltage")
        self.VoltageMultiplier = ET.SubElement(self.EVSEPresentVoltage, "ns6:Multiplier")
        self.VoltageUnit = ET.SubElement(self.EVSEPresentVoltage, "ns6:Unit")
        self.VoltageValue = ET.SubElement(self.EVSEPresentVoltage, "ns6:Value")
        self.EVSEPresentCurrent = ET.SubElement(self.CurrentDemandRes, "ns5:EVSEPresentCurrent")
        self.CurrentMultiplier = ET.SubElement(self.EVSEPresentCurrent, "ns6:Multiplier")
        self.CurrentUnit = ET.SubElement(self.EVSEPresentCurrent, "ns6:Unit")
        self.CurrentValue = ET.SubElement(self.EVSEPresentCurrent, "ns6:Value")
        self.EVSECurrentLimitAchieved = ET.SubElement(self.CurrentDemandRes, "ns5:EVSECurrentLimitAchieved")
        self.EVSEVoltageLimitAchieved = ET.SubElement(self.CurrentDemandRes, "ns5:EVSEVoltageLimitAchieved")
        self.EVSEPowerLimitAchieved = ET.SubElement(self.CurrentDemandRes, "ns5:EVSEPowerLimitAchieved")
        self.EVSEMaximumVoltageLimit = ET.SubElement(self.CurrentDemandRes, "ns5:EVSEMaximumVoltageLimit")
        self.VoltageLimitMultiplier = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns6:Multiplier")
        self.VoltageLimitUnit = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns6:Unit")
        self.VoltageLimitValue = ET.SubElement(self.EVSEMaximumVoltageLimit, "ns6:Value")
        self.EVSEMaximumCurrentLimit = ET.SubElement(self.CurrentDemandRes, "ns5:EVSEMaximumCurrentLimit")
        self.CurrentLimitMultiplier = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns6:Multiplier")
        self.CurrentLimitUnit = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns6:Unit")
        self.CurrentLimitValue = ET.SubElement(self.EVSEMaximumCurrentLimit, "ns6:Value")
        self.EVSEMaximumPowerLimit = ET.SubElement(self.CurrentDemandRes, "ns5:EVSEMaximumPowerLimit")
        self.PowerLimitMultiplier = ET.SubElement(self.EVSEMaximumPowerLimit, "ns6:Multiplier")
        self.PowerLimitUnit = ET.SubElement(self.EVSEMaximumPowerLimit, "ns6:Unit")
        self.PowerLimitValue = ET.SubElement(self.EVSEMaximumPowerLimit, "ns6:Value")

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

    def SessionStopRequest(self):
        self._V2GDINHeader()
        self.SessionStopReq = ET.SubElement(self.Body, "ns5:SessionStopReq")

    def SessionStopResponse(self):
        self._V2GDINHeader()
        self.SessionStopRes = ET.SubElement(self.Body, "ns5:SessionStopRes")
        self.ResponseCode = ET.SubElement(self.SessionStopRes, "ns5:ResponseCode")

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
            if name != "exi":
                delattr(self, name)


if __name__ == "__main__":
    x = XMLBuilder(EXIProcessor(protocol=Protocol.DIN))
    x.CurrentDemandRequest()
    x.show()
    print(x.getString() + "\n")
    # exi = x.getEXI()
    # print(binascii.unhexlify(exi))
