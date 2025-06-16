import xml.etree.ElementTree as ET

def SupportedAppProtocolRequest(
        protocolNamespace:str ="urn:din:70121:2012:MsgDef", 
        versionNumberMajor:str = "2", 
        versionNumberMinor:str = "0", 
        schemaID:str = "1", 
        priority:str = "1"
        ):
    
    root = ET.Element("ns4:supportedAppProtocolReq")
    root = ET.Element("ns4:supportedAppProtocolReq")
    root.set("xmlns:ns4", "urn:iso:15118:2:2010:AppProtocol")
    root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    root.set("xmlns:ns3", "http://www.w3.org/2001/XMLSchema")
    AppProtocol = ET.SubElement(root, "AppProtocol")
    ProtocolNamespace = ET.SubElement(AppProtocol, "ProtocolNamespace")
    VersionNumberMajor = ET.SubElement(AppProtocol, "VersionNumberMajor")
    VersionNumberMinor = ET.SubElement(AppProtocol, "VersionNumberMinor")
    SchemaID = ET.SubElement(AppProtocol, "SchemaID")
    Priority = ET.SubElement(AppProtocol, "Priority")

    ProtocolNamespace.text = protocolNamespace
    VersionNumberMajor.text = versionNumberMajor
    VersionNumberMinor.text = versionNumberMinor
    SchemaID.text = schemaID
    Priority.text = priority

    return root

def SupportedAppProtocolResponse(
        responseCode:str = "OK_SuccessfulNegotiation", 
        schemaID:str = "1"
        ):
    
    root = ET.Element("ns4:supportedAppProtocolRes")
    root.set("xmlns:ns4", "urn:iso:15118:2:2010:AppProtocol")
    root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    root.set("xmlns:ns3", "http://www.w3.org/2001/XMLSchema")
    ResponseCode = ET.SubElement(root, "ResponseCode")
    SchemaID = ET.SubElement(root, "SchemaID")

    ResponseCode.text = responseCode
    SchemaID.text = schemaID

    return root

def _V2GDINHeader():
    root = ET.Element("ns7:V2G_Message")
    root.set("xmlns:ns7", "urn:din:70121:2012:MsgDef")
    root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    root.set("xmlns:ns3", "http://www.w3.org/2001/XMLSchema")
    root.set("xmlns:ns4", "http://www.w3.org/2000/09/xmldsig#")
    root.set("xmlns:ns5", "urn:din:70121:2012:MsgBody")
    root.set("xmlns:ns6", "urn:din:70121:2012:MsgDataTypes")
    root.set("xmlns:ns8", "urn:din:70121:2012:MsgHeader")
    Header = ET.SubElement(root, "ns7:Header")
    SessionID = ET.SubElement(Header, "ns8:SessionID")
    Body = ET.SubElement(root, "ns7:Body")

    return root

def SessionSetupRequest(
        sessionID:str = "00", 
        evccID:str = "0000F07F0C006B1C"
        ):
    
    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    SessionSetupReq = ET.SubElement(Body, "ns5:SessionSetupReq")
    EVCCID = ET.SubElement(SessionSetupReq, "ns5:EVCCID")
    EVCCID.text = evccID

    return root

def SessionSetupResponse(
        sessionID:str = "4142423030303031", 
        responseCode:str = "OK",
        evseID:str = "00"
        ):
    
    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    SessionSetupRes = ET.SubElement(Body, "ns5:SessionSetupRes")
    ResponseCode = ET.SubElement(SessionSetupRes, "ns5:ResponseCode")
    EVSEID = ET.SubElement(SessionSetupRes, "ns5:EVSEID")

    ResponseCode.text = responseCode
    EVSEID.text = evseID

    return root

def ServiceDiscoveryRequest(
        sessionID:str = "4142423030303031", 
        serviceCategory:str = "EVCharging"
        ):
    
    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")
    
    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    ServiceDiscoveryReq = ET.SubElement(Body, "ns5:ServiceDiscoveryReq")
    ServiceCategory = ET.SubElement(ServiceDiscoveryReq, "ns5:ServiceCategory")

    ServiceCategory.text = serviceCategory

    return root

def ServiceDiscoveryResponse(
        sessionID:str = "4142423030303031", 
        responseCode:str = "OK", 
        paymentOption:str = "ExternalPayment", 
        serviceID:str = "1", 
        serviceCategory:str = "EVCharging",
        freeService:str = "false", 
        energyTransferType:str = "DC_extended"
        ):
    
    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    ServiceDiscoveryRes = ET.SubElement(Body, "ns5:ServiceDiscoveryRes")
    ResponseCode = ET.SubElement(ServiceDiscoveryRes, "ns5:ResponseCode")
    PaymentOptions = ET.SubElement(ServiceDiscoveryRes, "ns5:PaymentOptions")
    PaymentOption = ET.SubElement(PaymentOptions, "ns6:PaymentOption")
    ChargeService = ET.SubElement(ServiceDiscoveryRes, "ns5:ChargeService")
    ServiceTag = ET.SubElement(ChargeService, "ns6:ServiceTag")
    ServiceID = ET.SubElement(ServiceTag, "ns6:ServiceID")
    ServiceCategory = ET.SubElement(ServiceTag, "ns6:ServiceCategory")
    FreeService = ET.SubElement(ChargeService, "ns6:FreeService")
    EnergyTransferType = ET.SubElement(ChargeService, "ns6:EnergyTransferType")

    ResponseCode.text = responseCode
    PaymentOption.text = paymentOption
    ServiceID.text = serviceID
    ServiceCategory.text = serviceCategory
    FreeService.text = freeService
    EnergyTransferType.text = energyTransferType

    return root

def ServicePaymentSelectionRequest(
        sessionID:str = "4142423030303031",
        paymentOption:str = "ExternalPayment",
        serviceID:str = "1"
        ):
    
    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    ServicePaymentSelectionReq = ET.SubElement(Body, "ns5:ServicePaymentSelectionReq")
    SelectedPaymentOption = ET.SubElement(ServicePaymentSelectionReq, "ns5:SelectedPaymentOption")
    SelectedServiceList = ET.SubElement(ServicePaymentSelectionReq, "ns5:SelectedServiceList")
    SelectedService = ET.SubElement(SelectedServiceList, "ns6:SelectedService")
    ServiceID = ET.SubElement(SelectedService, "ns6:ServiceID")

    SelectedPaymentOption.text = paymentOption
    ServiceID.text = serviceID

    return root

def ServicePaymentSelectionResponse(
        sessionID:str = "4142423030303031", 
        responseCode:str = "OK"
        ):
    
    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    ServicePaymentSelectionRes = ET.SubElement(Body, "ns5:ServicePaymentSelectionRes")
    ResponseCode = ET.SubElement(ServicePaymentSelectionRes, "ns5:ResponseCode")

    ResponseCode.text = responseCode

    return root

def ContractAuthenticationRequest(
        sessionID:str = "4142423030303031", 
        ):
    
    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    ContractAuthenticationReq = ET.SubElement(Body, "ns5:ContractAuthenticationReq")

    return root

def ContractAuthenticationResponse(
        sessionID:str = "4142423030303031", 
        responseCode:str = "OK",
        evseProcessing:str = "Finished"
        ):
    
    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    ContractAuthenticationRes = ET.SubElement(Body, "ns5:ContractAuthenticationRes")
    ResponseCode = ET.SubElement(ContractAuthenticationRes, "ns5:ResponseCode")
    EVSEProcessing = ET.SubElement(ContractAuthenticationRes, "ns5:EVSEProcessing")

    ResponseCode.text = responseCode
    EVSEProcessing.text = evseProcessing

    return root

def ChargeParameterDiscoveryRequest(
        sessionID:str = "4142423030303031",
        evRequestedEnergyTransferType:str = "DC_extended",
        evReady:str = "true",
        evErrorCode:str = "NO_ERROR",
        evRessSoc:str = "10",
        evMaximumCurrentLimitMultiplier:str = "-1",
        evMaximumCurrentLimitUnit:str = "A",
        evMaximumCurrentLimitValue:str = "5000",
        evMaximumPowerLimitMultiplier:str = "1",
        evMaximumPowerLimitUnit:str = "W",
        evMaximumPowerLimitValue:str = "21100",
        evMaximumVoltageLimitMultiplier:str = "-1",
        evMaximumVoltageLimitUnit:str = "V",
        evMaximumVoltageLimitValue:str = "4220"
        ):

    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    ChargeParameterDiscoverReq = ET.SubElement(Body, "ns5:ChargeParameterDiscoveryReq")
    EVRequestedEnergyTransferType = ET.SubElement(ChargeParameterDiscoverReq, "ns5:EVRequestedEnergyTransferType")
    DC_EVChargeParameter = ET.SubElement(ChargeParameterDiscoverReq, "ns6:DC_EVChargeParameter")
    DC_EVStatus = ET.SubElement(DC_EVChargeParameter, "ns6:DC_EVStatus")
    EVReady = ET.SubElement(DC_EVStatus, "ns6:EVReady")
    EVErrorCode = ET.SubElement(DC_EVStatus, "ns6:EVErrorCode")
    EVRESSSOC = ET.SubElement(DC_EVStatus, "ns6:EVRESSSOC")
    EVMaximumCurrentLimit = ET.SubElement(DC_EVChargeParameter, "ns6:EVMaximumCurrentLimit")
    CurrentLimitMultiplier = ET.SubElement(EVMaximumCurrentLimit, "ns6:Multiplier")
    CurrentLimitUnit = ET.SubElement(EVMaximumCurrentLimit, "ns6:Unit")
    CurrentLimitValue = ET.SubElement(EVMaximumCurrentLimit, "ns6:Value")
    EVMaximumPowerLimit = ET.SubElement(DC_EVChargeParameter, "ns6:EVMaximumPowerLimit")
    PowerLimitMultiplier = ET.SubElement(EVMaximumPowerLimit, "ns6:Multiplier")
    PowerLimitUnit = ET.SubElement(EVMaximumPowerLimit, "ns6:Unit")
    PowerLimitValue = ET.SubElement(EVMaximumPowerLimit, "ns6:Value")
    EVMaximumVoltageLimit = ET.SubElement(DC_EVChargeParameter, "ns6:EVMaximumVoltageLimit")
    VoltageLimitMultiplier = ET.SubElement(EVMaximumVoltageLimit, "ns6:Multiplier")
    VoltageLimitUnit = ET.SubElement(EVMaximumVoltageLimit, "ns6:Unit")
    VoltageLimitValue = ET.SubElement(EVMaximumVoltageLimit, "ns6:Value")

    EVRequestedEnergyTransferType.text = evRequestedEnergyTransferType
    EVReady.text = evReady
    EVErrorCode.text = evErrorCode
    EVRESSSOC.text = evRessSoc
    CurrentLimitMultiplier.text = evMaximumCurrentLimitMultiplier
    CurrentLimitUnit.text = evMaximumCurrentLimitUnit
    CurrentLimitValue.text = evMaximumCurrentLimitValue
    PowerLimitMultiplier.text = evMaximumPowerLimitMultiplier
    PowerLimitUnit.text = evMaximumPowerLimitUnit
    PowerLimitValue.text = evMaximumPowerLimitValue
    VoltageLimitMultiplier.text = evMaximumVoltageLimitMultiplier
    VoltageLimitUnit.text = evMaximumVoltageLimitUnit
    VoltageLimitValue.text = evMaximumVoltageLimitValue

    return root

def ChargeParameterDiscoveryResponse(
        sessionID:str = "4142423030303031",
        responseCode:str = "OK",
        evseProcessing:str = "Finished",
        saScheduleTupleID:str = "1",
        pMaxScheduleID:str = "1",
        start:str = "0",
        pMax:str = "32767",
        evseIsolationStatus:str = "Invalid",
        evseStatusCode:str = "EVSE_IsolationMonitoringActive",
        notificationMaxDelay:str = "0",
        evseNotification:str = "None",
        maxCurrentLimitMultiplier:str = "0",
        maxCurrentLimitUnit:str = "A",
        maxCurrentLimitValue:str = "125",
        maxPowerLimitMultiplier:str = "1",
        maxPowerLimitUnit:str = "W",
        maxPowerLimitValue:str = "5000",
        maxVoltageLimitMultiplier:str = "0",
        maxVoltageLimitUnit:str = "V",
        maxVoltageLimitValue:str = "440",
        minCurrentLimitMultiplier:str = "0",
        minCurrentLimitUnit:str = "A",
        minCurrentLimitValue:str = "1",
        minVoltageLimitMultiplier:str = "0",
        minVoltageLimitUnit:str = "V",
        minVoltageLimitValue:str = "50",
        currentRippleMultiplier:str = "0",
        currentRippleUnit:str = "A",
        currentRippleValue:str = "3"
        ):

    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    ChargeParameterDiscoveryRes = ET.SubElement(Body, "ns5:ChargeParameterDiscoveryRes")
    ResponseCode = ET.SubElement(ChargeParameterDiscoveryRes, "ns5:ResponseCode")
    EVSEProcessing = ET.SubElement(ChargeParameterDiscoveryRes, "ns5:EVSEProcessing")
    SAScheduleList = ET.SubElement(ChargeParameterDiscoveryRes, "ns6:SAScheduleList")
    SAScheduleTuple = ET.SubElement(SAScheduleList, "ns6:SAScheduleTuple")
    SAScheduleTupleID = ET.SubElement(SAScheduleTuple, "ns6:SAScheduleTupleID")
    PMaxSchedule = ET.SubElement(SAScheduleTuple, "ns6:PMaxSchedule")
    PMaxScheduleID = ET.SubElement(PMaxSchedule, "ns6:PMaxScheduleID")
    PMaxScheduleEntry = ET.SubElement(PMaxSchedule, "ns6:PMaxScheduleEntry")
    RelativeTimeInterval = ET.SubElement(PMaxScheduleEntry, "ns6:RelativeTimeInterval")
    Start = ET.SubElement(RelativeTimeInterval, "ns6:start")
    PMax = ET.SubElement(PMaxScheduleEntry, "ns6:PMax")
    DC_EVSEChargeParameter = ET.SubElement(ChargeParameterDiscoveryRes, "ns6:DC_EVSEChargeParameter")
    DC_EVSEStatus = ET.SubElement(DC_EVSEChargeParameter, "ns6:DC_EVSEStatus")
    EVSEIsolationStatus = ET.SubElement(DC_EVSEStatus, "ns6:EVSEIsolationStatus")
    EVSEStatusCode = ET.SubElement(DC_EVSEStatus, "ns6:EVSEStatusCode")
    NotificationMaxDelay = ET.SubElement(DC_EVSEStatus, "ns6:NotificationMaxDelay")
    EVSENotification = ET.SubElement(DC_EVSEStatus, "ns6:EVSENotification")
    EVSEMaximumCurrentLimit = ET.SubElement(DC_EVSEChargeParameter, "ns6:EVSEMaximumCurrentLimit")
    MaxCurrentLimitMultiplier = ET.SubElement(EVSEMaximumCurrentLimit, "ns6:Multiplier")
    MaxCurrentLimitUnit = ET.SubElement(EVSEMaximumCurrentLimit, "ns6:Unit")
    MaxCurrentLimitValue = ET.SubElement(EVSEMaximumCurrentLimit, "ns6:Value")
    EVSEMaximumPowerLimit = ET.SubElement(DC_EVSEChargeParameter, "ns6:EVSEMaximumPowerLimit")
    MaxPowerLimitMultiplier = ET.SubElement(EVSEMaximumPowerLimit, "ns6:Multiplier")
    MaxPowerLimitUnit = ET.SubElement(EVSEMaximumPowerLimit, "ns6:Unit")
    MaxPowerLimitValue = ET.SubElement(EVSEMaximumPowerLimit, "ns6:Value")
    EVSEMaximumVoltageLimit = ET.SubElement(DC_EVSEChargeParameter, "ns6:EVSEMaximumVoltageLimit")
    MaxVoltageLimitMultiplier = ET.SubElement(EVSEMaximumVoltageLimit, "ns6:Multiplier")
    MaxVoltageLimitUnit = ET.SubElement(EVSEMaximumVoltageLimit, "ns6:Unit")
    MaxVoltageLimitValue = ET.SubElement(EVSEMaximumVoltageLimit, "ns6:Value")
    EVSEMinimumCurrentLimit = ET.SubElement(DC_EVSEChargeParameter, "ns6:EVSEMinimumCurrentLimit")
    MinCurrentLimitMultiplier = ET.SubElement(EVSEMinimumCurrentLimit, "ns6:Multiplier")
    MinCurrentLimitUnit = ET.SubElement(EVSEMinimumCurrentLimit, "ns6:Unit")
    MinCurrentLimitValue = ET.SubElement(EVSEMinimumCurrentLimit, "ns6:Value")
    EVSEMinimumVoltageLimit = ET.SubElement(DC_EVSEChargeParameter, "ns6:EVSEMinimumVoltageLimit")
    MinVoltageLimitMultiplier = ET.SubElement(EVSEMinimumVoltageLimit, "ns6:Multiplier")
    MinVoltageLimitUnit = ET.SubElement(EVSEMinimumVoltageLimit, "ns6:Unit")
    MinVoltageLimitValue = ET.SubElement(EVSEMinimumVoltageLimit, "ns6:Value")
    EVSEPeakCurrentRipple = ET.SubElement(DC_EVSEChargeParameter, "ns6:EVSEPeakCurrentRipple")
    CurrentRippleMultiplier = ET.SubElement(EVSEPeakCurrentRipple, "ns6:Multiplier")
    CurrentRippleUnit = ET.SubElement(EVSEPeakCurrentRipple, "ns6:Unit")
    CurrentRippleValue = ET.SubElement(EVSEPeakCurrentRipple, "ns6:Value")

    ResponseCode.text = responseCode
    EVSEProcessing.text = evseProcessing
    SAScheduleTupleID.text = saScheduleTupleID
    PMaxScheduleID.text = pMaxScheduleID
    Start.text = start
    PMax.text = pMax
    EVSEIsolationStatus.text = evseIsolationStatus
    EVSEStatusCode.text = evseStatusCode
    NotificationMaxDelay.text = notificationMaxDelay
    EVSENotification.text = evseNotification
    MaxCurrentLimitMultiplier.text = maxCurrentLimitMultiplier
    MaxCurrentLimitUnit.text = maxCurrentLimitUnit
    MaxCurrentLimitValue.text = maxCurrentLimitValue
    MaxPowerLimitMultiplier.text = maxPowerLimitMultiplier
    MaxPowerLimitUnit.text = maxPowerLimitUnit
    MaxPowerLimitValue.text = maxPowerLimitValue
    MaxVoltageLimitMultiplier.text = maxVoltageLimitMultiplier
    MaxVoltageLimitUnit.text = maxVoltageLimitUnit
    MaxVoltageLimitValue.text = maxVoltageLimitValue
    MinCurrentLimitMultiplier.text = minCurrentLimitMultiplier
    MinCurrentLimitUnit.text = minCurrentLimitUnit
    MinCurrentLimitValue.text = minCurrentLimitValue
    MinVoltageLimitMultiplier.text = minVoltageLimitMultiplier
    MinVoltageLimitUnit.text = minVoltageLimitUnit
    MinVoltageLimitValue.text = minVoltageLimitValue
    CurrentRippleMultiplier.text = currentRippleMultiplier
    CurrentRippleUnit.text = currentRippleUnit
    CurrentRippleValue.text = currentRippleValue

    return root

def CableCheckRequest(
        sessionID:str = "4142423030303031",
        evReady:str = "true",
        evErrorCode:str = "NO_ERROR",
        evRessSoc:str = "10"
        ):

    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    CableCheckReq = ET.SubElement(Body, "ns5:CableCheckReq")
    DC_EVStatus = ET.SubElement(CableCheckReq, "ns5:DC_EVStatus")
    EVReady = ET.SubElement(DC_EVStatus, "ns6:EVReady")
    EVErrorCode = ET.SubElement(DC_EVStatus, "ns6:EVErrorCode")
    EVRESSSOC = ET.SubElement(DC_EVStatus, "ns6:EVRESSSOC")

    EVReady.text = evReady
    EVErrorCode.text = evErrorCode
    EVRESSSOC.text = evRessSoc

    return root

def CableCheckResponse(
        sessionID:str = "4142423030303031",
        responseCode:str = "OK",
        evseIsolationStatus:str = "Valid",
        evseStatusCode:str = "EVSE_Ready",
        notificationMaxDelay:str = "0",
        evseNotification:str = "None",
        evseProcessing:str = "Finished"
        ):

    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    CableCheckRes = ET.SubElement(Body, "ns5:CableCheckRes")
    ResponseCode = ET.SubElement(CableCheckRes, "ns5:ResponseCode")
    DC_EVSEStatus = ET.SubElement(CableCheckRes, "ns5:DC_EVSEStatus")
    EVSEIsolationStatus = ET.SubElement(DC_EVSEStatus, "ns6:EVSEIsolationStatus")
    EVSEStatusCode = ET.SubElement(DC_EVSEStatus, "ns6:EVSEStatusCode")
    NotificationMaxDelay = ET.SubElement(DC_EVSEStatus, "ns6:NotificationMaxDelay")
    EVSENotification = ET.SubElement(DC_EVSEStatus, "ns6:EVSENotification")
    EVSEProcessing = ET.SubElement(CableCheckRes, "ns5:EVSEProcessing")

    ResponseCode.text = responseCode
    EVSEIsolationStatus.text = evseIsolationStatus
    EVSEStatusCode.text = evseStatusCode
    NotificationMaxDelay.text = notificationMaxDelay
    EVSENotification.text = evseNotification
    EVSEProcessing.text = evseProcessing

    return root

def PreChargeRequest(
        sessionID:str = "4142423030303031",
        evReady:str = "true",
        evErrorCode:str = "NO_ERROR",
        evRessSoc:str = "10",
        targetVoltageMultiplier:str = "-1",
        targetVoltageUnit:str = "V",
        targetVoltageValue:str = "4000",
        targetCurrentMultiplier:str = "0",
        targetCurrentUnit:str = "A",
        targetCurrentValue:str = "0"
        ):

    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    PreChargeReq = ET.SubElement(Body, "ns5:PreChargeReq")
    DC_EVStatus = ET.SubElement(PreChargeReq, "ns5:DC_EVStatus")
    EVReady = ET.SubElement(DC_EVStatus, "ns6:EVReady")
    EVErrorCode = ET.SubElement(DC_EVStatus, "ns6:EVErrorCode")
    EVRESSSOC = ET.SubElement(DC_EVStatus, "ns6:EVRESSSOC")
    EVTargetVoltage = ET.SubElement(PreChargeReq, "ns5:EVTargetVoltage")
    TargetVoltageMultiplier = ET.SubElement(EVTargetVoltage, "ns6:Multiplier")
    TargetVoltageUnit = ET.SubElement(EVTargetVoltage, "ns6:Unit")
    TargetVoltageValue = ET.SubElement(EVTargetVoltage, "ns6:Value")
    EVTargetCurrent = ET.SubElement(PreChargeReq, "ns5:EVTargetCurrent")
    TargetCurrentMultiplier = ET.SubElement(EVTargetCurrent, "ns6:Multiplier")
    TargetCurrentUnit = ET.SubElement(EVTargetCurrent, "ns6:Unit")
    TargetCurrentValue = ET.SubElement(EVTargetCurrent, "ns6:Value")

    EVReady.text = evReady
    EVErrorCode.text = evErrorCode
    EVRESSSOC.text = evRessSoc
    TargetVoltageMultiplier.text = targetVoltageMultiplier
    TargetVoltageUnit.text = targetVoltageUnit
    TargetVoltageValue.text = targetVoltageValue
    TargetCurrentMultiplier.text = targetCurrentMultiplier
    TargetCurrentUnit.text = targetCurrentUnit
    TargetCurrentValue.text = targetCurrentValue

    return root

def PreChargeResponse(
        sessionID:str = "4142423030303031",
        responseCode:str = "OK",
        evseIsolationStatus:str = "Valid",
        evseStatusCode:str = "EVSE_Ready",
        notificationMaxDelay:str = "0",
        evseNotification:str = "None",
        multiplier:str = "0",
        unit:str = "V",
        value:str = "370"
        ):

    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    PreChargeRes = ET.SubElement(Body, "ns5:PreChargeRes")
    ResponseCode = ET.SubElement(PreChargeRes, "ns5:ResponseCode")
    DC_EVSEStatus = ET.SubElement(PreChargeRes, "ns5:DC_EVSEStatus")
    EVSEIsolationStatus = ET.SubElement(DC_EVSEStatus, "ns6:EVSEIsolationStatus")
    EVSEStatusCode = ET.SubElement(DC_EVSEStatus, "ns6:EVSEStatusCode")
    NotificationMaxDelay = ET.SubElement(DC_EVSEStatus, "ns6:NotificationMaxDelay")
    EVSENotification = ET.SubElement(DC_EVSEStatus, "ns6:EVSENotification")
    EVSEPresentVoltage = ET.SubElement(PreChargeRes, "ns5:EVSEPresentVoltage")
    Multiplier = ET.SubElement(EVSEPresentVoltage, "ns6:Multiplier")
    Unit = ET.SubElement(EVSEPresentVoltage, "ns6:Unit")
    Value = ET.SubElement(EVSEPresentVoltage, "ns6:Value")

    ResponseCode.text = responseCode
    EVSEIsolationStatus.text = evseIsolationStatus
    EVSEStatusCode.text = evseStatusCode
    NotificationMaxDelay.text = notificationMaxDelay
    EVSENotification.text = evseNotification
    Multiplier.text = multiplier
    Unit.text = unit
    Value.text = value

    return root

def PowerDeliveryRequest(
        sessionID:str = "4142423030303031",
        readyToChargeState:str = "true",
        evReady:str = "true",
        evCabinConditioning:str = "false",
        evRessConditioning:str = "true",
        evErrorCode:str = "NO_ERROR",
        evRessSoc:str = "10",
        chargingComplete:str = "false"
        ):

    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    PowerDeliveryReq = ET.SubElement(Body, "ns5:PowerDeliveryReq")
    ReadyToChargeState = ET.SubElement(PowerDeliveryReq, "ns5:ReadyToChargeState")
    DC_EVPowerDeliveryParameter = ET.SubElement(PowerDeliveryReq, "ns6:DC_EVPowerDeliveryParameter")
    DC_EVStatus = ET.SubElement(DC_EVPowerDeliveryParameter, "ns6:DC_EVStatus")
    EVReady = ET.SubElement(DC_EVStatus, "ns6:EVReady")
    EVCabinConditioning = ET.SubElement(DC_EVStatus, "ns6:EVCabinConditioning")
    EVRESSConditioning = ET.SubElement(DC_EVStatus, "ns6:EVRESSConditioning")
    EVErrorCode = ET.SubElement(DC_EVStatus, "ns6:EVErrorCode")
    EVRESSSOC = ET.SubElement(DC_EVStatus, "ns6:EVRESSSOC")
    ChargingComplete = ET.SubElement(DC_EVPowerDeliveryParameter, "ns6:ChargingComplete")

    ReadyToChargeState.text = readyToChargeState
    EVReady.text = evReady
    EVCabinConditioning.text = evCabinConditioning
    EVRESSConditioning.text = evRessConditioning
    EVErrorCode.text = evErrorCode
    EVRESSSOC.text = evRessSoc
    ChargingComplete.text = chargingComplete

    return root

def PowerDeliveryResponse(
        sessionID:str = "4142423030303031",
        responseCode:str = "OK",
        evseIsolationStatus:str = "Valid",
        evseStatusCode:str = "EVSE_Ready",
        notificationMaxDelay:str = "0",
        evseNotification:str = "None"
        ):

    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    PowerDeliveryRes = ET.SubElement(Body, "ns5:PowerDeliveryRes")
    ResponseCode = ET.SubElement(PowerDeliveryRes, "ns5:ResponseCode")
    DC_EVSEStatus = ET.SubElement(PowerDeliveryRes, "ns6:DC_EVSEStatus")
    EVSEIsolationStatus = ET.SubElement(DC_EVSEStatus, "ns6:EVSEIsolationStatus")
    EVSEStatusCode = ET.SubElement(DC_EVSEStatus, "ns6:EVSEStatusCode")
    NotificationMaxDelay = ET.SubElement(DC_EVSEStatus, "ns6:NotificationMaxDelay")
    EVSENotification = ET.SubElement(DC_EVSEStatus, "ns6:EVSENotification")

    ResponseCode.text = responseCode
    EVSEIsolationStatus.text = evseIsolationStatus
    EVSEStatusCode.text = evseStatusCode
    NotificationMaxDelay.text = notificationMaxDelay
    EVSENotification.text = evseNotification

    return root

def CurrentDemandRequest(
        sessionID:str = "4142423030303031",
        evReady:str = "true",
        evCabinConditioning:str = "true",
        evRessConditioning:str = "true",
        evErrorCode:str = "NO_ERROR",
        evRessSoc:str = "10",
        targetCurrentMultiplier:str = "0",
        targetCurrentUnit:str = "A",
        targetCurrentValue:str = "0",
        evMaximumVoltageLimitMultiplier:str = "-1",
        evMaximumVoltageLimitUnit:str = "V",
        evMaximumVoltageLimitValue:str = "4000",
        evMaximumCurrentLimitMultiplier:str = "0",
        evMaximumCurrentLimitUnit:str = "A",
        evMaximumCurrentLimitValue:str = "125",
        bulkChargingComplete:str = "false",
        chargingComplete:str = "false",
        remainingTimeToFullSoCMultiplier:str = "1",
        remainingTimeToFullSoCUnit:str = "s",
        remainingTimeToFullSoCValue:str = "0",
        remainingTimeToBulkSoCMultiplier:str = "1",
        remainingTimeToBulkSoCUnit:str = "s",
        remainingTimeToBulkSoCValue:str = "0",
        targetVoltageMultiplier:str = "-1",
        targetVoltageUnit:str = "V",
        targetVoltageValue:str = "4000"
        ):
    
    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    CurrentDemandReq = ET.SubElement(Body, "ns5:CurrentDemandReq")
    DC_EVStatus = ET.SubElement(CurrentDemandReq, "ns5:DC_EVStatus")
    EVReady = ET.SubElement(DC_EVStatus, "ns6:EVReady")
    EVCabinConditioning = ET.SubElement(DC_EVStatus, "ns6:EVCabinConditioning")
    EVRESSConditioning = ET.SubElement(DC_EVStatus, "ns6:EVRESSConditioning")
    EVErrorCode = ET.SubElement(DC_EVStatus, "ns6:EVErrorCode")
    EVRESSSOC = ET.SubElement(DC_EVStatus, "ns6:EVRESSSOC")
    EVTargetCurrent = ET.SubElement(CurrentDemandReq, "ns5:EVTargetCurrent")
    TargetCurrentMultiplier = ET.SubElement(EVTargetCurrent, "ns6:Multiplier")
    TargetCurrentUnit = ET.SubElement(EVTargetCurrent, "ns6:Unit")
    TargetCurrentValue = ET.SubElement(EVTargetCurrent, "ns6:Value")
    EVMaximumVoltageLimit = ET.SubElement(CurrentDemandReq, "ns5:EVMaximumVoltageLimit")
    VoltageLimitMultiplier = ET.SubElement(EVMaximumVoltageLimit, "ns6:Multiplier")
    VoltageLimitUnit = ET.SubElement(EVMaximumVoltageLimit, "ns6:Unit")
    VoltageLimitValue = ET.SubElement(EVMaximumVoltageLimit, "ns6:Value")
    EVMaximumCurrentLimit = ET.SubElement(CurrentDemandReq, "ns5:EVMaximumCurrentLimit")
    CurrentLimitMultiplier = ET.SubElement(EVMaximumCurrentLimit, "ns6:Multiplier")
    CurrentLimitUnit = ET.SubElement(EVMaximumCurrentLimit, "ns6:Unit")
    CurrentLimitValue = ET.SubElement(EVMaximumCurrentLimit, "ns6:Value")
    BulkChargingComplete = ET.SubElement(CurrentDemandReq, "ns5:BulkChargingComplete")
    ChargingComplete = ET.SubElement(CurrentDemandReq, "ns5:ChargingComplete")
    RemainingTimeToFullSoC = ET.SubElement(CurrentDemandReq, "ns5:RemainingTimeToFullSoC")
    TimeToFullSoCMultiplier = ET.SubElement(RemainingTimeToFullSoC, "ns6:Multiplier")
    TimeToFullSoCUnit = ET.SubElement(RemainingTimeToFullSoC, "ns6:Unit")
    TimeToFullSoCValue = ET.SubElement(RemainingTimeToFullSoC, "ns6:Value")
    RemainingTimeToBulkSoC = ET.SubElement(CurrentDemandReq, "ns5:RemainingTimeToBulkSoC")
    TimeToBulkSoCMultiplier = ET.SubElement(RemainingTimeToBulkSoC, "ns6:Multiplier")
    TimeToBulkSoCUnit = ET.SubElement(RemainingTimeToBulkSoC, "ns6:Unit")
    TimeToBulkSoCValue = ET.SubElement(RemainingTimeToBulkSoC, "ns6:Value")
    EVTargetVoltage = ET.SubElement(CurrentDemandReq, "ns5:EVTargetVoltage")
    TargetVoltageMultiplier = ET.SubElement(EVTargetVoltage, "ns6:Multiplier")
    TargetVoltageUnit = ET.SubElement(EVTargetVoltage, "ns6:Unit")
    TargetVoltageValue = ET.SubElement(EVTargetVoltage, "ns6:Value")

    EVReady.text = evReady
    EVCabinConditioning.text = evCabinConditioning
    EVRESSConditioning.text = evRessConditioning
    EVErrorCode.text = evErrorCode
    EVRESSSOC.text = evRessSoc
    TargetCurrentMultiplier.text = targetCurrentMultiplier
    TargetCurrentUnit.text = targetCurrentUnit
    TargetCurrentValue.text = targetCurrentValue
    VoltageLimitMultiplier.text = evMaximumVoltageLimitMultiplier
    VoltageLimitUnit.text = evMaximumVoltageLimitUnit
    VoltageLimitValue.text = evMaximumVoltageLimitValue
    CurrentLimitMultiplier.text = evMaximumCurrentLimitMultiplier
    CurrentLimitUnit.text = evMaximumCurrentLimitUnit
    CurrentLimitValue.text = evMaximumCurrentLimitValue
    BulkChargingComplete.text = bulkChargingComplete
    ChargingComplete.text = chargingComplete
    TimeToFullSoCMultiplier.text = remainingTimeToFullSoCMultiplier
    TimeToFullSoCUnit.text = remainingTimeToFullSoCUnit
    TimeToFullSoCValue.text = remainingTimeToFullSoCValue
    TimeToBulkSoCMultiplier.text = remainingTimeToBulkSoCMultiplier
    TimeToBulkSoCUnit.text = remainingTimeToBulkSoCUnit
    TimeToBulkSoCValue.text = remainingTimeToBulkSoCValue
    TargetVoltageMultiplier.text = targetVoltageMultiplier
    TargetVoltageUnit.text = targetVoltageUnit
    TargetVoltageValue.text = targetVoltageValue

    return root

def CurrentDemandResponse(
        sessionID:str = "4142423030303031",
        responseCode:str = "OK",
        evseIsolationStatus:str = "Valid",
        evseStatusCode:str = "EVSE_Ready",
        notificationMaxDelay:str = "0",
        evseNotification:str = "None",
        voltageMultiplier:str = "0",
        voltageUnit:str = "V",
        voltageValue:str = "0",
        currentMultiplier:str = "0",
        currentUnit:str = "A",
        currentValue:str = "0",
        evseCurrentLimitAchieved:str = "false",
        evseVoltageLimitAchieved:str = "false",
        evsePowerLimitAchieved:str = "false",
        voltageLimitMultiplier:str = "0",
        voltageLimitUnit:str = "V",
        voltageLimitValue:str = "440",
        currentLimitMultiplier:str = "0",
        currentLimitUnit:str = "A",
        currentLimitValue:str = "125",
        powerLimitMultiplier:str = "1",
        powerLimitUnit:str = "W",
        powerLimitValue:str = "5000"
        ):

    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    CurrentDemandRes = ET.SubElement(Body, "ns5:CurrentDemandRes")
    ResponseCode = ET.SubElement(CurrentDemandRes, "ns5:ResponseCode")
    DC_EVSEStatus = ET.SubElement(CurrentDemandRes, "ns5:DC_EVSEStatus")
    EVSEIsolationStatus = ET.SubElement(DC_EVSEStatus, "ns6:EVSEIsolationStatus")
    EVSEStatusCode = ET.SubElement(DC_EVSEStatus, "ns6:EVSEStatusCode")
    NotificationMaxDelay = ET.SubElement(DC_EVSEStatus, "ns6:NotificationMaxDelay")
    EVSENotification = ET.SubElement(DC_EVSEStatus, "ns6:EVSENotification")
    EVSEPresentVoltage = ET.SubElement(CurrentDemandRes, "ns5:EVSEPresentVoltage")
    VoltageMultiplier = ET.SubElement(EVSEPresentVoltage, "ns6:Multiplier")
    VoltageUnit = ET.SubElement(EVSEPresentVoltage, "ns6:Unit")
    VoltageValue = ET.SubElement(EVSEPresentVoltage, "ns6:Value")
    EVSEPresentCurrent = ET.SubElement(CurrentDemandRes, "ns5:EVSEPresentCurrent")
    CurrentMultiplier = ET.SubElement(EVSEPresentCurrent, "ns6:Multiplier")
    CurrentUnit = ET.SubElement(EVSEPresentCurrent, "ns6:Unit")
    CurrentValue = ET.SubElement(EVSEPresentCurrent, "ns6:Value")
    EVSECurrentLimitAchieved = ET.SubElement(CurrentDemandRes, "ns5:EVSECurrentLimitAchieved")
    EVSEVoltageLimitAchieved = ET.SubElement(CurrentDemandRes, "ns5:EVSEVoltageLimitAchieved")
    EVSEPowerLimitAchieved = ET.SubElement(CurrentDemandRes, "ns5:EVSEPowerLimitAchieved")
    EVSEMaximumVoltageLimit = ET.SubElement(CurrentDemandRes, "ns5:EVSEMaximumVoltageLimit")
    VoltageLimitMultiplier = ET.SubElement(EVSEMaximumVoltageLimit, "ns6:Multiplier")
    VoltageLimitUnit = ET.SubElement(EVSEMaximumVoltageLimit, "ns6:Unit")
    VoltageLimitValue = ET.SubElement(EVSEMaximumVoltageLimit, "ns6:Value")
    EVSEMaximumCurrentLimit = ET.SubElement(CurrentDemandRes, "ns5:EVSEMaximumCurrentLimit")
    CurrentLimitMultiplier = ET.SubElement(EVSEMaximumCurrentLimit, "ns6:Multiplier")
    CurrentLimitUnit = ET.SubElement(EVSEMaximumCurrentLimit, "ns6:Unit")
    CurrentLimitValue = ET.SubElement(EVSEMaximumCurrentLimit, "ns6:Value")
    EVSEMaximumPowerLimit = ET.SubElement(CurrentDemandRes, "ns5:EVSEMaximumPowerLimit")
    PowerLimitMultiplier = ET.SubElement(EVSEMaximumPowerLimit, "ns6:Multiplier")
    PowerLimitUnit = ET.SubElement(EVSEMaximumPowerLimit, "ns6:Unit")
    PowerLimitValue = ET.SubElement(EVSEMaximumPowerLimit, "ns6:Value")

    # Default Values
    ResponseCode.text = responseCode
    EVSEIsolationStatus.text = evseIsolationStatus
    EVSEStatusCode.text = evseStatusCode
    NotificationMaxDelay.text = notificationMaxDelay
    EVSENotification.text = evseNotification
    VoltageMultiplier.text = voltageMultiplier
    VoltageUnit.text = voltageUnit
    VoltageValue.text = voltageValue
    CurrentMultiplier.text = currentMultiplier
    CurrentUnit.text = currentUnit
    CurrentValue.text = currentValue
    EVSECurrentLimitAchieved.text = evseCurrentLimitAchieved
    EVSEVoltageLimitAchieved.text = evseVoltageLimitAchieved
    EVSEPowerLimitAchieved.text = evsePowerLimitAchieved
    VoltageLimitMultiplier.text = voltageLimitMultiplier
    VoltageLimitUnit.text = voltageLimitUnit
    VoltageLimitValue.text = voltageLimitValue
    CurrentLimitMultiplier.text = currentLimitMultiplier
    CurrentLimitUnit.text = currentLimitUnit
    CurrentLimitValue.text = currentLimitValue
    PowerLimitMultiplier.text = powerLimitMultiplier
    PowerLimitUnit.text = powerLimitUnit
    PowerLimitValue.text = powerLimitValue

    return root

def SessionStopRequest(
        sessionID:str = "4142423030303031"
        ):
    
    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    SessionStopReq = ET.SubElement(Body, "ns5:SessionStopReq")

    return root

def SessionStopResponse(
        sessionID:str = "4142423030303031",
        responseCode:str = "OK"
        ):

    root = _V2GDINHeader()
    Body = root.find("ns7:Body")
    Header = root.find("ns7:Header")

    SessionID = Header.find("ns8:SessionID")
    SessionID.text = sessionID

    SessionStopRes = ET.SubElement(Body, "ns5:SessionStopRes")
    ResponseCode = ET.SubElement(SessionStopRes, "ns5:ResponseCode")

    ResponseCode.text = responseCode

    return root

def printXML(xml:ET.Element):
    ET.indent(xml, space="\t", level=0)
    print(ET.tostring(xml, encoding="unicode"))

if __name__ == "__main__":
    print(ET.tostring(CurrentDemandRequest(), encoding="unicode"))
    print(type(CurrentDemandRequest()))