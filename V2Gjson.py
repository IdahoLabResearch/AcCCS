# TODO: implement all every single optional field for each packet type

responseCodeMap = {
    "OK" : 0,
    "OK_NewSessionEstablished" : 1,
    "OK_OldSessionJoined" : 2,
    "OK_CertificateExpiresSoon" : 3,
    "FAILED" : 4,
    "FAILED_SequenceError" : 5,
    "FAILED_ServiceIDInvalid" : 6,
    "FAILED_UnknownSession" : 7,
    "FAILED_ServiceSelectionInvalid" : 8,
    "FAILED_PaymentSelectionInvalid" : 9,
    "FAILED_CertificateExpired" : 10,
    "FAILED_SignatureError" : 11,
    "FAILED_NoCertificateAvailable" : 12,
    "FAILED_CertChainError" : 13,
    "FAILED_ChallengeInvalid" : 14,
    "FAILED_ContractCanceled" : 15,
    "FAILED_WrongChargeParameter" : 16,
    "FAILED_PowerDeliveryNotApplied" : 17,
    "FAILED_TariffSelectionInvalid" : 18,
    "FAILED_ChargingProfileInvalid" : 19,
    "FAILED_EVSEPresentVoltageToLow" : 20,
    "FAILED_MeteringSignatureNotValid" : 21,
    "FAILED_WrongEnergyTransferType" : 22
    }

serviceCategoryMap = {
    "EVCharging" : 0,
    "Internet" : 1,
    "ContractCertificate" : 2,
    "OtherCustom" : 3
}

paymentOptionMap = {
    "Contract" : 0,
    "ExternalPayment" : 1
}

energyTransferTypeMap = {
    "AC_single_phase_core" : 0,
    "AC_three_phase_core " : 1,
    "DC_core" : 2,
    "DC_extended" : 3,
    "DC_combo_core" : 4,
    "DC_dual" : 5,
    "AC_core1p_DC_extended" : 6,
    "AC_single_DC_core" : 7,
    "AC_single_phase_three_phase_core_DC_extended" : 8,
    "AC_core3p_DC_extended" : 9
}

EVSEProcessingMap = {
    "Finished" : 0,
    "Ongoing" : 1
}

EVErrorCodeMap = {
    "NO_ERROR" : 0,
    "FAILED_RESSTemperatureInhibit" : 1,
    "FAILED_EVShiftPosition" : 2,
    "FAILED_ChargerConnectorLockFault" : 3,
    "FAILED_EVRESSMalfunction" : 4,
    "FAILED_ChargingCurrentdifferential" : 5,
    "FAILED_ChargingVoltageOutOfRange" : 6,
    "Reserved_A" : 7,
    "Reserved_B" : 8,
    "Reserved_C" : 9,
    "FAILED_ChargingSystemIncompatibility" : 10,
    "NoData" : 11
}

unitSymbolMap = {
    "h": 0,
    "m": 1,
    "s": 2,
    "A": 3,
    "Ah": 4,
    "V": 5,
    "VA": 6,
    "W": 7,
    "W_s": 8,
    "Wh": 9
}

IsolationLevelTypeMap = {
    "Invalid": 0,
    "Valid": 1,
    "Warning": 2,
    "Fault": 3
}

EVSEStatusCodeMap = {
    "EVSE_NotReady": 0,
    "EVSE_Ready": 1,
    "EVSE_Shutdown": 2,
    "EVSE_UtilityInterruptEvent": 3,
    "EVSE_IsolationMonitoringActive": 4,
    "EVSE_EmergencyShutdown": 5,
    "EVSE_Malfunction": 6,
    "Reserved_8": 7,
    "Reserved_9": 8,
    "Reserved_A": 9,
    "Reserved_B": 10,
    "Reserved_C": 11
}

EVSENotificationMap = {
    "None": 0,
    "StopCharging": 1,
    "ReNegotiation": 2
}

appHand_responseCodeMap = {
    "OK_SuccessfulNegotiation": 0,
    "OK_SuccessfulNegotiationWithMinorDeviation": 1,
    "Failed_NoNegotiation": 2
}


def SupportedAppProtocolRequest(
        protocolNamespace:str ="urn:din:70121:2012:MsgDef", 
        versionNumberMajor:int = 2, 
        versionNumberMinor:int = 0, 
        schemaID:int = 1, 
        priority:int = 1
        ):
    
    j = {
        "supportedAppProtocolReq": {
            "AppProtocol": {
                "array": [{
                    "ProtocolNamespace": {
                        "charactersLen": len(protocolNamespace),
                        "characters": [ord(x) for x in protocolNamespace]
                    },
                    "VersionNumberMajor": versionNumberMajor,
                    "VersionNumberMinor": versionNumberMinor,
                    "SchemaID": schemaID,
                    "Priority": priority
                }]
            }
        }
    }

    return j

def SupportedAppProtocolResponse(
        responseCode:str = "OK_SuccessfulNegotiation", 
        schemaID:int = 1
        ):

    j = {
        "supportedAppProtocolRes": {
            "ResponseCode": responseCode if type(responseCode) == int else appHand_responseCodeMap.get(responseCode, 0),
            "SchemaID": schemaID
        }
    }

    return j

def _V2GDINHeader(
        sessionID:bytearray = bytearray(b'DECAFBAD'), 
        ):

    sessionIDbytes = list(sessionID)

    j = {
        "Header": {
            "SessionID": {
                "bytes": sessionIDbytes,
                "bytesLen": len(sessionIDbytes)
            }
        }
    }

    return j

def SessionSetupRequest(
        sessionID:bytearray = bytearray(b'DECAFBAD'), 
        evccID:bytearray = bytearray(b'\x00\x00\xf0\x7f\x0c\x00k\x1c')
        ):

    evccIDbytes = list(evccID)

    j = {
        "Body": {
            "SessionSetupReq": {
                "EVCCID": {
                    "bytes": evccIDbytes,
                    "bytesLen": len(evccIDbytes)
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def SessionSetupResponse(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        responseCode = "OK",
        evseID:bytearray = bytearray(b"00")
        ):

    evseIDbytes = list(evseID)

    j = {
        "Body": {
            "SessionSetupRes": {
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0),
                "EVSEID": {
                    "bytes": evseIDbytes,
                    "bytesLen": len(evseIDbytes)
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ServiceDiscoveryRequest(
        sessionID:bytearray = bytearray(b'DECAFBAD'), 
        serviceCategory = "EVCharging",
    ):

    j = {
        "Body": {
            "ServiceDiscoveryReq": {
                "ServiceCategory": serviceCategory if type(serviceCategory) == int else serviceCategoryMap.get(serviceCategory, 0)
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ServiceDiscoveryResponse(
        sessionID:bytearray = bytearray(b'DECAFBAD'), 
        responseCode = "OK", 
        paymentOptions:list = ["ExternalPayment"], 
        serviceID:int = 1, 
        serviceCategory = "EVCharging",
        freeService:bool = False, 
        energyTransferType = "DC_extended"
        ):
    
    j = {
        "Body": {
            "ServiceDiscoveryRes": {
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0),
                "PaymentOptions": {
                    "PaymentOption": {
                        "array": [x if type(x) == int else paymentOptionMap.get(x, 0) for x in paymentOptions],
                        "arrayLen": len(paymentOptions)
                    }
                },
                "ChargeService": {
                    "ServiceTag": {
                        "ServiceID": serviceID,
                        # TODO: implement ServiceName
                        "ServiceCategory": serviceCategory if type(serviceCategory) == int else serviceCategoryMap.get(serviceCategory, 0),
                        # TODO: implement ServiceScope
                    },
                    "FreeService": freeService,
                    "EnergyTransferType": energyTransferType if type(energyTransferType) == int else energyTransferTypeMap.get(energyTransferType, 0)
                }
                # TODO: implement ServiceList
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ServicePaymentSelectionRequest(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        paymentOption = "ExternalPayment",
        serviceIDs:list = [1]
        ):
    
    j = {
        "Body": {
            "ServicePaymentSelectionReq": {
                "SelectedPaymentOption": paymentOption if type(paymentOption) == int else paymentOptionMap.get(paymentOption, 0),
                "SelectedServiceList": {
                    "SelectedService": {
                        "array": [{"ServiceID": x} for x in serviceIDs],
                        # TODO: implement ParameterSetID
                        "arrayLen": len(serviceIDs)
                    }
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ServicePaymentSelectionResponse(
        sessionID:bytearray = bytearray(b'DECAFBAD'), 
        responseCode = "OK"
        ):
    
    j = {
        "Body": {
            "ServicePaymentSelectionRes": {
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0)
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ContractAuthenticationRequest(
        sessionID:bytearray = bytearray(b'DECAFBAD'), 
        ):
    
    j = {
        "Body": {
            "ContractAuthenticationReq": {
                "isUsed": True
                # TODO: implement Id
                # TODO: implement GenChallenge
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ContractAuthenticationResponse(
        sessionID:bytearray = bytearray(b'DECAFBAD'), 
        responseCode = "OK",
        evseProcessing = "Finished"
        ):
    
    j = {
        "Body": {
            "ContractAuthenticationRes": {
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0),
                "EVSEProcessing": evseProcessing if type(evseProcessing) == int else EVSEProcessingMap.get(evseProcessing, 0)
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ChargeParameterDiscoveryRequest(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        evRequestedEnergyTransferType:str = "DC_extended",
        evReady:bool = True,
        evErrorCode = "NO_ERROR",
        evRessSoc:int = 10,
        evMaximumCurrentLimitMultiplier:int = -1,
        evMaximumCurrentLimitUnit:str = "A",
        evMaximumCurrentLimitValue:int = 5000,
        evMaximumPowerLimitMultiplier:int = 1,
        evMaximumPowerLimitUnit = "W",
        evMaximumPowerLimitValue:int = 21100,
        evMaximumVoltageLimitMultiplier:int = -1,
        evMaximumVoltageLimitUnit = "V",
        evMaximumVoltageLimitValue:int = 4220
        ):
    
    j = {
        "Body": {
            "ChargeParameterDiscoveryReq": {
                "EVRequestedEnergyTransferType": evRequestedEnergyTransferType if type(evRequestedEnergyTransferType) == int else energyTransferTypeMap.get(evRequestedEnergyTransferType, 0),
                # TODO: implement AC_EVChargeParameter
                # TODO: actually check if DC_EVChargeParameter is used
                "DC_EVChargeParameter": {
                    "DC_EVStatus": {
                        "EVReady": evReady,
                        # TODO: implement EVCabinConditioning
                        # TODO: implement EVRESSConditioning
                        "EVErrorCode": evErrorCode if type(evErrorCode) == int else EVErrorCodeMap.get(evErrorCode, 0),
                        "EVRESSSOC": evRessSoc
                    },
                    "EVMaximumCurrentLimit": {
                        "Multiplier": evMaximumCurrentLimitMultiplier,
                        # TODO: check if unit is used
                        "Unit": evMaximumCurrentLimitUnit if type(evMaximumCurrentLimitUnit) == int else unitSymbolMap.get(evMaximumCurrentLimitUnit, 3),
                        "Value": evMaximumCurrentLimitValue
                    },
                    # TODO: check if EVMaximumPowerLimit is used
                    "EVMaximumPowerLimit": {
                        "Multiplier": evMaximumPowerLimitMultiplier,
                        "Unit": evMaximumPowerLimitUnit if type(evMaximumPowerLimitUnit) == int else unitSymbolMap.get(evMaximumPowerLimitUnit, 7),
                        "Value": evMaximumPowerLimitValue
                    },
                    "EVMaximumVoltageLimit": {
                        "Multiplier": evMaximumVoltageLimitMultiplier,
                        "Unit": evMaximumVoltageLimitUnit if type(evMaximumVoltageLimitUnit) == int else unitSymbolMap.get(evMaximumVoltageLimitUnit, 5),
                        "Value": evMaximumVoltageLimitValue
                    }
                    # TODO: implement EVEnergyCapacity
                    # TODO: implement EVEnergyRequest
                    # TODO: implement FullSOC
                    # TODO: implement BulkSOC
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ChargeParameterDiscoveryResponse(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        responseCode = "OK",
        evseProcessing = "Finished",
        saScheduleTupleID:int = 1,
        pMaxScheduleID:int = 1,
        start:int = 0,
        pMax:int = 32767,
        evseIsolationStatus = "Invalid",
        evseStatusCode = "EVSE_IsolationMonitoringActive",
        notificationMaxDelay:int = 0,
        evseNotification = "None",
        maxCurrentLimitMultiplier:int = 0,
        maxCurrentLimitUnit:str = "A",
        maxCurrentLimitValue:int = 125,
        maxPowerLimitMultiplier:int = 1,
        maxPowerLimitUnit:str = "W",
        maxPowerLimitValue:int = 5000,
        maxVoltageLimitMultiplier:int = 0,
        maxVoltageLimitUnit:str = "V",
        maxVoltageLimitValue:int = 440,
        minCurrentLimitMultiplier:int = 0,
        minCurrentLimitUnit:str = "A",
        minCurrentLimitValue:int = 1,
        minVoltageLimitMultiplier:int = 0,
        minVoltageLimitUnit:str = "V",
        minVoltageLimitValue:int = 50,
        currentRippleMultiplier:int = 0,
        currentRippleUnit:str = "A",
        currentRippleValue:int = 3
        ):
    
    j = {
        "Body": {
            "ChargeParameterDiscoveryRes": {
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0),
                "EVSEProcessing": evseProcessing if type(evseProcessing) == int else EVSEProcessingMap.get(evseProcessing, 0),
                # TODO: check ifSAScheduleList is used
                "SAScheduleList": {
                    "SAScheduleTuple": {
                        "array": [{
                            "SAScheduleTupleID": saScheduleTupleID,
                            "PMaxSchedule": {
                                "PMaxScheduleID": pMaxScheduleID,
                                "PMaxScheduleEntry": {
                                    # TODO: implement variable length array
                                    "array": [{
                                        "RelativeTimeInterval": {
                                            "start": start,
                                            # TODO: implement Duration
                                        },
                                        "PMax": pMax
                                    }],
                                    "arrayLen": 1
                                }
                                # TODO: implement SalesTarrif
                            }
                        }],
                        "arrayLen": 1
                    }
                },
                # TODO: check if AC_EVSEChargeParameter is used
                # TODO: check if DC_EVSEChargeParameter is used
                "DC_EVSEChargeParameter": {
                    "DC_EVSEStatus": {
                        # TODO: check if EVSEIsolationStatus is used
                        "EVSEIsolationStatus": evseIsolationStatus if type(evseIsolationStatus) == int else IsolationLevelTypeMap.get(evseIsolationStatus, 0),
                        "EVSEStatusCode": evseStatusCode if type(evseStatusCode) == int else EVSEStatusCodeMap.get(evseStatusCode, 0),
                        "NotificationMaxDelay": notificationMaxDelay,
                        "EVSENotification": evseNotification if type(evseNotification) == int else EVSENotificationMap.get(evseNotification, 0)
                    },
                    "EVSEMaximumCurrentLimit": {
                        "Multiplier": maxCurrentLimitMultiplier,
                        "Unit": maxCurrentLimitUnit if type(maxCurrentLimitUnit) == int else unitSymbolMap.get(maxCurrentLimitUnit, 3),
                        "Value": maxCurrentLimitValue
                    },
                    "EVSEMaximumPowerLimit": {
                        "Multiplier": maxPowerLimitMultiplier,
                        "Unit": maxPowerLimitUnit if type(maxPowerLimitUnit) == int else unitSymbolMap.get(maxPowerLimitUnit, 7),
                        "Value": maxPowerLimitValue
                    },
                    "EVSEMaximumVoltageLimit": {
                        "Multiplier": maxVoltageLimitMultiplier,
                        "Unit": maxVoltageLimitUnit if type(maxVoltageLimitUnit) == int else unitSymbolMap.get(maxVoltageLimitUnit, 5),
                        "Value": maxVoltageLimitValue
                    },
                    "EVSEMinimumCurrentLimit": {
                        "Multiplier": minCurrentLimitMultiplier,
                        "Unit": minCurrentLimitUnit if type(minCurrentLimitUnit) == int else unitSymbolMap.get(minCurrentLimitUnit, 3),
                        "Value": minCurrentLimitValue
                    },
                    "EVSEMinimumVoltageLimit": {
                        "Multiplier": minVoltageLimitMultiplier,
                        "Unit": minVoltageLimitUnit if type(minVoltageLimitUnit) == int else unitSymbolMap.get(minVoltageLimitUnit, 5),
                        "Value": minVoltageLimitValue
                    },
                    # TODO: check if EVSECurrentRegulationTolerance is used
                    "EVSEPeakCurrentRipple": {
                        "Multiplier": currentRippleMultiplier,
                        "Unit": currentRippleUnit if type(currentRippleUnit) == int else unitSymbolMap.get(currentRippleUnit, 3),
                        "Value": currentRippleValue
                    }
                    # TODO: check if EVSEEnergyToBeDelivered is used
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def CableCheckRequest(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        evReady:bool = True,
        evErrorCode = "NO_ERROR",
        evRessSoc:int = 10
        ):
    
    j = {
        "Body": {
            "CableCheckReq": {
                "DC_EVStatus": {
                    "EVReady": evReady,
                    # TODO: implement EVCabinConditioning
                    # TODO: implement EVRESSConditioning
                    "EVErrorCode": evErrorCode if type(evErrorCode) == int else EVErrorCodeMap.get(evErrorCode, 0),
                    "EVRESSSOC": evRessSoc
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def CableCheckResponse(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        responseCode = "OK",
        evseIsolationStatus = "Valid",
        evseStatusCode = "EVSE_Ready",
        notificationMaxDelay:int = 0,
        evseNotification = "None",
        evseProcessing = "Finished"
        ):
    
    j = {
        "Body": {
            "CableCheckRes": {
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0),
                "DC_EVSEStatus": {
                    "EVSEIsolationStatus": evseIsolationStatus if type(evseIsolationStatus) == int else IsolationLevelTypeMap.get(evseIsolationStatus, 0),
                    "EVSEStatusCode": evseStatusCode if type(evseStatusCode) == int else EVSEStatusCodeMap.get(evseStatusCode, 0),
                    "NotificationMaxDelay": notificationMaxDelay,
                    "EVSENotification": evseNotification if type(evseNotification) == int else EVSENotificationMap.get(evseNotification, 0)
                },
                "EVSEProcessing": evseProcessing if type(evseProcessing) == int else EVSEProcessingMap.get(evseProcessing, 0)
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def PreChargeRequest(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        evReady:bool = True,
        evErrorCode = "NO_ERROR",
        evRessSoc:int = 10,
        targetVoltageMultiplier:int = -1,
        targetVoltageUnit:str = "V",
        targetVoltageValue:int = 4000,
        targetCurrentMultiplier:int = 0,
        targetCurrentUnit:str = "A",
        targetCurrentValue:int = 0
        ):
    
    j = {
        "Body": {
            "PreChargeReq": {
                "DC_EVStatus": {
                    "EVReady": evReady,
                    # TODO: implement EVCabinConditioning
                    # TODO: implement EVRESSConditioning
                    "EVErrorCode": evErrorCode if type(evErrorCode) == int else EVErrorCodeMap.get(evErrorCode, 0),
                    "EVRESSSOC": evRessSoc
                },
                "EVTargetVoltage": {
                    "Multiplier": targetVoltageMultiplier,
                    "Unit": targetVoltageUnit if type(targetVoltageUnit) == int else unitSymbolMap.get(targetVoltageUnit, 5),
                    "Value": targetVoltageValue
                },
                "EVTargetCurrent": {
                    "Multiplier": targetCurrentMultiplier,
                    "Unit": targetCurrentUnit if type(targetCurrentUnit) == int else unitSymbolMap.get(targetCurrentUnit, 3),
                    "Value": targetCurrentValue
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def PreChargeResponse(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        responseCode = "OK",
        evseIsolationStatus = "Valid",
        evseStatusCode = "EVSE_Ready",
        notificationMaxDelay:int = 0,
        evseNotification = "None",
        multiplier:int = 0,
        unit:str = "V",
        value:int = 370
        ):
    
    j = {
        "Body": {
            "PreChargeRes": {
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0),
                "DC_EVSEStatus": {
                    "EVSEIsolationStatus": evseIsolationStatus if type(evseIsolationStatus) == int else IsolationLevelTypeMap.get(evseIsolationStatus, 0),
                    "EVSEStatusCode": evseStatusCode if type(evseStatusCode) == int else EVSEStatusCodeMap.get(evseStatusCode, 0),
                    "NotificationMaxDelay": notificationMaxDelay,
                    "EVSENotification": evseNotification if type(evseNotification) == int else EVSENotificationMap.get(evseNotification, 0)
                },
                "EVSEPresentVoltage": {
                    "Multiplier": multiplier,
                    "Unit": unit if type(unit) == int else unitSymbolMap.get(unit, 5),
                    "Value": value
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def PowerDeliveryRequest(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        readyToChargeState:bool = True,
        evReady:bool = True,
        evCabinConditioning:bool = False,
        evRessConditioning:bool = True,
        evErrorCode = "NO_ERROR",
        evRessSoc:int = 10,
        chargingComplete:bool = False
        ):
    
    j = {
        "Body": {
            "PowerDeliveryReq": {
                "ReadyToChargeState": readyToChargeState,
                # TODO: implement ChargingProfile
                "DC_EVPowerDeliveryParameter": {
                    "DC_EVStatus": {
                        "EVReady": evReady,
                        "EVCabinConditioning": evCabinConditioning,
                        "EVRESSConditioning": evRessConditioning,
                        "EVErrorCode": evErrorCode if type(evErrorCode) == int else EVErrorCodeMap.get(evErrorCode, 0),
                        "EVRESSSOC": evRessSoc
                    },
                    "ChargingComplete": chargingComplete
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def PowerDeliveryResponse(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        responseCode = "OK",
        evseIsolationStatus = "Valid",
        evseStatusCode = "EVSE_Ready",
        notificationMaxDelay:int = 0,
        evseNotification = "None"
        ):
    
    j = {
        "Body": {
            "PowerDeliveryRes": {
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0),
                "DC_EVSEStatus": {
                    "EVSEIsolationStatus": evseIsolationStatus if type(evseIsolationStatus) == int else IsolationLevelTypeMap.get(evseIsolationStatus, 0),
                    "EVSEStatusCode": evseStatusCode if type(evseStatusCode) == int else EVSEStatusCodeMap.get(evseStatusCode, 0),
                    "NotificationMaxDelay": notificationMaxDelay,
                    "EVSENotification": evseNotification if type(evseNotification) == int else EVSENotificationMap.get(evseNotification, 0)
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def CurrentDemandRequest(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        evReady:bool = True,
        evCabinConditioning:bool = True,
        evRessConditioning:bool = True,
        evErrorCode = "NO_ERROR",
        evRessSoc:int = 10,
        targetCurrentMultiplier:int = 0,
        targetCurrentUnit:str = "A",
        targetCurrentValue:int = 0,
        evMaximumVoltageLimitMultiplier:int = -1,
        evMaximumVoltageLimitUnit:str = "V",
        evMaximumVoltageLimitValue:int = 4000,
        evMaximumCurrentLimitMultiplier:int = 0,
        evMaximumCurrentLimitUnit:str = "A",
        evMaximumCurrentLimitValue:int = 125,
        bulkChargingComplete:bool = False,
        chargingComplete:bool = False,
        remainingTimeToFullSoCMultiplier:int = 1,
        remainingTimeToFullSoCUnit:str = "s",
        remainingTimeToFullSoCValue:int = 0,
        remainingTimeToBulkSoCMultiplier:int = 1,
        remainingTimeToBulkSoCUnit:str = "s",
        remainingTimeToBulkSoCValue:int = 0,
        targetVoltageMultiplier:int = -1,
        targetVoltageUnit:str = "V",
        targetVoltageValue:int = 4000
        ):
    
    j = {
        "Body": {
            "CurrentDemandReq": {
                "DC_EVStatus": {
                    "EVReady": evReady,
                    "EVCabinConditioning": evCabinConditioning,
                    "EVRESSConditioning": evRessConditioning,
                    "EVErrorCode": evErrorCode if type(evErrorCode) == int else EVErrorCodeMap.get(evErrorCode, 0),
                    "EVRESSSOC": evRessSoc
                },
                "EVTargetCurrent": {
                    "Multiplier": targetCurrentMultiplier,
                    "Unit": targetCurrentUnit if type(targetCurrentUnit) == int else unitSymbolMap.get(targetCurrentUnit, 3),
                    "Value": targetCurrentValue
                },
                "EVMaximumVoltageLimit": {
                    "Multiplier": evMaximumVoltageLimitMultiplier,
                    "Unit": evMaximumVoltageLimitUnit if type(evMaximumVoltageLimitUnit) == int else unitSymbolMap.get(evMaximumVoltageLimitUnit, 5),
                    "Value": evMaximumVoltageLimitValue
                },
                "EVMaximumCurrentLimit": {
                    "Multiplier": evMaximumCurrentLimitMultiplier,
                    "Unit": evMaximumCurrentLimitUnit if type(evMaximumCurrentLimitUnit) == int else unitSymbolMap.get(evMaximumCurrentLimitUnit, 3),
                    "Value": evMaximumCurrentLimitValue
                },
                # TODO: check if BulkChargingComplete is used
                "BulkChargingComplete": bulkChargingComplete,
                "ChargingComplete": chargingComplete,
                # TODO: check if RemainingTimeToBulkSoC is used
                "RemainingTimeToFullSoC": {
                    "Multiplier": remainingTimeToFullSoCMultiplier,
                    "Unit": remainingTimeToFullSoCUnit if type(remainingTimeToFullSoCUnit) == int else unitSymbolMap.get(remainingTimeToFullSoCUnit, 2),
                    "Value": remainingTimeToFullSoCValue
                },
                # TODO: check if RemainingTimeToBulkSoC is used
                "RemainingTimeToBulkSoC": {
                    "Multiplier": remainingTimeToBulkSoCMultiplier,
                    "Unit": remainingTimeToBulkSoCUnit if type(remainingTimeToBulkSoCUnit) == int else unitSymbolMap.get(remainingTimeToBulkSoCUnit, 2),
                    "Value": remainingTimeToBulkSoCValue
                },
                "EVTargetVoltage": {
                    "Multiplier": targetVoltageMultiplier,
                    "Unit": targetVoltageUnit if type(targetVoltageUnit) == int else unitSymbolMap.get(targetVoltageUnit, 5),
                    "Value": targetVoltageValue
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def CurrentDemandResponse(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        responseCode = "OK",
        evseIsolationStatus = "Valid",
        evseStatusCode = "EVSE_Ready",
        notificationMaxDelay:int = 0,
        evseNotification = "None",
        voltageMultiplier:int = 0,
        voltageUnit:str = "V",
        voltageValue:int = 0,
        currentMultiplier:int = 0,
        currentUnit:str = "A",
        currentValue:int = 0,
        evseCurrentLimitAchieved:bool = False,
        evseVoltageLimitAchieved:bool = False,
        evsePowerLimitAchieved:bool = False,
        voltageLimitMultiplier:int = 0,
        voltageLimitUnit:str = "V",
        voltageLimitValue:int = 440,
        currentLimitMultiplier:int = 0,
        currentLimitUnit:str = "A",
        currentLimitValue:int = 125,
        powerLimitMultiplier:int = 1,
        powerLimitUnit:str = "W",
        powerLimitValue:int = 5000
        ):
    
    j = {
        "Body": {
            "CurrentDemandRes": {
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0),
                "DC_EVSEStatus": {
                    "EVSEIsolationStatus": evseIsolationStatus if type(evseIsolationStatus) == int else IsolationLevelTypeMap.get(evseIsolationStatus, 0),
                    "EVSEStatusCode": evseStatusCode if type(evseStatusCode) == int else EVSEStatusCodeMap.get(evseStatusCode, 0),
                    "NotificationMaxDelay": notificationMaxDelay,
                    "EVSENotification": evseNotification if type(evseNotification) == int else EVSENotificationMap.get(evseNotification, 0)
                },
                "EVSEPresentVoltage": {
                    "Multiplier": voltageMultiplier,
                    "Unit": voltageUnit if type(voltageUnit) == int else unitSymbolMap.get(voltageUnit, 5),
                    "Value": voltageValue
                },
                "EVSEPresentCurrent": {
                    "Multiplier": currentMultiplier,
                    "Unit": currentUnit if type(currentUnit) == int else unitSymbolMap.get(currentUnit, 3),
                    "Value": currentValue
                },
                "EVSECurrentLimitAchieved": evseCurrentLimitAchieved,
                "EVSEVoltageLimitAchieved": evseVoltageLimitAchieved,
                "EVSEPowerLimitAchieved": evsePowerLimitAchieved,
                "EVSEMaximumVoltageLimit": {
                    "Multiplier": voltageLimitMultiplier,
                    "Unit": voltageLimitUnit if type(voltageLimitUnit) == int else unitSymbolMap.get(voltageLimitUnit, 5),
                    "Value": voltageLimitValue
                },
                "EVSEMaximumCurrentLimit": {
                    "Multiplier": currentLimitMultiplier,
                    "Unit": currentLimitUnit if type(currentLimitUnit) == int else unitSymbolMap.get(currentLimitUnit, 3),
                    "Value": currentLimitValue
                },
                "EVSEMaximumPowerLimit": {
                    "Multiplier": powerLimitMultiplier,
                    "Unit": powerLimitUnit if type(powerLimitUnit) == int else unitSymbolMap.get(powerLimitUnit, 7),
                    "Value": powerLimitValue
                }
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def SessionStopRequest(
        sessionID:bytearray = bytearray(b'DECAFBAD')
        ):
    
    j = {
        "Body": {
            "SessionStopReq": {
                "_unused": 0
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def SessionStopResponse(
        sessionID:bytearray = bytearray(b'DECAFBAD'),
        responseCode = "OK"
        ):
    
    j = {
        "Body": {
            "SessionStopRes": {
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0)
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j