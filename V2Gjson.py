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

unitSuymbolMap = {
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

def _V2GDINHeader(
        sessionID:str = "4142423030303031", 
        ):
    
    sessionIDbytes = list(bytes.fromhex(sessionID))
    
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
        sessionID:str = "4142423030303031", 
        evccID:str = "0000F07F0C006B1C"
        ):

    evccIDbytes = list(bytes.fromhex(evccID))

    j = {
        "Body": {
            "SessionSetupReq": {
                "isUsed": True,
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
        sessionID:str = "4142423030303031", 
        responseCode = "OK",
        evseID:str = "00"
        ):
    
    evseIDbytes = list(bytes.fromhex(evseID))

    j = {
        "Body": {
            "SessionSetupRes": {
                "isUsed": True,
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
        sessionID:str = "4142423030303031", 
        serviceCategory = "EVCharging",
    ):

    j = {
        "Body": {
            "ServiceDiscoveryReq": {
                "isUsed": True,
                "ServiceCategory": serviceCategory if type(serviceCategory) == int else serviceCategoryMap.get(serviceCategory, 0)
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ServiceDiscoveryResponse(
        sessionID:str = "4142423030303031", 
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
                "isUsed": True,
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
        sessionID:str = "4142423030303031",
        paymentOption = "ExternalPayment",
        serviceIDs:list = [1]
        ):
    
    j = {
        "Body": {
            "ServicePaymentSelectionReq": {
                "isUsed": True,
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
        sessionID:str = "4142423030303031", 
        responseCode = "OK"
        ):
    
    j = {
        "Body": {
            "ServicePaymentSelectionRes": {
                "isUsed": True,
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0)
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ContractAuthenticationRequest(
        sessionID:str = "4142423030303031", 
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
        sessionID:str = "4142423030303031", 
        responseCode = "OK",
        evseProcessing = "Finished"
        ):
    
    j = {
        "Body": {
            "ContractAuthenticationRes": {
                "isUsed": True,
                "ResponseCode": responseCode if type(responseCode) == int else responseCodeMap.get(responseCode, 0),
                "EVSEProcessing": evseProcessing if type(evseProcessing) == int else EVSEProcessingMap.get(evseProcessing, 0)
            }
        }
    }

    j.update(_V2GDINHeader(sessionID))

    return j

def ChargeParameterDiscoveryRequest(
        sessionID:str = "4142423030303031",
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
                "isUsed": True,
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
                        "Unit": evMaximumCurrentLimitUnit if type(evMaximumCurrentLimitUnit) == int else unitSuymbolMap.get(evMaximumCurrentLimitUnit, 3),
                        "Value": evMaximumCurrentLimitValue
                    },
                    # TODO: check if EVMaximumPowerLimit is used
                    "EVMaximumPowerLimit": {
                        "Multiplier": evMaximumPowerLimitMultiplier,
                        "Unit": evMaximumPowerLimitUnit if type(evMaximumPowerLimitUnit) == int else unitSuymbolMap.get(evMaximumPowerLimitUnit, 7),
                        "Value": evMaximumPowerLimitValue
                    },
                    "EVMaximumVoltageLimit": {
                        "Multiplier": evMaximumVoltageLimitMultiplier,
                        "Unit": evMaximumVoltageLimitUnit if type(evMaximumVoltageLimitUnit) == int else unitSuymbolMap.get(evMaximumVoltageLimitUnit, 5),
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