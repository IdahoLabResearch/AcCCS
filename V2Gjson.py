import json

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

def SessionSetupRequest(
        sessionID:str = "FFFF000000000000", 
        evccID:str = "0000F07F0C006B1C"
        ):

    sessionIDbytes = list(bytes.fromhex(sessionID))
    evccIDbytes = list(bytes.fromhex(evccID))

    s = """
    {
    "Header": {
        "SessionID": {
            "bytes": 0,
            "bytesLen": 0
        }
    },
    "Body": {
        "SessionSetupReq": {
            "isUsed": true,
            "EVCCID": {
                "bytes": 0,
                "bytesLen": 0
            }
        }
    }
}
"""

    j = json.loads(s)
    j["Header"]["SessionID"]["bytes"] = sessionIDbytes
    j["Header"]["SessionID"]["bytesLen"] = len(sessionIDbytes)
    j["Body"]["SessionSetupReq"]["EVCCID"]["bytes"] = evccIDbytes
    j["Body"]["SessionSetupReq"]["EVCCID"]["bytesLen"] = len(evccIDbytes)

    return j

def SessionSetupResponse(
        sessionID:str = "4142423030303031", 
        responseCode:str = "OK",
        evseID:str = "00"
        ):
    
    sessionIDbytes = list(bytes.fromhex(sessionID))
    evseIDbytes = list(bytes.fromhex(evseID))

    s = """
{
    "Header": {
        "SessionID": {
            "bytes": 0,
            "bytesLen": 0
        }
    },
    "Body": {
        "SessionSetupRes": {
            "isUsed": true,
            "ResponseCode": 0,
            "EVSEID": {
                "bytes": 0,
                "bytesLen": 0
            }
        }
    }
}
"""

    j = json.loads(s)
    j["Header"]["SessionID"]["bytes"] = sessionIDbytes
    j["Header"]["SessionID"]["bytesLen"] = len(sessionIDbytes)
    j["Body"]["SessionSetupRes"]["EVSEID"]["bytes"] = evseIDbytes
    j["Body"]["SessionSetupRes"]["EVSEID"]["bytesLen"] = len(evseIDbytes)
    j["Body"]["SessionSetupRes"]["ResponseCode"] = responseCodeMap.get(responseCode, 0)

    return j