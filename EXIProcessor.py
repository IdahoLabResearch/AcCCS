import sys

sys.path.append("../EXPy/")

from DINProcessor import *
from V2Gjson import *

jsonString = SessionSetupRequest()
print(jsonString)

# Create instance of DINProcessor
dinProcessor = DINProcessor()

# Encode the json string
encodedEXIResult = dinProcessor.encode(jsonString)
print("Encoded EXI for SessionSetupRes:", encodedEXIResult.hex())