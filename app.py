import hashlib
import hmac
import base64
import datetime
import requests
import json
from uuid import uuid4

# Generate Digest
def generateDigest(jsonBody):  
    return base64.b64encode(hashlib.sha256(jsonBody.encode('utf-8')).digest()).decode("utf-8")

def generateSignature(clientId, requestId, requestTimestamp, requestTarget, digest, secret):
    # Prepare Signature Component
    print("----- Signature Component -----")
    componentSignature = "Client-Id:" + clientId
    componentSignature += "\n"
    componentSignature += "Request-Id:" + requestId
    componentSignature += "\n"
    componentSignature += "Request-Timestamp:" + requestTimestamp
    componentSignature += "\n"
    componentSignature += "Request-Target:" + requestTarget
    # If body not send when access API with HTTP method GET/DELETE
    if digest:
        componentSignature += "\n"
        componentSignature += "Digest:" + digest
     
    print(componentSignature)
    message = bytes(componentSignature, encoding='utf-8')
    secret = bytes(secret, encoding='utf-8')
 
    # Calculate HMAC-SHA256 base64 from all the components above
    signature = base64.b64encode(hmac.new(secret, message, digestmod=hashlib.sha256).digest()).decode("utf-8")

    # Prepend encoded result with algorithm info HMACSHA256=
    return "HMACSHA256="+signature 

# Sample of usage

# Generate Digest from JSON Body, For HTTP Method GET/DELETE don't need generate Digest
print("----- Digest -----")
jsonBody = '{\"order\":{\"amount\":20000,\"invoice_number\":\"INV-20210231-0002\"},\"payment\":{\"payment_due_date\":60}}'
digest = generateDigest(jsonBody)
print(digest)
print("JSON BODY:" + jsonBody)
print("")

#Variable Definition
# invoice = "INV-"+randomInvoice(10);
clientId = 'BRN-0252-1648456322620'
secret = 'SK-2zQLDKEZE8IzWWGT0BS8'
url = 'https://api-sandbox.doku.com'
requestTarget = '/checkout/v1/payment'
time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()
requestTimestamp  = time+'Z'
requestId = str(uuid4())

# Generate Header Signature
headerSignature = generateSignature(
        clientId,
        requestId,
        requestTimestamp,
        requestTarget, # For merchant request to Jokul, use Jokul path here. For HTTP Notification, use merchant path here
        digest, # Set empty string for this argumentes if HTTP Method is GET/DELETE
        secret)
print("----- Header Signature -----")
print(headerSignature)

#Generate API
print("----- API Response -----")
finalurl = url + requestTarget
header = { "Content-Type": "application/json", "Client-Id": clientId, "Request-Id": requestId, "Request-Timestamp": requestTimestamp, "Signature": headerSignature}

result = requests.post(finalurl, headers=header, data=jsonBody)
# result = requests.post(finalurl, headers=header, data=json.dumps(jsonBody))
response_json = result.json()
print (response_json)