"""
DNI Generator by /6h4ack (@6h4ack)
"""

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadProcessor
from burp import IIntruderPayloadGenerator
from random import randint
letters = ("T","R","W","A","G","M","Y","F","P","D","X","B","N","J","Z","S","Q","V","H","L","C","K","E","T",)

payloads = []

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor):

    def registerExtenderCallbacks(self, callbacks):
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("DNI Generator")
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        callbacks.registerIntruderPayloadProcessor(self)


    def getGeneratorName(self):
        return "DNI Generator Payloads"

    def createNewInstance(self, attack):
        return IntruderPayloadGenerator()

    def getProcessorName(self):
        return "Serialized input wrapper"

    def processPayload(self, currentPayload, originalPayload, baseValue):
        dataParameter = self._helpers.bytesToString(
                self._helpers.base64Decode(self._helpers.urlDecode(baseValue)))
        
        start = dataParameter.index("input=") + 6
        if start == -1:
            return currentPayload

        prefix = dataParameter[0:start]
        end = dataParameter.index("&", start)
        if end == -1:
            end = len(dataParameter)

        suffix = dataParameter[end:len(dataParameter)]
        
        dataParameter = prefix + self._helpers.bytesToString(currentPayload) + suffix
        return self._helpers.stringToBytes(
                self._helpers.urlEncode(self._helpers.base64Encode(dataParameter)))
    

class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self._payloadIndex = 0

    def hasMorePayloads(self):
        number_dni = randint(10000000, 99999999)
        letter_dni = letters[number_dni % 23]
        dni = str(number_dni)+str(letter_dni)
        payloads.append(dni)
        return self._payloadIndex < len(payloads)

    def getNextPayload(self, baseValue):
        payload = payloads[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1

        return payload

    def reset(self):
        self._payloadIndex = 0