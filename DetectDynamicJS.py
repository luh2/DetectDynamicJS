# -*- coding: utf-8 -*-
# Burp DetectDynamicJS Extension
# Copyright (c) 2015, 2016 Veit Hailperin (scip AG), 2017, 2018 Veit Hailperin

# This extension is supposed to help detecting dynamic js files, to look
# for state-dependency.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

try:
    from burp import IBurpExtender
    from burp import IScannerCheck
    from burp import IExtensionStateListener
    from burp import IHttpRequestResponse
    from burp import IScanIssue
    from array import array
    from time import sleep
    import difflib
except ImportError:
    print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

VERSION = '0.10'
VERSIONNAME = 'Lance'


class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener, IHttpRequestResponse):

    def registerExtenderCallbacks(self, callbacks):

        print "Loading..."

        self._callbacks = callbacks
        self._callbacks.setExtensionName('Detect Dynamic JS')
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)
        self._helpers = callbacks.getHelpers()
        # Define some constants
        self.validStatusCodes = [200]
        self.ifields = ['cookie', 'authorization']
        self.possibleFileEndings = ["js", "json"]
        self.possibleContentTypes = [
            "javascript", "ecmascript", "jscript", "json"]
        self.ichars = ['{', '<']
        print "Loaded Detect Dynamic JS v%s (%s)!" % (VERSION, VERSIONNAME)
        return

    def extensionUnloaded(self):
        print "Unloaded"
        return

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def doPassiveScan(self, baseRequestResponse):
        # WARNING: NOT REALLY A PASSIVE SCAN!
        # doPassiveScan issues 1 request if simply dynamic JS
        # 2 requests if generically dynamic
        # 3 requests if it was a POST that works as GET
        # per request scanned
        # This is, because the insertionPoint idea doesn't work well
        # for this test.
        scan_issues = []

        if (not self.isScannableRequest(baseRequestResponse) or
            not self.isScript(baseRequestResponse) or
            not self.containsAuthenticationCharacteristics(baseRequestResponse) or
            self.isProtected(baseRequestResponse)):
            return None

        if not self.isGet(baseRequestResponse.getRequest()):
            baseRequestResponse = self.switchMethod(baseRequestResponse)

        newRequestResponse = self.sendUnauthenticatedRequest(baseRequestResponse)
        issue = self.compareResponses(newRequestResponse, baseRequestResponse)
        if not issue:
            return None
        # If response is script, check if script is dynamic
        if self.isScript(newRequestResponse):
            # sleep, in case this is a generically time stamped script
            sleep(1)
            secondRequestResponse = self.sendUnauthenticatedRequest(baseRequestResponse)
            isDynamic = self.compareResponses(secondRequestResponse, newRequestResponse)
            if isDynamic:
                issue = self.reportDynamicOnly(newRequestResponse, baseRequestResponse,
                                               secondRequestResponse)
        scan_issues.append(issue)
        return scan_issues

    def containsAuthenticationCharacteristics(self, requestResponse):
        """
        Check whether the request contains ambient authority information
        returns a boolean
        """
        reqHeaders = self._helpers.analyzeRequest(requestResponse).getHeaders()
        newHeaders = []
        for header in reqHeaders:
            headerName = header.split(':')[0].lower()
            if headerName in self.ifields:
                return True
        return False

    def sendUnauthenticatedRequest(self, requestResponse):
        """
        Send the request without ambient authority information
        requestResponse: The request to send again
        returns a requestResponse
        """
        newRequest = self.stripAuthenticationCharacteristics(requestResponse)
        return self._callbacks.makeHttpRequest(requestResponse.getHttpService(), newRequest)

    def isGet(self, request):
        """
        Check whether the request method is GET
        """
        requestInfo = self._helpers.analyzeRequest(request)
        return requestInfo.getMethod() == "GET"

    def switchMethod(self, requestResponse):
        """
        Turn POST into GET
        """
        newRequest = self._helpers.toggleRequestMethod(
            requestResponse.getRequest())
        newRequestResponse = self._callbacks.makeHttpRequest(
            requestResponse.getHttpService(), newRequest)
        return newRequestResponse

    def isProtected(self, requestResponse):
        """
        Checks for common protection mechanisms
        """
        response = requestResponse.getResponse()
        responseInfo = self._helpers.analyzeResponse(response)
        body = response.tostring()[responseInfo.getBodyOffset():]
        return any([self.isThrowProtected(body), self.isCloseParenthesisProtected(body),
                    self.isInfiniteLoopProtected(body)])

    def isThrowProtected(self, responseBody):
        """
        Checks for common DWR XSSI protection method
        """
        return responseBody.startswith("throw 'allowScriptTagRemoting is false.';")

    def isCloseParenthesisProtected(self, responseBody):
        """
        Checks for common Google Defense
        """
        return responseBody.startswith(")]}'")

    def isInfiniteLoopProtected(self, responseBody):
        """
        Checks wether the response is protected by a while(1); statement
        """
        return responseBody.startswith("while(1);")

    def isScannableRequest(self, requestResponse):
        """
        Checks whether the given request is actually of interest to this scanner
        module.
        requestResponse: The request to evaluate
        """
        response = requestResponse.getResponse()
        responseInfo = self._helpers.analyzeResponse(response)
        return self.hasValidStatusCode(responseInfo.getStatusCode())

    def hasValidStatusCode(self, statusCode):
        """
        Checks the status code of the request
        """
        return statusCode in self.validStatusCodes

    def stripAuthenticationCharacteristics(self, requestResponse):
        """
        Strip possible ambient authority information.
        """
        reqHeaders = self._helpers.analyzeRequest(requestResponse).getHeaders()
        newHeaders = []
        for header in reqHeaders:
            headerName = header.split(':')[0].lower()
            if headerName not in self.ifields:
                newHeaders.append(header)
        return self._helpers.buildHttpMessage(newHeaders, None)

    def hasBody(self, response):
        """
        Checks whether the response contains a body
        """
        responseInfo = self._helpers.analyzeResponse(response)
        body = response[responseInfo.getBodyOffset():]
        return len(body) > 0

    def hasScriptFileEnding(self, requestResponse):
        """
        Checks for common script file endings
        """
        url = self._helpers.analyzeRequest(requestResponse).getUrl()
        extractedFileEnding = ".totallynotit"
        urlSplit = str(url).split("/")
        if len(urlSplit) != 0:
            fileName = urlSplit[len(urlSplit) - 1]
            fileNameSplit = fileName.split(".")
            extractedFileEnding = fileNameSplit.pop() # pop() returns last item of list when called without index
            extractedFileEnding = extractedFileEnding.lower() # account for upper case letters
            extractedFileEnding = extractedFileEnding.split("?")[0]
        return extractedFileEnding in self.possibleFileEndings # will not detect, e.g., 'jspa' as script file ending


    def hasScriptContentType(self, response):
        """ Checks for common content types, that could be scripts """
        responseInfo = self._helpers.analyzeResponse(response)
        headers = responseInfo.getHeaders()
        contentType = ""
        contentTypeL = [x for x in headers if "content-type:" in x.lower()]
        if len(contentTypeL) == 1:
            contentType = contentTypeL[0].lower()
        return any(content in contentType for content in self.possibleContentTypes)

    def isScript(self, requestResponse):
        """Determine if the response is a script"""
        try:
            response = requestResponse.getResponse()
        except:
            return False
        if not self.hasBody(response):
            return False
        responseInfo = self._helpers.analyzeResponse(response)
        body = response.tostring()[responseInfo.getBodyOffset():]
        first_char = body[0:1]
        mimeType = responseInfo.getStatedMimeType().split(';')[0]
        inferredMimeType = responseInfo.getInferredMimeType().split(';')[0]
        return (first_char not in self.ichars and
                ("script" in mimeType or "script" in inferredMimeType or
                 self.hasScriptFileEnding(requestResponse) or self.hasScriptContentType(response)))

    def compareResponses(self, newRequestResponse, oldRequestResponse):
        """Compare two responses in respect to their body contents"""
        result = None
        nResponse = newRequestResponse.getResponse()
        if nResponse is None:
            return result
        nResponseInfo = self._helpers.analyzeResponse(nResponse)
        # Only considering non-cached HTTP responses
        if nResponseInfo.getStatusCode() == 304:
            return result
        nBodyOffset = nResponseInfo.getBodyOffset()
        nBody = nResponse.tostring()[nBodyOffset:]
        oResponse = oldRequestResponse.getResponse()
        oResponseInfo = self._helpers.analyzeResponse(oResponse)
        oBodyOffset = oResponseInfo.getBodyOffset()
        oBody = oResponse.tostring()[oBodyOffset:]
        if str(nBody) == str(oBody):
            return result
        issuename = "Dynamic JavaScript Code Detected"
        issuelevel = "Medium"
        issuedetail = "These two files contain differing contents. Check the contents of the files to ensure that they don't contain sensitive information."
        issuebackground = "Dynamically generated JavaScript might contain session or user relevant information. Contrary to regular content that is protected by Same-Origin Policy, scripts can be included by third parties. This can lead to leakage of user/session relevant information."
        issueremediation = "Applications should not store user/session relevant data in JavaScript files with known URLs. If strict separation of data and code is not possible, CSRF tokens should be used."
        issueconfidence = "Firm"
        oOffsets = self.calculateHighlights(nBody, oBody, oBodyOffset)
        nOffsets = self.calculateHighlights(oBody, nBody, nBodyOffset)
        result = ScanIssue(oldRequestResponse.getHttpService(),
                           self._helpers.analyzeRequest(oldRequestResponse).getUrl(),
                           issuename, issuelevel, issuedetail, issuebackground, issueremediation, issueconfidence,
                           [self._callbacks.applyMarkers(oldRequestResponse, None, oOffsets),
                            self._callbacks.applyMarkers(newRequestResponse, None, nOffsets)])
        return result

    def reportDynamicOnly(self, firstRequestResponse, originalRequestResponse, secondRequestResponse):
        """Report Situation as Dynamic Only"""
        issuename = "Dynamic JavaScript Code Detected"
        issuelevel = "Information"
        issueconfidence = "Certain"
        issuedetail = "These files contain differing contents. Check the contents of the files to ensure that they don't contain sensitive information."
        issuebackground = "Dynamically generated JavaScript might contain session or user relevant information. Contrary to regular content that is protected by Same-Origin Policy, scripts can be included by third parties. This can lead to leakage of user/session relevant information."
        issueremediation = "Applications should not store user/session relevant data in JavaScript files with known URLs. If strict separation of data and code is not possible, CSRF tokens should be used."

        nResponse = firstRequestResponse.getResponse()
        nResponseInfo = self._helpers.analyzeResponse(nResponse)
        nBodyOffset = nResponseInfo.getBodyOffset()
        nBody = nResponse.tostring()[nBodyOffset:]

        oResponse = originalRequestResponse.getResponse()
        oResponseInfo = self._helpers.analyzeResponse(oResponse)
        oBodyOffset = oResponseInfo.getBodyOffset()
        oBody = oResponse.tostring()[oBodyOffset:]

        sResponse = secondRequestResponse.getResponse()
        sResponseInfo = self._helpers.analyzeResponse(sResponse)
        sBodyOffset = sResponseInfo.getBodyOffset()
        sBody = sResponse.tostring()[sBodyOffset:]

        oOffsets = self.calculateHighlights(nBody, oBody, oBodyOffset)
        nOffsets = self.calculateHighlights(oBody, nBody, nBodyOffset)
        sOffsets = self.calculateHighlights(oBody, sBody, sBodyOffset)
        result = ScanIssue(originalRequestResponse.getHttpService(),
                           self._helpers.analyzeRequest(originalRequestResponse).getUrl(),
                           issuename, issuelevel, issuedetail, issuebackground, issueremediation, issueconfidence,
                           [self._callbacks.applyMarkers(originalRequestResponse, None, oOffsets),
                            self._callbacks.applyMarkers(firstRequestResponse, None, nOffsets),
                            self._callbacks.applyMarkers(secondRequestResponse, None, sOffsets)])
        return result

    def calculateHighlights(self, newBody, oldBody, bodyOffset):
        """find the exact points for highlighting the responses"""
        s = difflib.SequenceMatcher(None, oldBody, newBody)
        matching_blocks = s.get_matching_blocks()
        offsets = []
        poszero = 0
        posone = 0
        first = True
        # can create slightly weird marks because of being as
        # exact as one character. But I'd rather keep precision
        for m in matching_blocks:
            offset = array('i', [0, 0])
            if first:
                poszero = m.a + m.size
                first = False
            else:
                posone = m.a
                if posone != poszero:
                    offset[0] = poszero + bodyOffset
                    offset[1] = posone + bodyOffset
                    offsets.append(offset)
                poszero = m.a + m.size
        return offsets

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        newRequestResponse = newIssue.getHttpMessages()[0]
        newUrl = str(self._helpers.analyzeRequest(newRequestResponse).getUrl())
        existingRequestResponse = existingIssue.getHttpMessages()[0]
        existingUrl = str(self._helpers.analyzeRequest(
            existingRequestResponse).getUrl())

        if (existingIssue.getIssueName() == newIssue.getIssueName() and
            existingIssue.getIssueType() == newIssue.getIssueType() and
                existingUrl == newUrl):
            return -1
        else:
            return 0


class ScanIssue(IScanIssue):

    def __init__(self, httpservice, url, name, severity, detailmsg, background, remediation, confidence, requests):
        self._url = url
        self._httpservice = httpservice
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg
        self._issuebackground = background
        self._issueremediation = remediation
        self._confidence = confidence
        self._httpmsgs = requests

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._httpmsgs

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return self._issuebackground

    def getRemediationBackground(self):
        return self._issueremediation

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence
