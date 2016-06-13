# -*- coding: utf-8 -*-
# Burp DetectDynamicJS Extension
# Copyright (c) 2015, 2016 Veit Hailperin (scip AG)

# This extension is supposed to help detecting dynamic js files, to look for state-dependency.

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
    from burp import IExtensionHelpers
    from burp import IHttpRequestResponse
    from burp import IScanIssue
    from array import array
    from time import sleep
    import difflib
except ImportError:
    print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

VERSION = '0.6'
VERSIONNAME = 'Marsellus Wallace'


class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener, IHttpRequestResponse):

    def	registerExtenderCallbacks(self, callbacks):

        print "Loading..."

        self._callbacks = callbacks
        self._callbacks.setExtensionName('Detect Dynamic JS')
        
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)
        self._helpers = callbacks.getHelpers()
        
        print "Loaded Detect Dynamic JS v"+VERSION+" ("+VERSIONNAME+")!"
        return


    def extensionUnloaded(self):
        print "Unloaded"
        return

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []
    
    def doPassiveScan(self, baseRequestResponse):
        # WARNING: NOT REALLY A PASSIVE SCAN!
        # doPassiveScan issues always at least one, if not two requests,
        # per request scanned
        # This is, because the insertionPoint idea doesn't work well
        # for this test. 
        scan_issues = []
        possibleFileEndings = ["js", "jsp", "json"]
        possibleContentTypes = ["javascript", "ecmascript", "jscript", "json"]
        self._requestResponse = baseRequestResponse
        self._helpers = self._callbacks.getHelpers()
        
        response = self._requestResponse.getResponse()
        responseInfo = self._helpers.analyzeResponse(response)
        
        # Check if the script is world readable
        resHeaders = responseInfo.getHeaders()
        if any(h for h in resHeaders if "access-control-allow-origin: *" in h.lower()):
            return None

        # Check for authorization
        reqHeaders = self._helpers.analyzeRequest(self._requestResponse).getHeaders()
        hfields = [h.split(':')[0] for h in reqHeaders]
        ifields = ['cookie','authorization']
        if not any(h for h in ifields if h not in str(hfields).lower()):
            return None

        url = self._helpers.analyzeRequest(self._requestResponse).getUrl()
        fileEnding = ".totallynotit"
        urlSplit = str(url).split("/")
        if len(urlSplit) != 0:
            fileName = urlSplit[len(urlSplit)-1]
            fileNameSplit = fileName.split(".")
            fileEnding = fileNameSplit[len(fileNameSplit)-1]
            fileEnding = fileEnding.split("?")[0]
            
        url = str(url).split("?")[0]
        mimeType = responseInfo.getStatedMimeType().split(';')[0]
        inferredMimeType = responseInfo.getInferredMimeType().split(';')[0]
        bodyOffset = responseInfo.getBodyOffset()
        headers = response.tostring()[:bodyOffset].split('\r\n')
        body = response.tostring()[bodyOffset:]
        first_char = body[0:1]
        ichars = ['{','<']
        
        contentLengthL = [x for x in headers if "content-length:" in x.lower()]
        if len(contentLengthL) >= 1:
            contentLength = int(contentLengthL[0].split(':')[1].strip())
        else:
            contentLength = 0
        
        if contentLength > 0:
            contentType = ""
            contentTypeL = [x for x in headers if "content-type:" in x.lower()]
            if len(contentTypeL) == 1:
                contentType = contentTypeL[0].lower()
            # this might need extension
            if (any(fileEnd in fileEnding for fileEnd in possibleFileEndings) or any(content in contentType for content in possibleContentTypes) or "script" in inferredMimeType or "script" in mimeType) and first_char not in ichars:
                request = self._requestResponse.getRequest()
                requestInfo = self._helpers.analyzeRequest(request)
                requestBodyOffset = requestInfo.getBodyOffset()
                requestHeaders = request.tostring()[:requestBodyOffset].split('\r\n')
                requestBody = request.tostring()[requestBodyOffset:]
                modified_headers = "\n".join(header for header in requestHeaders if "Cookie" not in header)
                newResponse = self._callbacks.makeHttpRequest(self._requestResponse.getHttpService(), self._helpers.stringToBytes(modified_headers+requestBody))
                issue = self.compareResponses(newResponse, self._requestResponse)
                if issue:
                    # If response is script, check if script is dynamic
                    if self.isScript(newResponse):
                        # sleep, in case this is a generically time stamped script
                        sleep(1)
                        secondResponse = self._callbacks.makeHttpRequest(self._requestResponse.getHttpService(), self._helpers.stringToBytes(modified_headers+requestBody))
                        isDynamic = self.compareResponses(secondResponse, newResponse)
                        if isDynamic:
                            issue = self.reportDynamicOnly(newResponse, self._requestResponse, secondResponse)
                    scan_issues.append(issue)
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None
    
 
    def isScript(self, requestResponse):
        """Determine if the response is a script"""
        possibleContentTypes = ["javascript", "ecmascript", "jscript", "json"]
        self._helpers = self._callbacks.getHelpers()
        
        url = self._helpers.analyzeRequest(requestResponse).getUrl()
        url = str(url).split("?")[0]
        
        response = requestResponse.getResponse()
        responseInfo = self._helpers.analyzeResponse(response)
        mimeType = responseInfo.getStatedMimeType().split(';')[0]
        inferredMimeType = responseInfo.getInferredMimeType().split(';')[0]
        bodyOffset = responseInfo.getBodyOffset()
        headers = response.tostring()[:bodyOffset].split('\r\n')
        
        contentLengthL = [x for x in headers if "content-length:" in x.lower()]
        if len(contentLengthL) >= 1:
            contentLength = int(contentLengthL[0].split(':')[1].strip())
        else:
            contentLength = 0
        
        if contentLength > 0:
            contentType = ""
            contentTypeL = [x for x in headers if "content-type:" in x.lower()]
            if len(contentTypeL) == 1:
                contentType = contentTypeL[0].lower()
            if (any(content in contentType for content in possibleContentTypes) or "script" in inferredMimeType or "script" in mimeType):
                return True
        return False
        

    def compareResponses(self, newResponse, oldResponse):
        """Compare two responses in respect to their body contents"""
        nResponse = newResponse.getResponse()
        nResponseInfo = self._helpers.analyzeResponse(nResponse)
          
        nBodyOffset = nResponseInfo.getBodyOffset()
        nBody = nResponse.tostring()[nBodyOffset:]
        
        oResponse = oldResponse.getResponse()
        oResponseInfo = self._helpers.analyzeResponse(oResponse)
        oBodyOffset = oResponseInfo.getBodyOffset()
        oBody = oResponse.tostring()[oBodyOffset:]
        
        result = None
        if str(nBody) != str(oBody):
            issuename = "Dynamic JavaScript Code Detected"
            issuelevel = "Medium"
            issuedetail = "These two files contain differing contents. Check the contents of the files to ensure that they don't contain sensitive information."
            issuebackground = "Dynamically generated JavaScript might contain session or user relevant information. Contrary to regular content that is protected by Same-Origin Policy, scripts can be included by third parties. This can lead to leakage of user/session relevant information."
            issueremediation = "Applications should not store user/session relevant data in JavaScript files with known URLs. If strict separation of data and code is not possible, CSRF tokens should be used."
            issueconfidence = "Firm"
            oOffsets = self.calculateHighlights(nBody, oBody, oBodyOffset)
            nOffsets = self.calculateHighlights(oBody, nBody, nBodyOffset)
            result = ScanIssue(self._requestResponse.getHttpService(),
                               self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                               issuename, issuelevel, issuedetail, issuebackground, issueremediation, issueconfidence,
                               [self._callbacks.applyMarkers(oldResponse, None, oOffsets), self._callbacks.applyMarkers(newResponse, None, nOffsets)])
        else:
            url = self._helpers.analyzeRequest(newResponse).getUrl()
            url = str(url)
            
        return result

    def reportDynamicOnly(self, firstResponse, originalResponse, secondResponse):
        """Report Situation as Dynamic Only"""
        issuename = "Dynamic JavaScript Code Detected"
        issuelevel = "Information"
        issueconfidence = "Certain"
        issuedetail = "These files contain differing contents. Check the contents of the files to ensure that they don't contain sensitive information."
        issuebackground = "Dynamically generated JavaScript might contain session or user relevant information. Contrary to regular content that is protected by Same-Origin Policy, scripts can be included by third parties. This can lead to leakage of user/session relevant information."
        issueremediation = "Applications should not store user/session relevant data in JavaScript files with known URLs. If strict separation of data and code is not possible, CSRF tokens should be used."

        nResponse = firstResponse.getResponse()
        nResponseInfo = self._helpers.analyzeResponse(nResponse)
        nBodyOffset = nResponseInfo.getBodyOffset()
        nBody = nResponse.tostring()[nBodyOffset:]
        
        oResponse = originalResponse.getResponse()
        oResponseInfo = self._helpers.analyzeResponse(oResponse)
        oBodyOffset = oResponseInfo.getBodyOffset()
        oBody = oResponse.tostring()[oBodyOffset:]

        sResponse = secondResponse.getResponse()
        sResponseInfo = self._helpers.analyzeResponse(sResponse)
        sBodyOffset = sResponseInfo.getBodyOffset()
        sBody = sResponse.tostring()[sBodyOffset:]
        
        oOffsets = self.calculateHighlights(nBody, oBody, oBodyOffset)
        nOffsets = self.calculateHighlights(oBody, nBody, nBodyOffset)
        sOffsets = self.calculateHighlights(oBody, sBody, sBodyOffset)
        result = ScanIssue(self._requestResponse.getHttpService(),
                           self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                           issuename, issuelevel, issuedetail, issuebackground, issueremediation, issueconfidence,
                           [self._callbacks.applyMarkers(originalResponse, None, oOffsets),
                            self._callbacks.applyMarkers(firstResponse, None, nOffsets),
                            self._callbacks.applyMarkers(secondResponse, None, sOffsets)])
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
        existingIssueResponses = []
        newIssueResponses = []
        sameMessages = 0
        for newResponse in newIssue.getHttpMessages():
            nResponse = newResponse.getResponse()
            nResponseInfo = self._helpers.analyzeResponse(nResponse)
            nBodyOffset = nResponseInfo.getBodyOffset()
            nBody = nResponse.tostring()[nBodyOffset:]
#            newIssueResponses.append(nBody)
            
        for oldResponse in existingIssue.getHttpMessages():
            oResponse = oldResponse.getResponse()
            oResponseInfo = self._helpers.analyzeResponse(oResponse)
            oBodyOffset = oResponseInfo.getBodyOffset()
            oBody = oResponse.tostring()[oBodyOffset:]
#            existingIssueResponses.append(oBody)

        for newIssueResp in newIssueResponses:
            for existingIssueResp in existingIssueResponses:
                if newIssueResp == existingIssueResp:
                    sameMessages += 1
                    break
        if sameMessages == 2:
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
