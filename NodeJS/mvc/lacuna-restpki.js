var request = require('request');
var fs = require('fs');
var Promise = require('bluebird');

var appRoot = process.cwd();

var RestPkiClient = function (endPointUrl, accessToken) {
    var self = this;

    var _endPointUrl = endPointUrl;
    var _accessToken = accessToken;

    self.get = function(url) {

        return new Promise(function(resolve, reject) {
            request.get(_endPointUrl + url, {
                json: true,
                headers: { 'Authorization': 'Bearer ' + _accessToken}
            }, function(err, restRes, body) {
                var errObj = { value: err };
                if (_checkResponse(errObj, restRes, 'GET', url)) {
                    resolve(body);
                } else {
                    reject(errObj.value);
                }
            });
        });
    };

    self.post = function(url, data) {

        return new Promise(function(resolve, reject) {
            request.post(_endPointUrl + url, {
                json: true,
                headers: { 'Authorization': 'Bearer ' + _accessToken},
                body: data
            }, function (err, restRes, body) {
                var errObj = { value: err };
                if (_checkResponse(errObj, restRes, 'POST', url)) {
                    resolve(body);
                } else {
                    reject(errObj.value);
                }
            });
        });
    };

    self.getAuthentication = function() {
        return new Authentication(this);
    };

    function _checkResponse(errObj, restRes, verb, url) {
        var statusCode = restRes.statusCode;

        if (errObj.value || statusCode < 200 || statusCode >= 300) {
            if (!errObj.value) {
                try {
                    var response = restRes.body;
                    if (statusCode == 422 && response.code && response.code.length > 0) {
                        if (restRes.code == 'ValidationError') {
                            var vr = new ValidationResults(response.validationResults);
                            errObj.value = new ValidationError(verb, url, vr);
                        } else {
                            errObj.value = new RestPKiError(verb, url, response.code, response.detail);
                        }
                    } else {
                        errObj.value = new RestError(verb, url, statusCode, response.message);
                    }
                } catch (error) {
                    errObj.value = new RestError(verb, url, statusCode);
                }

            }
            return false;
        } else {
            return true;
        }
    }

    return self;
};

var RestBaseError = function(errorName, message, verb, url) {
    var self = new Error(message);
    self.name = errorName;

    var _verb = verb;
    var _url = url;

    self.getVerb = function() { return _verb; };
    self.getUrl = function() { return _url; };

    return self;
};

var RestUnreachableError = function(verb, url) {
    var message = 'REST action ' + verb + ' ' + url + ' unreachable';
    var self = new RestBaseError('RestUnreachableError', message, verb, url);

    Error.captureStackTrace(this, RestUnreachableError);
    return self;
};

var RestError = function(verb, url, statusCode, errorMessage) {
    var message = 'REST action ' + verb + ' ' + url + ' returned HTTP error ' + statusCode;
    if (errorMessage && errorMessage.length > 0) {
        message += ': ' + errorMessage;
    }
    var self = new RestBaseError('RestError', message, verb, url);

    var _statusCode = statusCode;
    var _errorMessage = errorMessage;

    self.getStatusCode = function() { return _statusCode; };
    self.getErrorMessage = function() { return _errorMessage; };

    Error.captureStackTrace(this, RestError);
    return self;
};

var RestPKiError = function(verb, url, errorCode, detail) {
    var message = 'REST PKI action ' + verb + ' ' + url + ' error: ' + errorCode;
    if (detail && detail.length > 0) {
        message += ' (' + detail + ')';
    }
    var self = new RestBaseError('RestPkiError', message, verb, url);

    var _errorCode = errorCode;
    var _detail = detail;

    self.getErrorCode = function() { return _errorCode; };
    self.getDetail = function() { return _detail; };

    Error.captureStackTrace(this, RestPKiError);
    return self;
};

var ValidationError = function(verb, url, validationResults) {
    var message = validationResults.__toString();
    var self = new RestBaseError('ValidationError', message, verb, url);

    var _validationResults = validationResults;

    self.getValidationResults = function() { return _validationResults; };

    Error.captureStackTrace(this, ValidationError);
    return self;
};

var Authentication = function(restPkiClient) {
    var self = this;

    var _restPkiClient = restPkiClient;
    var _certificateInfo;
    var _done = false;

    self.startWithWebPkiAsync = function(securityContextId) {

        return new Promise(function(resolve, reject) {
            _restPkiClient.post('Api/Authentications', { 'securityContextId': securityContextId })
            .then(function(response) {
                resolve(response.token);
            }).catch(function(err) {
                reject(err);
            });
        });
    };

    self.completeWithWebPkiAsync = function(token) {

        return new Promise(function(resolve, reject) {
            _restPkiClient.post('Api/Authentications/' + token + '/Finalize', null)
            .then(function(response) {
                _certificateInfo = response.certificate;
                _done = true;

                resolve(new ValidationResults(response.validationResults));
            }).catch(function(err) {
                reject(err);
            });
        });
    };

    self.getCertificateInfo = function() {
        if (!_done) {
            throw new Error('The method getCertificateInfo() can only called after calling the completeWithWebPki method');
        }

        return _certificateInfo;
    };

    return self;
};

var SignatureStarter = function(restPkiClient) {
    var self = this;

    self._client = restPkiClient;
    self._signerCertificateBase64 = null;
    self._done = null;
    self._certificateInfo = null;
    self._signaturePolicy = null;
    self._securityContext = null;
    self._callbackArgument = null;

    function _getSignatureAlgorithm(oid) {
        switch(oid) {
            case '1.2.840.113549.2.5':
                return 'RSA-MD5';
            case '1.3.14.3.2.26':
                return 'RSA-SHA1';
            case '2.16.840.1.101.3.4.2.1':
                return 'RSA-SHA256';
            case '2.16.840.1.101.3.4.2.2':
                return 'RSA-SHA384';
            case '2.16.840.1.101.3.4.2.3':
                return 'RSA-SHA512';
            default:
                return null;
        }
    }

    self._getClientSideInstructionsObject = function(response) {
        return {
            token: response.token,
            toSignData: new Buffer(response.toSignData, 'base64'),
            toSignHash: new Buffer(response.toSignHash, 'base64'),
            digestAlgorithmOid: response.digestAlgorithmOid,
            signatureAlgorithm: _getSignatureAlgorithm(response.digestAlgorithmOid)
        };
    };

    self.setSignerCertificateRaw = function(certificate) {
        self._signerCertificateBase64 = new Buffer(certificate).toString('base64');
    };

    self.setSignerCertificateBase64 = function(certificate) {
        self._signerCertificateBase64 = certificate;
    };

    self.setSecurityContext = function(securityContextId) {
        self._securityContext = securityContextId;
    };

    self.setSignaturePolicy = function(signaturePolicyId) {
        self._signaturePolicy = signaturePolicyId;
    };

    self.setCallbackArgument = function(callbackArgument) {
        self._callbackArgument = callbackArgument;
    };

    self.getCertificateInfo = function() {

        if (!self._done) {
            throw new Error('The getCertificateInfo() method can only be called after calling one of the start methods');
        }
        return self._certificateInfo;
    };

    self.startWithWebPkiAsync = null;
    self.startAsync = null;

    return self;
};

var PadesSignatureStarter = function(restPkiClient) {
    var self = new SignatureStarter(restPkiClient);

    var _visualRepresentation = null;
    var _pdfToSign = null;

    //region setPdfToSign
    self.setPdfToSignFromPath = function(path) {
        _pdfToSign = fs.readFileSync(appRoot + path, 'base64');
    };

    self.setPdfToSignFromContentRaw = function(contentRaw) {
        _pdfToSign = new Buffer(contentRaw).toString('base64');
    };

    self.setPdfToSignFromContentBase64 = function(contentBase64) {
        _pdfToSign = contentBase64;
    };

    self.setPdfFileToSign = function(path) {
        self.setPdfToSignFromPath(path);
    };

    self.setPdfContentToSign = function(contentRaw) {
        self.setPdfToSignFromContentRaw(contentRaw);
    };
    //endregion

    self.setVisualRepresentation = function(visualRepresentation) {
        _visualRepresentation = visualRepresentation;
    };

    self.startWithWebPkiAsync = function() {

        return new Promise(function(resolve, reject) {
            _startCommonAsync().then(function(response) {

                if (response.certificate) {
                    self._certificateInfo = response.certificate;
                }
                self._done = true;

                resolve(response.token);
            }).catch(function(err) {
                reject(err);
            });
        });
    };

    self.startAsync = function() {

        if (_isNullOrEmpty(self._signerCertificateBase64)) {
            throw new Error('The signer certificate was not set');
        }

        return new Promise(function(resolve, reject) {
            _startCommonAsync().then(function(response) {

               if (response.certificate) {
                   self._certificateInfo = response.certificate;
               }
               self._done = true;

               resolve(self._getClientSideInstructionsObject(response));
           }).catch(function(err) {
               reject(err);
            });
        });
    };

    function _startCommonAsync() {

        if (_isNullOrEmpty(_pdfToSign)) {
            throw new Error('The PDF to sign was not set');
        }
        if (_isNullOrEmpty(self._signaturePolicy)) {
            throw new Error('The signature policy was not set');
        }

        var request = {
            'certificate': self._signerCertificateBase64,
            'signaturePolicyId': self._signaturePolicy,
            'securityContextId': self._securityContext,
            'callbackArgument': self.callbackArgument,
            'visualRepresentation': _visualRepresentation
        };

        request['pdfToSign'] = _pdfToSign;

        return self._client.post('Api/PadesSignatures', request);
    }

    return {
        setSignerCertificateRaw: self.setSignerCertificateRaw,
        setSignerCertificateBase64: self.setSignerCertificateBase64,
        setSecurityContext: self.setSecurityContext,
        setSignaturePolicy: self.setSignaturePolicy,
        setCallbackArgument: self.setCallbackArgument,
        getCertificateInfo: self.getCertificateInfo,
        setPdfToSignFromPath: self.setPdfToSignFromPath,
        setPdfToSignFromContentRaw: self.setPdfToSignFromContentRaw,
        setPdfToSignFromContentBase64: self.setPdfToSignFromContentBase64,
        setPdfFileToSign: self.setPdfFileToSign,
        setPdfContentToSign: self.setPdfContentToSign,
        setVisualRepresentation: self.setVisualRepresentation,
        startWithWebPkiAsync: self.startWithWebPkiAsync,
        startAsync: self.startAsync
    };
};

var CadesSignatureStarter = function(restPkiClient) {
    var self = new SignatureStarter(restPkiClient);

    var _fileToSign = null;
    var _cmsToCoSign = null;
    var _encapsulateContent = null;

    //region setFileToSign

    self.setFileToSignFromPath = function(path) {
        _fileToSign = fs.readFileSync(appRoot + path, 'base64');
    };

    self.setFileToSignFromContentRaw = function(contentRaw) {
        _fileToSign = new Buffer(contentRaw).toString('base64');
    };

    self.setFileToSignFromContentBase64 = function(contentBase64) {
        _fileToSign = contentBase64;
    };

    self.setFileToSign = function(path) {
        self.setFileToSignFromPath(path);
    };

    self.setContentToSign = function(contentRaw) {
        self.setFileToSignFromContentRaw(contentRaw);
    };

    //endregion

    //region setCmsToCoSign

    self.setCmsToCoSignFromPath = function(path) {
        _cmsToCoSign = fs.readFileSync(appRoot + path, 'base64');
    };

    self.setCmsToCoSignFromContentRaw = function(contentRaw) {
        _cmsToCoSign = new Buffer(contentRaw).toString('base64');
    };

    self.setCmsToCoSignFromcontentBase64 = function(contentBase64) {
        _cmsToCoSign = contentBase64;
    };

    self.setCmsFileToSign = function(path) {
        self.setCmsToCoSignFromPath(path);
    };

    self.setCmsToSign = function(contentRaw) {
        self.setCmsToCoSignFromContentRaw(contentRaw);
    };

    //endregion

    self.setEncapsulateContent = function(encapsulateContent) {
        _encapsulateContent = encapsulateContent;
    };

    self.startWithWebPkiAsync = function() {

        return new Promise(function(resolve, reject) {
           _startCommonAsync().then(function(response) {

               if (response.certificate) {
                   self._certificateInfo = response.certificate;
               }
               self._done = true;

               resolve(response.token);
           }).catch(function(err) {
               reject(err);
           });
        });
    };

    self.startAsync = function() {

        if (_isNullOrEmpty(self._signerCertificateBase64)) {
            throw new Error('The signer certificate was not set');
        }

        return new Promise(function(resolve, reject) {
            _startCommonAsync().then(function(response) {

                if (response.certificate) {
                    self._certificateInfo = response.certificate;
                }
                self._done = true;

                resolve(self._getClientSideInstructionsObject(response));
            }).catch(function(err) {
                reject(err);
            });
        });
    };

    function _startCommonAsync() {

        if (_isNullOrEmpty(_fileToSign) && _isNullOrEmpty(_cmsToCoSign)) {
            throw new Error('The content to sign was not set and no CMS to be co-signed was given');
        }
        if (_isNullOrEmpty(self._signaturePolicy)) {
            throw new Error('The signature policy was not set');
        }

        var request = {
            'certificate': self._signerCertificateBase64,
            'signaturePolicyId': self._signaturePolicy,
            'securityContextId': self._securityContext,
            'callbackArgument': self.callbackArgument,
            'encapsulateContent': _encapsulateContent
        };

        if (_fileToSign) {
            request['contentToSign'] = _fileToSign;
        }
        if (_cmsToCoSign) {
            request['cmsToCoSign'] = _cmsToCoSign;
        }

        return self._client.post('Api/CadesSignatures', request);
    }

    return {
        setSignerCertificateRaw: self.setSignerCertificateRaw,
        setSignerCertificateBase64: self.setSignerCertificateBase64,
        setSecurityContext: self.setSecurityContext,
        setSignaturePolicy: self.setSignaturePolicy,
        setCallbackArgument: self.setCallbackArgument,
        getCertificateInfo: self.getCertificateInfo,
        setFileToSignFromPath: self.setFileToSignFromPath,
        setFileToSignFromContentRaw: self.setFileToSignFromContentRaw,
        setFileToSignFromContentBase64: self.setFileToSignFromContentBase64,
        setFileToSign: self.setFileToSign,
        setContentToSign: self.setContentToSign,
        setCmsToCoSignFromPath: self.setCmsToCoSignFromPath,
        setCmsToCoSignFromContentRaw: self.setCmsToCoSignFromContentRaw,
        setCmsToCoSignFromcontentBase64: self.setCmsToCoSignFromcontentBase64,
        setCmsFileToSign: self.setCmsFileToSign,
        setCmsToSign: self.setCmsToSign,
        setEncapsulateContent: self.setEncapsulateContent,
        startWithWebPkiAsync: self.startWithWebPkiAsync,
        startAsync: self.startAsync
    }
};

var XmlSignatureStarter = function(restPkiClient) {
    var self = new SignatureStarter(restPkiClient);

    self._xmlToSign = null;
    self._signatureElementId = null;
    self._signatureElementLocationXPath = null;
    self._signatureElementLocationNsm = null;
    self._signatureElementLocationInsertionOption = null;

    //region setXmlToSign

    self.setXmlToSignFromPath = function(path) {
        self._xmlToSign = fs.readFileSync(appRoot + path, 'base64');
    };

    self.setXmlToSignFromContentRaw = function(contentRaw) {
        self._xmlToSign = new Buffer(contentRaw).toString('base64');
    };

    self.setXmlToSignFromContentBase64 = function(contentBase64) {
        self._xmlToSign = contentBase64;
    };

    self.setXmlFileToSign = function(path) {
        self.setXmlToSignFromPath(path);
    };

    self.setXmlContentToSign = function(contentRaw) {
        self.setXmlToSignFromContentRaw(contentRaw);
    };

    //endregion

    self.setSignatureElementLocation = function(xpath, insertionOption, namespaceManager) {
        self._signatureElementLocationXPath = xpath;
        self._signatureElementLocationInsertionOption = insertionOption;
        self._signatureElementLocationNsm = namespaceManager;
    };

    self.setSignatureElementId = function(signatureElementId) {
        self._signatureElementId = signatureElementId;
    };

    self._verifyCommonParameters = function(isWithWebPki) {
        isWithWebPki = isWithWebPki || false;

        if (!isWithWebPki) {
            if (_isNullOrEmpty(self._signerCertificateBase64)) {
                throw new Error('The signer certificate was not set');
            }
        }
        if (_isNullOrEmpty(self._signaturePolicy)) {
            throw new Error('The signature policy was not set');
        }
    };

    self._getRequest = function() {

        var request = {
            'certificate': self._signerCertificateBase64,
            'signaturePolicyId': self._signaturePolicy,
            'securityContextId': self._securityContext,
            'signatureElementId': self._signatureElementId
        };

        if (self._xmlToSign) {
            request['xml'] = self._xmlToSign;
        }
        if (self._signatureElementLocationXPath && self._signatureElementLocationInsertionOption) {

            request['signatureElementLocation'] = {
                'xPath': self._signatureElementLocationXPath,
                'insertionOption': self._signatureElementLocationInsertionOption
            };
            if (self._signatureElementLocationNsm) {

                request['signatureElementLocation']['namespaces'] = [];
                for (var key in self._signatureElementLocationNsm) {

                    if (self._signatureElementLocationNsm.hasOwnProperty(key)) {
                        request['signatureElementLocation']['namespaces'].push({
                            'prefix': key,
                            'uri': self._signatureElementLocationNsm[key]
                        });
                    }
                }
            }
        }

        return request;
    };

    return self;
};

var XmlElementSignatureStarter = function(restPkiClient) {
    var self = new XmlSignatureStarter(restPkiClient);

    var _toSignElementId;
    var _idResolutionTable;

    self.setToSignElementId = function(toSignElementId)  {
        _toSignElementId = toSignElementId;
    };

    self.setIdResolutionTable = function(idResolutionTable) {
        _idResolutionTable = idResolutionTable;
    };

    self.startWithWebPkiAsync = function() {

        self._verifyCommonParameters(true);

        return new Promise(function(resolve, reject) {
            _startCommonAsync().then(function(response) {

                if (response.certificate) {
                    self._certificateInfo = response.certificate;
                }
                self._done = true;

                resolve(response.token);
            }).catch(function(err) {
                reject(err);
            });
        });
    };

    self.startAsync = function() {

        self._verifyCommonParameters(false);

        return new Promise(function(resolve, reject) {
           _startCommonAsync().then(function(response) {

               if (response.certificate) {
                   self._certificateInfo = response.certificate;
               }
               self._done = true;

               resolve(self._getClientSideInstructionsObject(response));
           }).catch(function(err) {
               reject(err);
           });
        });
    };

    function _startCommonAsync() {

        if (_isNullOrEmpty(self._xmlToSign)) {
            throw new Error('The XML was not set');
        }
        if (_isNullOrEmpty(_toSignElementId)) {
            throw new Error('The XML element Id to sign was not net');
        }

        var request = self._getRequest();
        request['elementToSignId'] = _toSignElementId;
        if (_idResolutionTable != null) {
            request['idResolutionTable'] = _idResolutionTable.toModel();
        }

        return self._client.post('Api/XmlSignatures/XmlElementSignature', request);
    }

    return {
        setSignerCertificateRaw: self.setSignerCertificateRaw,
        setSignerCertificateBase64: self.setSignerCertificateBase64,
        setSecurityContext: self.setSecurityContext,
        setSignaturePolicy: self.setSignaturePolicy,
        setCallbackArgument: self.setCallbackArgument,
        getCertificateInfo: self.getCertificateInfo,
        setXmlToSignFromPath: self.setXmlToSignFromPath,
        setXmlToSignFromContentRaw: self.setXmlToSignFromContentRaw,
        setXmlToSignFromContentBase64: self.setXmlToSignFromContentBase64,
        setXmlFileToSign: self.setXmlFileToSign,
        setXmlContentToSign: self.setXmlContentToSign,
        setSignatureElementLocation: self.setSignatureElementLocation,
        setSignatureElementId: self.setSignatureElementId,
        setToSignElementId: self.setToSignElementId,
        setIdResolutionTable: self.setIdResolutionTable,
        startWithWebPkiAsync: self.startWithWebPkiAsync,
        startAsync: self.startAsync
    };
};

var FullXmlSignatureStarter = function(restPkiClient) {
    var self = new XmlSignatureStarter(restPkiClient);

    self.startWithWebPkiAsync = function() {

        self._verifyCommonParameters(true);

        return new Promise(function(resolve, reject) {
            _startCommonAsync().then(function(response) {

                if (response.certificate) {
                    self._certificateInfo = response.certificate;
                }
                self._done = true;

                resolve(response.token);
            }).catch(function(err) {
                reject(err);
            });
        });
    };

    self.startAsync = function() {

        self._verifyCommonParameters(false);

        return new Promise(function(resolve, reject) {
            _startCommonAsync().then(function(response) {

                if (response.certificate) {
                    self._certificateInfo = response.certificate;
                }
                self._done = true;

                resolve(self._getClientSideInstructionsObject(response));
            }).catch(function(err) {
                reject(err);
            });
        });
    };

    function _startCommonAsync() {

        if (_isNullOrEmpty(self._xmlToSign)) {
            throw new Error('The XML was not set');
        }

        var request = self._getRequest();

        return self._client.post('Api/XmlSignatures/FullXmlSignature', request);
    }

    return {
        setSignerCertificateRaw: self.setSignerCertificateRaw,
        setSignerCertificateBase64: self.setSignerCertificateBase64,
        setSecurityContext: self.setSecurityContext,
        setSignaturePolicy: self.setSignaturePolicy,
        setCallbackArgument: self.setCallbackArgument,
        getCertificateInfo: self.getCertificateInfo,
        setXmlToSignFromPath: self.setXmlToSignFromPath,
        setXmlToSignFromContentRaw: self.setXmlToSignFromContentRaw,
        setXmlToSignFromContentBase64: self.setXmlToSignFromContentBase64,
        setXmlFileToSign: self.setXmlFileToSign,
        setXmlContentToSign: self.setXmlContentToSign,
        setSignatureElementLocation: self.setSignatureElementLocation,
        setSignatureElementId: self.setSignatureElementId,
        startWithWebPkiAsync: self.startWithWebPkiAsync,
        startAsync: self.startAsync
    };
};

var SignatureFinisher = function(restPkiClient) {
    var self = this;

    self._client = restPkiClient;
    self._token = null;
    self._signatureBase64 = null;
    self._done = null;
    self._callbackArgument = null;
    self._certificateInfo = null;

    self.setToken = function(token) {
        self._token = token;
    };

    self.setSignatureRaw = function(signatureRaw) {
        self._signatureBase64 = new Buffer(signatureRaw).toString('base64');
    };

    self.setSignatureBase64 = function(signatureBase64) {
        self._signatureBase64 = signatureBase64;
    };

    self.finishAsync = null;

    self.getCallbackArgument = function() {

        if (!self._done) {
            throw new Error('The getCallbackArgument() method can only be called after calling the finish() method')
        }
        return self._callbackArgument;
    };

    self.getCertificateInfo = function() {

        if (!self._done) {
            throw new Error('The method getCertificateInfo() can only be called after calling the finish() method');
        }
        return self._certificateInfo;
    };

    return self;
};

var PadesSignatureFinisher = function(restPkiClient) {
    var self = new SignatureFinisher(restPkiClient);

    var _signedPdf;

    self.finishAsync = function() {

        var request = {};

        if (_isNullOrEmpty(self._token)) {
            throw new Error('The token was not set');
        }

        return new Promise(function(resolve, reject) {

            var promise;
            if (_isNullOrEmpty(self._signatureBase64)) {
                promise = self._client.post('Api/PadesSignatures/' + self._token + '/Finalize', null);
            } else {
                request['signature'] = self._signatureBase64;
                promise = self._client.post('Api/PadesSignatures/' + self._token + '/SignedBytes', request);
            }

            promise.then(function(response) {

                _signedPdf = new Buffer(response.signedPdf, 'base64'); // Base64-decoding
                self._callbackArgument = response.callbackArgument;
                self._certificateInfo = response.certificate;
                self._done = true;

                resolve(_signedPdf);
            }).catch(function(err) {
                reject(err);
            });
        });
    };

    self.getSignedPdf = function() {

        if (!self._done) {
            throw new Error('The getSignedPdf() method can only be called after calling the finish() method');
        }
        return _signedPdf;
    };

    self.writeSignedPdfToPath = function(pdfPath) {

        if (!_done) {
            throw new Error('The method writeSignedPdfToPath() can only be called after calling the finish() method');
        }
        fs.writeFileSync(pdfPath, _signedPdf);
    };

    return {
        setToken: self.setToken,
        setSignatureRaw: self.setSignatureRaw,
        setSignatureBase64: self.setSignatureBase64,
        getCallbackArgument: self.getCallbackArgument,
        getCertificateInfo: self.getCertificateInfo,
        finishAsync: self.finishAsync,
        getSignedPdf: self.getSignedPdf,
        writeSignedPdfToPath: self.writeSignedPdfToPath
    };
};

var CadesSignatureFinisher = function(restPkiClient) {
    var self = SignatureFinisher(restPkiClient);

    var _cms;

    self.finishAsync = function() {

        var request = {};

        if (_isNullOrEmpty(self._token)) {
            throw new Error('The token was not set');
        }

        return new Promise(function(resolve, reject) {

            var promise;
            if (_isNullOrEmpty(self._signatureBase64)) {
                promise = self._client.post('Api/CadesSignatures/' + _token + '/Finalize', null);
            } else {
                request['signature'] = self._signatureBase64;
                promise = self._client.post('Api/CadesSignatures/' + _token + '/SignedBytes', request);
            }

            promise.then(function(response) {

                _cms = new Buffer(response.cms, 'base64'); // Base64-decoding
                self._callbackArgument = response.callbackArgument;
                self._certificateInfo = response.certificate;
                self._done = true;

                resolve(_cms);
            }).catch(function(err) {
                reject(err);
            });
        });
    };

    self.getCms = function() {

        if (!self._done) {
            throw new Error('The getCms() method can only be called after calling the finish() method');
        }
        return _cms;
    };

    self.writeCmsToPath = function(path)  {

        if (!self._done) {
            throw new Error('The method writeCmsfToPath() can only be called after calling the finish() method');
        }
        fs.writeFileSync(path, _cms);
    };

    return {
        setToken: self.setToken,
        setSignatureRaw: self.setSignatureRaw,
        setSignatureBase64: self.setSignatureBase64,
        getCallbackArgument: self.getCallbackArgument,
        getCertificateInfo: self.getCertificateInfo,
        finishAsync: self.finishAsync,
        getCms: self.getCms,
        writeCmsToPath: self.writeCmsToPath
    }

};

var XmlSignatureFinisher = function(restPkiClient) {
    var self = new SignatureFinisher(restPkiClient);

    var _signedXml;

    self.finishAsync = function() {

        if (_isNullOrEmpty(self._token)) {
            throw new Error('The token was not set');
        }

        return new Promise(function(resolve, reject) {

            var promise;
            if (_isNullOrEmpty(self._signatureBase64)) {
                promise = self._client.post('Api/XmlSignatures/' + self._token + '/Finalize', null);
            } else {
                request['signature'] = self._signatureBase64;
                promise = self._client.post('Api/XmlSignatures/' + self._token + '/SignedBytes', request);
            }

            promise.then(function(response) {
                _signedXml = new Buffer(response.signedXml, 'base64'); // Base64-decoding
                self._callbackArgument = response.callbackArgument;
                self._certificateInfo = response.certificate;
                self._done = true;

                resolve(_signedXml);
            }).catch(function(err) {
                reject(err);
            });
        });
    };

    self.getSignedXml = function() {

        if(!self._done) {
            throw new Error('The getSignedXml() method can only be called after calling the finish() method');
        }
        return _signedXml;
    };

    self.writeSignedXmlToPath = function(xmlPath) {

        if (!_done) {
            throw new Error('The method writeSignedXmlToPath() can only be called after calling the finish() method');
        }
        fs.writeFileSync(xmlPath, _signedXml);
    };

    return {
        setToken: self.setToken,
        setSignatureRaw: self.setSignatureRaw,
        setSignatureBase64: self.setSignatureBase64,
        getCallbackArgument: self.getCallbackArgument,
        getCertificateInfo: self.getCertificateInfo,
        finishAsync: self.finishAsync,
        getSignedXml: self.getSignedXml,
        writeSignedXmlToPath: self.writeSignedXmlToPath
    };
};

var StandardSignaturePolicies = {
    padesBasic: '78d20b33-014d-440e-ad07-929f05d00cdf',
    padesBasicWithPkiBrazilCerts: '3fec800c-366c-49bf-82c5-2e72154e70f6',
    padesTWithPkiBrazilCerts: '6a39aeea-a2d0-4754-bf8c-19da15296ddb',
    pkiBrazilPadesAdrBasica: '531d5012-4c0d-4b6f-89e8-ebdcc605d7c2',
    pkiBrazilPadesAdrTempo: '10f0d9a5-a0a9-42e9-9523-e181ce05a25b',

    cadesBes: 'a4522485-c9e5-46c3-950b-0d6e951e17d1',
    cadesBesWithSigningTimeAndNoCrls: '8108539d-c137-4f45-a1f2-de5305bc0a37',
    pkiBrazilCadesAdrBasica:'3ddd8001-1672-4eb5-a4a2-6e32b17ddc46',
    pkiBrazilCadesAdrTempo: 'a5332ad1-d105-447c-a4bb-b5d02177e439',
    pkiBrazilCadesAdrCompleta: '30d881e7-924a-4a14-b5cc-d5a1717d92f6',

    xadesBes: '1beba282-d1b6-4458-8e46-bd8ad6800b54',
    xmlDSigBasic: '2bb5d8c9-49ba-4c62-8104-8141f6459d08',
    pkiBrazilXadesAdrBasica: '1cf5db62-58b6-40ba-88a3-d41bada9b621',
    pkiBrazilXadesAdrTempo: '5aa2e0af-5269-43b0-8d45-f4ef52921f04',
    pkiBrazilNFePadraoNacional: 'a3c24251-d43a-4ba4-b25d-ee8e2ab24f06'
};

var StandardSecurityContexts = {
    pkiBrazil: '201856ce-273c-4058-a872-8937bd547d36',
    pkiItaly: 'c438b17e-4862-446b-86ad-6f85734f0bfe',
    windowsServer: '3881384c-a54d-45c5-bbe9-976b674f5ec7'
};

var XmlInsertionOptions = {
    appendChild: 'AppendChild',
    prependChild: 'PrependChild',
    appendSibling: 'AppendSibling',
    prependSibling: 'PrependSibling'
};

var PadesVisualPositioningPresets = (function() {
    var self = this;

    var _cachedPresets = {};

    self.getFootnote = function(restPkiClient, pageNumber, rows) {

        var urlSegment = 'Footnote';
        if (!_isNullOrEmpty(pageNumber)) {
            urlSegment += "?pageNumber=" + pageNumber;
        }
        if (!_isNullOrEmpty(rows)) {
            urlSegment += "?rows=" + rows;
        }

        return _getPreset(restPkiClient, urlSegment);
    };

    self.getNewPage = function(restPkiClient) {
        return _getPreset(restPkiClient, 'NewPage');
    };

    function _getPreset(restPkiClient, urlSegment) {

        return new Promise(function(resolve) {
            if (_cachedPresets.hasOwnProperty(urlSegment)) {
                resolve(_cachedPresets[urlSegment]);
            }

            restPkiClient.get('Api/PadesVisualPositioningPresets/' + urlSegment)
            .then(function(preset) {
                _cachedPresets[urlSegment] = preset;
                resolve(preset);
            });
        });
    }

    return self;
})();

var XmlIdResolutionTable = function(includeXmlIdGlobalAttribute) {
    var self = this;

    var _model = {
        'elementIdAttributes': {},
        'globalIdAttributes': {},
        'includeXmlIdAttribute': includeXmlIdGlobalAttribute
    };

    self.addGlobalIdAttribute = function(idAttributeLocalName, idAttributeNamespace) {
        _model['globalIdAttributes'] = {
            localName: idAttributeLocalName,
            namespace: idAttributeNamespace
        };
    };

    self.setElementIdAttribute = function(elementLocalName, elementNamespace, idAttributeLocalName, idAttributeNamespace) {
        _model['elementIdAttributes'] = {
            element: {
                localName: elementLocalName,
                namespace: elementNamespace
            },
            attribute: {
                localName: idAttributeLocalName,
                namespace: idAttributeNamespace
            }
        };
    };

    self.toModel = function() {
        return _model;
    };

    return self;
};

var ValidationResults = function(model) {
    var self = this;

    var _errors = _convertItems(model.errors);
    var _warnings = _convertItems(model.warnings);
    var _passedChecks = _convertItems(model.passedChecks);

    self.isValid = function() {
        return _isNullOrEmpty(_errors);
    };

    self.getChecksPerformed = function() {
        return _errors.length + _warnings.length + _passedChecks.length;
    };

    self.hasErrors = function() {
        return !self.isValid();
    };

    self.hasWarnings = function() {
        return _warnings && _warnings.length > 0;
    };

    self.__toString = function() {
        return self.toString(0);
    };

    self.toString = function(indentationLevel) {
        var itemIndent = '\t'.repeat(indentationLevel);
        var text = '';

        text += self.getSummary(indentationLevel);
        if (self.hasErrors()) {
            text += '\n' + itemIndent + 'Errors:\n';
            text += _joinItems(_errors, indentationLevel);
        }
        if (self.hasWarnings()) {
            text += '\n' + itemIndent + 'Warnings:\n';
            text += _joinItems(_warnings, indentationLevel);
        }
        if (!_isNullOrEmpty(_passedChecks)) {
            text += '\n' + itemIndent + 'Passed Checks:\n';
            text += _joinItems(_passedChecks, indentationLevel);
        }

        return text;
    };

    self.getSummary = function(indentationLevel) {
        indentationLevel = indentationLevel || 0;

        var itemIndent = '\t'.repeat(indentationLevel);
        var text = itemIndent + 'Validation results: ';

        if (self.getChecksPerformed() === 0) {
            text += 'no checks performed';
        } else {
            text += self.getChecksPerformed() + ' checks performed';
            if (self.hasErrors()) {
                text += ', ' + _errors.length + ' errors';
            }
            if (self.hasWarnings()) {
                text += ', ' + _warnings.length + ' warnings';
            }
            if (!_isNullOrEmpty(_passedChecks)) {
                if (!self.hasErrors() && !self.hasWarnings()) {
                    text += ', all passed';
                } else {
                    text += ', ' + _passedChecks.length + ' passed';
                }
            }
        }

        return text;
    };

    function _convertItems(items) {
        var converted = [];
        for (var i = 0; i < items.length; i++) {
            converted.push(new ValidationItem(items[i]));
        }

        return converted;
    }

    function _joinItems (items, indentationLevel) {
        var text = '';
        var isFirst = true;
        var itemIndent = '\t'.repeat(indentationLevel);

        for (var i = 0; i < items.length; i++) {
            if (isFirst) {
                isFirst = false;
            } else {
                text += '\n';
            }
            text += itemIndent + '- ';
            text += items[i].toString(indentationLevel);
        }

        return text;
    }

    return self;
};

var ValidationItem = function (model) {
    var self = this;

    var _type = model.type;
    var _message = model.message;
    var _detail = model.detail;
    var _innerValidationResults;
    if (model.innerValidationResults != null) {
        _innerValidationResults = new ValidationResults(model.innerValidationResults);
    }

    self.getType = function() {
        return _type;
    };

    self.getMessage = function() {
        return _message;
    };

    self.getDetail = function() {
        return _detail;
    };

    self.__toString = function() {
        return self.toString(0);
    };

    self.toString = function(indentationLevel) {
        var text = '';
        text += _message;
        if (!_isNullOrEmpty(_detail)) {
            text += ' (' + _detail + ')';
        }
        if (_innerValidationResults != null) {
            text += '\n';
            text += _innerValidationResults.toString(indentationLevel + 1);
        }

        return text;
    };

    return self;
};

function _isNullOrEmpty(collection) {
    return !collection || collection.length === 0;
}

module.exports = {
    RestPkiClient: RestPkiClient,
    RestUnreachableError: RestUnreachableError,
    RestError: RestError,
    RestPKiError: RestPKiError,
    ValidationError: ValidationError,
    Authentication: Authentication,
    PadesSignatureStarter: PadesSignatureStarter,
    CadesSignatureStarter: CadesSignatureStarter,
    XmlSignatureStarter: XmlSignatureStarter,
    XmlElementSignatureStarter: XmlElementSignatureStarter,
    FullXmlSignatureStarter: FullXmlSignatureStarter,
    PadesSignatureFinisher: PadesSignatureFinisher,
    CadesSignatureFinisher: CadesSignatureFinisher,
    XmlSignatureFinisher: XmlSignatureFinisher,
    StandardSignaturePolicies: StandardSignaturePolicies,
    StandardSecurityContexts: StandardSecurityContexts,
    XmlInsertionOptions: XmlInsertionOptions,
    PadesVisualPositioningPresets: PadesVisualPositioningPresets,
    XmlIdResolutionTable: XmlIdResolutionTable,
    ValidationResults: ValidationResults,
    ValidationItem: ValidationItem
};