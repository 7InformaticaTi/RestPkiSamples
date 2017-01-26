var request = require('request');
var fs = require('fs');
var Promise = require('bluebird');

var appRoot = process.cwd();

var RestPkiClient = function (endPointUrl, accessToken) {
    var _endPointUrl = endPointUrl;
    var _accessToken = accessToken;

    this.get = function(url) {
        return new Promise(function(resolve, reject) {
            request.get(_endPointUrl + url, {
                json: true,
                headers: { 'Authorization': 'Bearer ' + _accessToken}
            }, function(err, restRes, body) {
                var errObj = { value: err };
                if (_checkResponse(errObj, restRes, 'GET', url)) {
                    resolve(body);
                } else {
                    reject(errObj.value, body);
                }
            });
        });
    };

    this.post = function(url, data) {
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
                    reject(errObj.value, body);
                }
            });
        });
    };

    this.getAuthentication = function() {
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
                        errObj.value = new RestErrError(verb, url, statusCode, response.message);
                    }
                } catch (error) {
                    errObj.value = new RestErrError(verb, url, statusCode);
                }

            }
            return false;
        } else {
            return true;
        }
    }
};

var RestError = function(message, verb, url) {
    var _verb = verb;
    var _url = url;

    Error.captureStackTrace(this, this.constructor);
    this.__proto__ = new Error(message);
    this.__proto__.constructor = RestError;
    this.__proto__.getVerb = function() { return _verb; };
    this.__proto__.getUrl = function() { return _url; };
};

var RestUnreachableError = function(verb, url) {
    Error.captureStackTrace(this, this.constructor);
    this.__proto__ = new RestError('REST action ' + verb + ' ' + url + ' unreachable', verb, url);
    this.__proto__.constructor = RestUnreachableError;
    this.__proto__.name = 'RestUnreachableError';
};

var RestErrError = function(verb, url, statusCode, errorMessage) {
    var message = 'REST action ' + verb + ' ' + url + ' returned HTTP error ' + statusCode;
    if (errorMessage && errorMessage.length > 0) {
        message += ': ' + errorMessage;
    }
    var _statusCode = statusCode;
    var _errorMessage = errorMessage;

    Error.captureStackTrace(this, this.constructor);
    this.__proto__ = new RestError(message, verb, url);
    this.__proto__.constructor = RestErrError;
    this.__proto__.name = 'RestError';
    this.__proto__.getStatusCode = function() { return _statusCode; };
    this.__proto__.getErrorMessage = function() { return _errorMessage; };
};

var RestPKiError = function(verb, url, errorCode, detail) {
    var message = 'REST PKI action ' + verb + ' ' + url + ' error: ' + errorCode;
    if (detail && detail.length > 0) {
        message += ' (' + detail + ')';
    }
    var _errorCode = errorCode;
    var _detail = detail;

    Error.captureStackTrace(this, this.constructor);
    this.__proto__ = new RestError(message, verb, url);
    this.__proto__.constructor = RestPKiError;
    this.__proto__.name = 'RestPKiError';
    this.__proto__.getErrorCode = function() { return _errorCode; };
    this.__proto__.getDetail = function() { return _detail; };
};

var ValidationError = function(verb, url, validationResults) {
    var _validationResults = validationResults;

    Error.captureStackTrace(this, this.constructor);
    this.__proto__ = new RestError(validationResults.__toString(), verb, url);
    this.__proto__.constructor = ValidationError;
    this.__proto__.name = 'ValidationError';
    this.__proto__.getValidationResults = function() { return _validationResults; };
};

var Authentication = function(restPkiClient) {

    var _restPkiClient = restPkiClient;
    var _certificate;
    var _done = false;

    this.startWithWebPkiAsync = function(securityContextId) {

        return new Promise(function(resolve) {
            _restPkiClient.post('Api/Authentications', { 'securityContextId': securityContextId })
            .then(function(response) {
                resolve(response.token);
            });
        });
    };

    this.completeWithWebPkiAsync = function(token) {

        return new Promise(function(resolve) {
            _restPkiClient.post('Api/Authentications/' + token + '/Finalize', null)
            .then(function(response) {
                _certificate = response.certificate;
                _done = true;

                resolve(new ValidationResults(response.validationResults));
            });
        });
    };

    this.getCertificate = function() {
        if (!_done) {
            throw new Error('The method getCertificate() can only called after calling the completeWithWebPki method');
        }

        return _certificate;
    };
};

var PadesSignatureStarter = function(restPkiClient) {

    var _restPkiClient = restPkiClient;
    var _pdfContent;
    var _securityContextId;
    var _signaturePolicyId;
    var _visualRepresentation;

    this.setPdfFileToSign = function(pdfPath) {
        _pdfContent = fs.readFileSync(appRoot + pdfPath);
    };

    this.setPdfContentToSign = function(content) {
        _pdfContent = content;
    };

    this.setSecurityContextId = function(securityContextId) {
        _securityContextId = securityContextId;
    };

    this.setSignaturePolicyId = function(signaturePolicyId) {
        _signaturePolicyId = signaturePolicyId;
    };

    this.setVisualRepresentation = function(visualRepresentation) {
        _visualRepresentation = visualRepresentation;
    };

    this.startWithWebPkiAsync = function() {

        if (_isNullOrEmpty(_pdfContent)) {
            throw new Error('The PDF to sign was not set');
        }
        if (_isNullOrEmpty(_signaturePolicyId)) {
            throw new Error('The signature policy was not set');
        }

        return new Promise(function(resolve) {
            _restPkiClient.post('Api/PadesSignatures', {
                'pdfToSign' : new Buffer(_pdfContent).toString('base64'), // Base64-encoding
                'signaturePolicyId': _signaturePolicyId,
                'securityContextId': _securityContextId,
                'visualRepresentation': _visualRepresentation
            }).then(function(response) {
                resolve(response.token);
            });
        });
    };
};

var PadesSignatureFinisher = function(restPkiClient) {

    var _restPkiClient = restPkiClient;
    var _token;
    var _done;
    var _signedPdf;
    var _certificate;

    this.setToken = function(token) {
        _token = token;
    };

    this.finishAsync = function() {

        if (_isNullOrEmpty(_token)) {
            throw new Error('The token was not set');
        }

        return new Promise(function(resolve) {
            _restPkiClient.post('Api/PadesSignatures/' + _token + '/Finalize', null)
            .then(function(response) {
                _signedPdf = new Buffer(response.signedPdf, 'base64'); // Base64-decoding
                _certificate = response.certificate;
                _done = true;

                resolve(_signedPdf);
            });
        });
    };

    this.getCertificate = function() {
        if (!_done) {
            throw new Error('The method getCertificate() can only be called after calling the finish() method');
        }
        return _certificate;
    };

    this.writeSignedPdfToPath = function(pdfPath) {
        if (!_done) {
            throw new Error('The method writeSignedPdfToPath() can only be called after calling the finish() method');
        }
        fs.writeFileSync(pdfPath, _signedPdf);
    };
};

var CadesSignatureStarter = function(restPkiClient) {

    var _restPkiClient = restPkiClient;
    var _contentToSign;
    var _securityContextId;
    var _signaturePolicyId;
    var _cmsToCoSign;
    var _callbackArgument;
    var _encapsulateContent;

    this.setFileToSign = function(filePath) {
        _contentToSign = fs.readFileSync(appRoot + filePath);
    };

    this.setContentToSign = function(content) {
        _contentToSign = content;
    };

    this.setCmsFileToCoSign = function(cmsPath) {
        _cmsToCoSign = fs.readFileSync(appRoot + cmsPath);
    };

    this.setCmsToCoSign = function(cmsBytes) {
        _cmsToCoSign = cmsBytes;
    };

    this.setSecurityContextId = function(securityContextId) {
        _securityContextId = securityContextId;
    };

    this.setSignaturePolicyId = function(signaturePolicyId) {
        _signaturePolicyId = signaturePolicyId;
    };

    this.setCallbackArgument = function(callbackArgument) {
        _callbackArgument = callbackArgument;
    };

    this.setEncapsulateContent = function(encapsulateContent) {
        _encapsulateContent = encapsulateContent;
    };

    this.startWithWebPkiAsync = function() {

        if (_isNullOrEmpty(_contentToSign) && _isNullOrEmpty(_cmsToCoSign)) {
            throw new Error('The content to sign was not set and no CMS to be co-signed was given');
        }
        if (_isNullOrEmpty(_signaturePolicyId)) {
            throw new Error('The signature policy was not set');
        }

        var request = {
            'signaturePolicyId': _signaturePolicyId,
            'securityContextId': _securityContextId,
            'callbackArgument': _callbackArgument,
            'encapsulateContent': _encapsulateContent
        };
        if (!_isNullOrEmpty(_contentToSign)) {
            request['contentToSign'] = new Buffer(_contentToSign).toString('base64');
        }
        if (!_isNullOrEmpty(_cmsToCoSign)) {
            request['cmsToCoSign'] = new Buffer(_cmsToCoSign).toString('base64');
        }

        return new Promise(function(resolve) {
            _restPkiClient.post('Api/CadesSignatures', request)
            .then(function(response) {
                resolve(response.token);
            });
        });
    };
};

var CadesSignatureFinisher = function(restPkiClient) {

    var _restPkiClient = restPkiClient;
    var _token;
    var _done;
    var _cms;
    var _certificate;
    var _callbackArgument;

    this.setToken = function(token) {
        _token = token;
    };

    this.finishAsync = function() {

        if (_isNullOrEmpty(_token)) {
            throw new Error('The token was not set');
        }

        return new Promise(function(resolve) {
            _restPkiClient.post('Api/CadesSignatures/' + _token + '/Finalize', null)
            .then(function(response) {
                _cms = new Buffer(response.cms, 'base64'); // Base64-decoding
                _certificate = response.certificate;
                _callbackArgument = response.callbackArgument;
                _done = true;

                resolve(_cms);
            });
        });
    };

    this.getCertificate = function() {
        if (!_done) {
            throw new Error('The method getCertificate() can only be called after calling the finish() method');
        }
        return _certificate;
    };

    this.getCallbackArgument = function() {
        if (!_done) {
            throw new Error('The method getCallbackArgument() can only be called after calling the finish() method');
        }
        return _callbackArgument;
    };

    this.writeCmsToPath = function(path)  {
        if (!_done) {
            throw new Error('The method writeCmsfToPath() can only be called after calling the finish() method');
        }
        fs.writeFileSync(path, _cms);
    };

};

var XmlSignatureStarter = function(restPkiClient) {

    this._restPkiClient = restPkiClient;
    this._xmlContent;
    this._securityContextId;
    this._signaturePolicyId;
    this._signatureElementId;
    this._signatureElementLocationXPath;
    this._signatureElementLocationNsm;
    this._signatureElementLocationInsertionOption;

    this.setXmlFileToSign = function(xmlPath) {
        this._xmlContent = fs.readFileSync(appRoot + xmlPath);
    };

    this.setXmlContentToSign = function(content) {
        this._xmlContent = content;
    };

    this.setSecurityContextId = function(securityContextId) {
        this._securityContextId = securityContextId;
    };

    this.setSignaturePolicyId = function(signaturePolicyId) {
        this._signaturePolicyId = signaturePolicyId;
    };

    this.setSignatureElementLocation = function(xpath, insertionOption, namespaceManager) {
        this._signatureElementLocationXPath = xpath;
        this._signatureElementLocationInsertionOption = insertionOption;
        this._signatureElementLocationNsm = namespaceManager;
    };

    this.setSignatureElementId = function(signatureElementId) {
        this._signatureElementId = signatureElementId;
    };

    this._verifyCommonParameters = function() {
        if (_isNullOrEmpty(this.signaturePolicyId)) {
            throw new Error('The signature policy was not set');
        }
    };

    this._getRequest = function() {

        var request = {
            'signaturePolicyId': _signaturePolicyId,
            'securityContextId': _securityContextId,
            'signatureElementId': _signatureElementId
        };

        if (_xmlContent != null) {
            request['xml'] = new Buffer(_xmlContent).toString('base64'); // Base64-encoding
        }
        if (_signatureElementLocationXPath != null && _signatureElementLocationInsertionOption != null) {
            request['signatureElementLocation'] = {
                'xPath': _signatureElementLocationXPath,
                'insertionOption': _signatureElementLocationInsertionOption
            };
            if (_signatureElementLocationNsm != null) {
                for (var key in _signatureElementLocationNsm) {
                    if (_signatureElementLocationNsm.hasOwnProperty(key)) {
                        request['signatureElementLocation']['namespaces'] = {
                            'prefix': key,
                            'uri': _signatureElementLocationNsm[key]
                        };
                    }
                }
            }
        }

        return request;
    };
};

var XmlElementSignatureStarter = function(restPkiClient) {
    this.__proto__ = new XmlSignatureStarter(restPkiClient);
    this.__proto__.constructor = XmlElementSignatureStarter;

    var _toSignElementId;
    var _idResolutionTable;

    this.setToSignElementId = function(toSignElementId)  {
        _toSignElementId = toSignElementId;
    };

    this.setIdResolutionTable = function(idResolutionTable) {
        _idResolutionTable = idResolutionTable;
    };

    this.startWithWebPki = function() {

        this._verifyCommonParameters();
        if (_isNullOrEmpty(this._xmlContent)) {
            throw new Error('The XML was not set');
        }
        if (_isNullOrEmpty(this._toSignElementId)) {
            throw new Error('The XML element id to sign was not set');
        }

        var request = this._getRequest();
        request['elementToSignId'] = _toSignElementId;
        if (_idResolutionTable != null) {
            request['idResolutionTable'] = _idResolutionTable.toModel();
        }

        return new Promise(function(resolve) {
            this._restPkiClient.post('Api/XmlSignatures/XmlElementSignature', request)
            .then(function(response) {
                resolve(response.token);
            });
        });
    };
};

var FullXmlSignatureStarter = function(restPkiClient) {
    this.__proto__ = new XmlSignatureStarter(restPkiClient);
    this.__proto__.constructor = FullXmlSignatureStarter;

    this.startWithWebPki = function() {

        this._verifyCommonParameters();
        if (_isNullOrEmpty(this._xmlContent)) {
            throw new Error('The XML was not set');
        }

        var request = this._getRequest();

        return new Promise(function(resolve) {
            this._restPkiClient.post('Api/XmlSignatures/FullXmlSignature', request)
            .then(function(response) {
                resolve(response.token);
            });
        })
    };
};

var XmlSignatureFinisher = function(restPkiClient) {

    var _restPkiClient = restPkiClient;
    var _token;
    var _done;
    var _signedXml;
    var _certificate;

    this.setToken = function(token) {
        _token = token;
    };

    this.finish = function() {

        if (_isNullOrEmpty(_token)) {
            throw new Error('The token was not set');
        }

        return new Promise(function(resolve) {
            _restPkiClient.post('Api/XmlSignatures/' + _token + '/Finalize', null)
            .then(function(response) {
                _signedXml = new Buffer(response.signedXml, 'base64'); // Base64-decoding
                _certificate = response.certificate;
                _done = true;

                resolve(_signedXml);
            });
        });
    };

    this.getCertificate = function() {
        if (!_done) {
            throw new Error('The method getCertificate() can only be called after calling the finish() method');
        }
        return _certificate;
    };

    this.writeSignedXmlToPath = function(pdfPath) {
        if (!_done) {
            throw new Error('The method writeSignedXmlToPath() can only be called after calling the finish() method');
        }
        fs.writeFileSync(pdfPath, _signedXml);
    };
};

var StandardSignaturePolicies = {
    padesBasic: '78d20b33-014d-440e-ad07-929f05d00cdf',
    padesBasicWithPkiBrazilCerts: '3fec800c-366c-49bf-82c5-2e72154e70f6',
    padesPadesTWithPkiBrazilCerts: '6a39aeea-a2d0-4754-bf8c-19da15296ddb',
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

    var _cachedPresets = {};

    var getFootnote = function(restPkiClient, pageNumber, rows) {
        var urlSegment = 'Footnote';
        if (!_isNullOrEmpty(pageNumber)) {
            urlSegment += "?pageNumber=" + pageNumber;
        }
        if (!_isNullOrEmpty(rows)) {
            urlSegment += "?rows=" + rows;
        }

        return _getPreset(restPkiClient, urlSegment);
    };

    var getNewPage = function(restPkiClient) {
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

    return {
        getFootnote: getFootnote,
        getNewPage: getNewPage
    };
})();

var XmlIdResolutionTable = function(includeXmlIdGlobalAttribute) {

    var _model = {
        'elementIdAttributes': {},
        'globalIdAttributes': {},
        'includeXmlIdAttribute': includeXmlIdGlobalAttribute
    };

    this.addGlobalIdAttribute = function(idAttributeLocalName, idAttributeNamespace) {
        _model['globalIdAttributes'] = {
            localName: idAttributeLocalName,
            namespace: idAttributeNamespace
        };
    };

    this.setElementIdAttribute = function(elementLocalName, elementNamespace, idAttributeLocalName, idAttributeNamespace) {
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

    this.toModel = function() {
        return _model;
    };
};

var ValidationResults = function(model) {
    var _errors = _convertItems(model.errors);
    var _warnings = _convertItems(model.warnings);
    var _passedChecks = _convertItems(model.passedChecks);

    this.isValid = function() {
        return _isNullOrEmpty(_errors);
    };

    this.getChecksPerformed = function() {
        return _errors.length + _warnings.length + _passedChecks.length;
    };

    this.hasErrors = function() {
        return !this.isValid();
    };

    this.hasWarnings = function() {
        return _warnings && _warnings.length > 0;
    };

    this.__toString = function() {
        return this.toString(0);
    };

    this.toString = function(indentationLevel) {
        var itemIndent = '\t'.repeat(indentationLevel);
        var text = '';

        text += this.getSummary(indentationLevel);
        if (this.hasErrors()) {
            text += '\n' + itemIndent + 'Errors:\n';
            text += _joinItems(_errors, indentationLevel);
        }
        if (this.hasWarnings()) {
            text += '\n' + itemIndent + 'Warnings:\n';
            text += _joinItems(_warnings, indentationLevel);
        }
        if (!_isNullOrEmpty(_passedChecks)) {
            text += '\n' + itemIndent + 'Passed Checks:\n';
            text += _joinItems(_passedChecks, indentationLevel);
        }

        return text;
    };

    this.getSummary = function(indentationLevel) {
        indentationLevel = indentationLevel || 0;

        var itemIndent = '\t'.repeat(indentationLevel);
        var text = itemIndent + 'Validation results: ';

        if (this.getChecksPerformed() === 0) {
            text += 'no checks performed';
        } else {
            text += this.getChecksPerformed() + ' checks performed';
            if (this.hasErrors()) {
                text += ', ' + _errors.length + ' errors';
            }
            if (this.hasWarnings()) {
                text += ', ' + _warnings.length + ' warnings';
            }
            if (!_isNullOrEmpty(_passedChecks)) {
                if (!this.hasErrors() && !this.hasWarnings()) {
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
};

var ValidationItem = function (model) {
    var _type = model.type;
    var _message = model.message;
    var _detail = model.detail;
    var _innerValidationResults;
    if (model.innerValidationResults != null) {
        _innerValidationResults = new ValidationResults(model.innerValidationResults);
    }

    this.getType = function() {
        return _type;
    };

    this.getMessage = function() {
        return _message;
    };

    this.getDetail = function() {
        return _detail;
    };

    this.__toString = function() {
        return this.toString(0);
    };

    this.toString = function(indentationLevel) {
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
    }
};

function _isNullOrEmpty(collection) {
    return collection == null || collection.length === 0;
}

module.exports = {
    RestPkiClient: RestPkiClient,
    RestError: RestError,
    RestUnreachableError: RestUnreachableError,
    RestErrError: RestErrError,
    RestPKiError: RestPKiError,
    ValidationError: ValidationError,
    Authentication: Authentication,
    PadesSignatureStarter: PadesSignatureStarter,
    PadesSignatureFinisher: PadesSignatureFinisher,
    CadesSignatureStarter: CadesSignatureStarter,
    CadesSignatureFinisher: CadesSignatureFinisher,
    XmlElementSignatureStarter: XmlElementSignatureStarter,
    FullXmlSignatureStarter: FullXmlSignatureStarter,
    XmlSignatureFinisher: XmlSignatureFinisher,
    StandardSignaturePolicies: StandardSignaturePolicies,
    StandardSecurityContexts: StandardSecurityContexts,
    XmlInsertionOptions: XmlInsertionOptions,
    PadesVisualPositioningPresets: PadesVisualPositioningPresets,
    XmlIdResolutionTable: XmlIdResolutionTable,
    ValidationResults: ValidationResults,
    ValidationItem: ValidationItem
};