var request = require('request');

module.exports.RestPki = (function () {
    var RestPkiClient = function (endPointUrl, accessToken) {
        var _endPointUrl = endPointUrl;
        var _accessToken = accessToken;
        var _err = null;

        this.get = function(url, callback) {
            // TODO
        };

        this.post = function(url, data, callback) {

            request.post(_endPointUrl + url, {
                json: true,
                headers: { 'Authorization': 'Bearer ' + _accessToken},
                body: data
            }, function (err, restRes, body) {
                _err = err;
                if (checkResponse(restRes, 'POST', url)) {
                    callback(null, restRes.body);
                } else {
                    callback(_err, restRes.body);
                }
            });
        };

        this.getAuthentication = function() {
            return new Authentication(this);
        };

        var checkResponse = function (restRes, verb, url) {
            var statusCode = restRes.statusCode;
            
            if (_err || statusCode < 200 || statusCode >= 300) {
                if (!_err) {
                    try {
                        var response = restRes.body;
                        if (statusCode == 422 && response.code && response.code.length > 0) {
                            if (restRes.code == 'ValidationError') {
                                var vr = new ValidationResults(response.validationResults);
                                _err = new ValidationError(verb, url, vr);
                            } else {
                                _err = new RestPKiError(verb, url, response.code, response.detail);
                            }
                        } else {
                            _err = new RestErrError(verb, url, statusCode, response.message);
                        }
                    } catch (error) {
                        _err = new RestErrError(verb, url, statusCode);
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

        this.startWithWebPki = function(securityContextId, callback) {
            var response = _restPkiClient.post('Api/Authentications', {
                'securityContextId': securityContextId
            }, function(err, response) {
                if (!err) {
                    callback(null, response);
                } else {
                    callback(err, response);
                }
            });
        };

        this.completeWithWebPki = function(token, callback) {
            var response = _restPkiClient.post('Api/Authentications/' + token + '/Finalize', null, 
                function(err, response) {
                    if (!err) {
                        _certificate = response.certificate;
                        _done = true;
                        callback(null, new ValidationResults(response.validationResults));
                    } else {
                        callback(err, response);
                    }
                }
            );
        };

        this.getCertificate = function() {
            if (!_done) {
                throw new Error('The method getCertificate() can only called after calling the completeWithWebPki method');
            }

            return _certificate;
        };
    };

    var ValidationResults = function(model) {
        var _errors = convertItems(model.errors);
        var _warnings = convertItems(model.warnings);
        var _passedChecks = convertItems(model.passedChecks);

        this.isValid = function() {
            return !_errors || _errors.length == 0;
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
                text += joinItems(_errors, indentationLevel);
            }
            if (this.hasWarnings()) {
                text += '\n' + itemIndent + 'Warnings:\n';
                text += joinItems(_warnings, indentationLevel);
            }
            if (_passedChecks && _passedChecks.length > 0) {
                text += '\n' + itemIndent + 'Passed Checks:\n';
                text += joinItems(_passedChecks, indentationLevel);
            }

            return text;
        };

        this.getSummary = function(indentationLevel) {
            indentationLevel = indentationLevel | 0;

            var itemIndent = '\t'.repeat(indentationLevel);
            var text = itemIndent + 'ValidationError: ';

            if (this.getChecksPerformed() == 0) {
                text += 'no checks performed';
            } else {
                text += this.getChecksPerformed() + ' checks performed';
                if (this.hasErrors()) {
                    text += ', ' + _errors.length + ' errors';
                }
                if (this.hasWarnings()) {
                    text += ', ' + _warnings.length + ' warnings';
                }
                if (_passedChecks && _passedChecks.length > 0) {
                    if (!this.hasErrors() && !this.hasWarnings()) {
                        text += ', all passed';
                    } else {
                        text += ', ' + _passedChecks.length + ' passed';
                    }
                }
            }

            return text;
        };

        function convertItems(items) {
            var converted = [];
            for (var i = 0; i < items.length; i++) {
                converted.push(new ValidationItem(items[i]));
            }

            return converted;
        }

        function joinItems(items, indentationLevel) {
            var itemIndent = '\t'.repeat(indentationLevel);
            var text = '';
            var isFirst = true;

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
            if (_detail && _detail.length) {
                text += ' (' + _detail + ')';
            }
            if (_innerValidationResults != null) {
                text += '\n';
                text += _innerValidationResults.toString(indentationLevel + 1);
            }
            return text;
        }
    };

    var StandardSignaturePolicies = {
        padesBes: '78d20b33-014d-440e-ad07-929f05d00cdf',
        cadesBes: 'a4522485-c9e5-46c3-950b-0d6e951e17d1',

        pkiBrazilCadesAdrBasica:'3ddd8001-1672-4eb5-a4a2-6e32b17ddc46',
        pkiBrazilCadesAdrTempo: 'a5332ad1-d105-447c-a4bb-b5d02177e439',
        pkiBrazilCadesAdrValidacao: '92378630-dddf-45eb-8296-8fee0b73d5bb',
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

    return { 
        RestPkiClient, 
        RestPkiClient, 
        RestError, 
        RestUnreachableError, 
        RestErrError, 
        RestPKiError, 
        ValidationError, 
        Authentication, 
        ValidationResults, 
        ValidationItem, 
        StandardSignaturePolicies, 
        StandardSecurityContexts
    }
})();