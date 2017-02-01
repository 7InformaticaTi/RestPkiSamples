var express = require('express');
var request = require('request');
var fs = require('fs');
var crypto = require('crypto');
var uuid = require('node-uuid');
var restPki = require('../lacuna-restpki'),
	PadesSignatureStarter = restPki.PadesSignatureStarter,
    PadesSignatureFinisher = restPki.PadesSignatureFinisher,
    PadesVisualPositioningPresets = restPki.PadesVisualPositioningPresets,
    StandardSignaturePolicies = restPki.StandardSignaturePolicies,
    StandardSecurityContexts = restPki.StandardSecurityContexts;

var client = require('../restpki-client');

var router = express.Router();
var appRoot = process.cwd();

/**
 * GET /pades-signature-server-key
 * 
 * This route performs a PAdES signature using REST PKI and PEM-encoded files for a certificate and for its private key. 
 * It renders the signature page.
 */
router.get('/', function(req, res, next) {

    // This function is called below. It contains examples of signature visual representation positionings. This code is
    // only in a separate function in order to organize the various examples, you can pick the one that best suits your
    // needs and use it below directly without an encapsulating function.
    function getVisualRepresentationPositionAsync(sampleNumber) {

        switch(sampleNumber) {
            case 1:
                // Example #1: automatic positioning on footnote. This will insert the signature, and future signatures,
                // ordered as a footnote of the last page of the document
                return PadesVisualPositioningPresets.getFootnote(client.getRestPkiClient());

            case 2:
                // Example #2: get the footnote positioning preset and customize it
                return new Promise(function(resolve, reject) {
                    PadesVisualPositioningPresets.getFootnote(client.getRestPkiClient())
                        .then(function(visualPosition) {
                            visualPosition.auto.container.left = 2.54;
                            visualPosition.auto.container.bottom = 2.54;
                            visualPosition.auto.container.right = 2.54;

                            resolve(visualPosition);
                        }).catch(function(error) {
                        reject(error);
                    });
                });

            case 3:
                // Example #3: automatic positioning on new page. This will insert the signature, and future signatures,
                // in a new page appended to the end of the document.
                return PadesVisualPositioningPresets.getNewPage(client.getRestPkiClient());

            case 4:
                // Example #4: get the "new page" positioning preset and customize it
                return new Promise(function(resolve, reject) {
                    PadesVisualPositioningPresets.getNewPage(client.getRestPkiClient())
                        .then(function(visualPosition) {
                            visualPosition.auto.container.left = 2.54;
                            visualPosition.auto.container.top = 2.54;
                            visualPosition.auto.container.right = 2.54;
                            visualPosition.auto.signatureRectangleSize.width = 5;
                            visualPosition.auto.signatureRectangleSize.height = 3;

                            resolve(visualPosition);
                        }).catch(function(error) {
                        reject(error);
                    });
                });

            case 5:
                // Example #5: manual positioning
                return new Promise(function(resolve) {
                    resolve({
                        pageNumber: 0, // zero means the signature will be placed on a new page appended to the end of the
                        // document
                        measurementUnits: 'Centimeters',
                        // define a manual position of 5cm x 3cm, positioned at 1 inch from the left and bottom margins
                        manual: {
                            left: 2.54,
                            bottom: 2.54,
                            width: 5,
                            height: 3
                        }
                    });
                });

            case 6:
                // Example #6: custom auto positioning
                return new Promise(function(resolve) {
                    resolve({
                        pageNumber: -1, // negative values represent pages counted from the end of the document (-1 is
                        // last page)
                        measurementUnits: 'Centimeters',
                        auto: {
                            // Specification of the container where the signatures will be placed, one after the other
                            container: {
                                // Specifying left and right (but no width) results in a variable-width container with the
                                // given margins
                                left: 2.54,
                                right: 2.54,
                                // Specifying bottom and height (but no top) results in a bottom-aligned fixed-height
                                // container
                                bottom: 2.54,
                                height: 12.31
                            },
                            // Specification of the size of each signature rectangle
                            signatureRectangleSize: {
                                width: 5,
                                height: 3
                            },
                            // The signatures will be placed in the container side by side. If there's no room left, the
                            // signatures will "wrap" to the next row. The value below specifies the vertical distance
                            // between rows
                            rowSpacing: 1
                        }
                    });
                });

            default:
                return null;
        }
    }

    // Instantiate the PadesSignatureStarter class, responsible for receiving the signature elements and start the signature
	// process
	var signatureStarter = new PadesSignatureStarter(client.getRestPkiClient());

    // Set PEM-encoded certificate file for ("Pierre de Fermat")
	signatureStarter.setSignerCertificateRaw(fs.readFileSync('./resources/fermat-cert.pem'));

    // If the user was redirected here by the route "upload" (signature with file uploaded by user), the "userfile" URL
    // argument will contain the filename under the "public/app-data" folder. Otherwise (signature with server file),
    // we'll sign a sample document.
    if (req.query.userfile) {
        signatureStarter.setPdfToSignFromPath('/public/app-data/' + req.query.userfile);
    } else {
        signatureStarter.setPdfToSignFromPath('/public/SampleDocument.pdf');
    }

    // Set the signature policy. For this sample, we'll use the Lacuna Test PKI in order to accept our test certificate used
    // above ("Pierre de Fermat"). This security context should be used FOR DEVELOPMENT PUPOSES ONLY. In production, you'll
    // typically want one of the alternatives below
    signatureStarter.setSignaturePolicy(StandardSignaturePolicies.padesBasic);
    signatureStarter.setSecurityContext('803517ad-3bbc-4169-b085-60053a8f6dbf');

    // Alternative option: PAdES Basic with ICP-Brasil certificates
    // signatureStarter.setSignaturePolicy(StandardSignaturePolicies.padesBasicWithPkiBrazilCerts);

    // Alternative option: aAd a ICP-Brasil timestamp to the signature
    // signatureStarter.setSignaturePolicy(StandardSignaturePolicies.padesTWithPkiBrazilCerts);

    // Alternative option: PAdES Basic with PKIs trusted by Windows
    // signatureStarter.setSignaturePolicy(StandardSignaturePolicies.padesBasic);
    // signatureStarter.setSecurityContext(StandardSecurityContexts.windowsServer);

	var visualRepresentation = {

        text: {
            // The tags {{name}} and {{national_id}} will be substituted according to the user's certificate
            //
            //  name        : full name of the signer
            //  national_id : if the certificate is ICP-Brasil, contains the signer's CPF
            //
            // For a full list of the supported tags, see:
            // https://github.com/LacunaSoftware/RestPkiSamples/blob/master/PadesTags.md
            text: 'Signed by {{signerName}} ({{signerNationalId}})',

            // Specify that the signing time should also be rendered
            includeSigningTime: true,

            // Optionally set the horizontal alignment of the text ('Left' or 'Right'), if not set the default is Left
            horizontalAlign: 'Left',

            // Optionally set the container within the signature rectangle on which to place the text. By default, the
            // text can occupy the entire rectangle (how much of the rectangle the text will actually fill depends on
			// the length and font size). Below, we specify that the text should respect a right margin of 1.5 cm.
            container: {
                left: 0,
				top: 0,
				right: 1.5,
				bottom: 0
            }
        },

        image: {

            // We'll use as background the image content/PdfStamp.png
            resource: {
                content: fs.readFileSync(appRoot + '/resources/PdfStamp.png', 'base64'), // Base64-encoded
                mimeType: 'image/png'
            },

            // Opacity is an integer from 0 to 100 (0 is completely transparent, 100 is completely opaque).
            opacity: 50,

            // Align the image to the right
            horizontalAlign: 'Right',

            // Align the image to the center
            verticalAlign: 'Center'
        }
	};

    // Position of the visual representation. We have encapsulated this code in a function to include several
    // possibilities depending on the argument passed to the function. Experiment changing the argument to see
    // different examples of signature positioning. Once you decide which is best for your case, you can place the
    // code directly here.
    getVisualRepresentationPositionAsync(1).then(function(visualPosition) {

    	visualRepresentation['position'] = visualPosition;

    	// Set the visual representation for the signature
		signatureStarter.setVisualRepresentation(visualRepresentation);

        // Call the startAsync() method, which initiates the signature. This yields the parameters for the signature
		// using the certificate
		signatureStarter.startAsync().then(function(signatureParams) {

            // Read PEM-encoded private-key file for ("Pierre de Fermat")
            var pkey = fs.readFileSync('./resources/fermat-pkey.pem', 'binary');

            // Create a new signature, setting the algorithm that will be used
            var sign = crypto.createSign(signatureParams.signatureAlgorithm);

            // Set the data that will be signed
            sign.write(signatureParams.toSignData);
            sign.end();

            // Perform the signature and receives the signature content
            var signature = sign.sign({ key: pkey, passphrase: '1234' });

            // Instantiate the PadesSignatureFinisher class, responsible for completing the signature process
            var signatureFinisher = new PadesSignatureFinisher(client.getRestPkiClient());

            // Set the token
			signatureFinisher.setToken(signatureParams.token);

			// Set the signature
			signatureFinisher.setSignatureRaw(signature);

            // Call the finishAsync() method, which finalizes the signature process
			signatureFinisher.finishAsync().then(function(signedPdf) {

                // Get information about the certificate used by the user to sign the file. This method must only be called
                // after calling the finish() method.
                var signerCert = signatureFinisher.getCertificateInfo();

                // At this point, you'd typically store the signed PDF on your database. For demonstration purposes, we'll
                // store the PDF on a temporary folder publicly accessible and render a link to it.
                var filename = uuid.v4() + '.pdf';
                var appDataPath = appRoot + '/public/app-data/';
                if (!fs.existsSync(appDataPath)){
                    fs.mkdirSync(appDataPath);
                }
                fs.writeFileSync(appDataPath + filename, signedPdf);

                // Render the signature completed page
                res.render('pades-signature-complete', {
                    signedFileName: filename,
                    signerCert: signerCert
                });

			}).catch(function(error) {
				next(error);
			});

        }).catch(function(error) {
            next(error);
        });

    }).catch(function(error) {
        next(error);
    });
});

module.exports = router;