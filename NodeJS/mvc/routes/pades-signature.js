var express = require('express');
var request = require('request');
var fs = require('fs');
var Promise = require('bluebird');
var uuid = require('node-uuid');
var restPki = require('../lacuna-restpki'),
	PadesVisualPositioningPresets = restPki.PadesVisualPositioningPresets,
	PadesSignatureStarter = restPki.PadesSignatureStarter,
    PadesSignatureFinisher = restPki.PadesSignatureFinisher,
    StandardSignaturePolicies = restPki.StandardSignaturePolicies,
    StandardSecurityContexts = restPki.StandardSecurityContexts;

var client = require('../restpki-client');

var router = express.Router();
var appRoot = process.cwd();


/*
 * GET /pades-signature
 *
 * This route initiates a PAdES signature using REST PKI and renders the signature page.
 *
 * Both PAdES signature examples, with a server file and with a file uploaded by the user, use this route. The
 * difference is that, when the file is uploaded by the user, the route is called with a URL argument named "userfile".
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
				return new Promise(function(resolve) {
                    PadesVisualPositioningPresets.getFootnote(client.getRestPkiClient())
					.then(function(visualPosition) {
						resolve(visualPosition);
					});
				});

			case 2:
				// Example #2: get the footnote positioning preset and customize it
				return new Promise(function(resolve) {
                    PadesVisualPositioningPresets.getFootnote(client.getRestPkiClient())
					.then(function(visualPosition) {
						visualPosition.auto.container.left = 2.54;
						visualPosition.auto.container.bottom = 2.54;
						visualPosition.auto.container.right = 2.54;
						resolve(visualPosition);
					});
				});

			case 3:
				// Example #3: automatic positioning on new page. This will insert the signature, and future signatures,
				// in a new page appended to the end of the document.
				return new Promise(function(resolve) {
					PadesVisualPositioningPresets.getNewPage(client.getRestPkiClient())
					.then(function(visualPosition) {
                        resolve(visualPosition);
                    });
                });

			case 4:
				// Example #4: get the "new page" positioning preset and customize it
				return new Promise(function(resolve) {
					PadesVisualPositioningPresets.getNewPage(client.getRestPkiClient())
					.then(function(visualPosition) {
						visualPosition.auto.container.left = 2.54;
						visualPosition.auto.container.top = 2.54;
						visualPosition.auto.container.right = 2.54;
						visualPosition.auto.signatureRectangleSize.width = 5;
						visualPosition.auto.signatureRectangleSize.height = 3;
						resolve(visualPosition);
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

    // Instantiate the PadesSignatureStarter class, responsible for receiving the signature elements and start the
	// signature process
	var signatureStarter = new PadesSignatureStarter(client.getRestPkiClient());

	// If the user was redirected here by the route "upload" (signature with file uploaded by user), the "userfile" URL
	// argument will contain the filename under the "public/app-data" folder. Otherwise (signature with server file),
	// we'll sign a sample document.
	if (req.query.userfile) {
		signatureStarter.setPdfFileToSign('/public/app-data/' + req.query.userfile);
	} else {
		signatureStarter.setPdfFileToSign('/public/SampleDocument.pdf');
	}

    // Set the signature policy
	signatureStarter.setSignaturePolicyId(StandardSignaturePolicies.padesBasic);

    // Set a SecurityContext to be used to determine trust in the certificate chain
	signatureStarter.setSecurityContextId(StandardSecurityContexts.pkiBrazil);
    // Note: By changing the SecurityContext above you can accept only certificates from a certain PKI, for instance,
	// ICP-Brasil (restPki.StandardSecurityContexts.pkiBrazil).

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
			horizontalAlign: 'Left'
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
			horizontalAlign: 'Right'
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

        // This operation yields the token, a 43-character case-sensitive URL-safe string, which identifies this
		// signature process. We'll use this value to call the signWithRestPki() method on the Web PKI
		// component (see view 'pades-signature') and also to complete the signature after the form is submitted. This
		// should not be mistaken with the API access token.
		signatureStarter.startWithWebPkiAsync().then(function(token) {

            // The token acquired can only be used for a single signature attempt. In order to retry the signature it is
            // necessary to get a new token. This can be a problem if the user uses the back button of the browser,
			// since the browser might show a cached page that we rendered previously, with a now stale token. To
			// prevent this from happening, we set some response headers specifying that the page should not be cached.
            res.set({
                'Cache-Control': 'private, no-store, max-age=0, no-cache, must-revalidate, post-check=0, pre-check=0',
                'Pragma': 'no-cache'
            });

            // Render the signature page
            res.render('pades-signature', {
                token: token,
                userfile: req.query.userfile
            });

		}).catch(function(err, data) {
			next(err);
			console.warn(data.message);
		});

	}).catch(function(err, data) {
		next(err);
		console.warn(data.message);
	});
});

/*
 * POST /pades-signature
 *
 * This route receives the form submission from the view 'pades-signature'. We'll call REST PKI to complete the
 * signature.
 */
router.post('/', function(req, res, next) {

	// Retrieve the token from the URL
	var token = req.body.token;

    // Instantiate the PadesSignatureFinisher class, responsible for completing the signature process
	var signatureFinisher = new PadesSignatureFinisher(client.getRestPkiClient());

    // Set the token
	signatureFinisher.setToken(token);

    // Call the finishAsync() method, which finalizes the signature process and returns the signed PDF
	signatureFinisher.finishAsync().then(function (signedPdf) {

        // Get information about the certificate used by the user to sign the file. This method must only be called
		// after calling the finish() method.
		var signerCert = signatureFinisher.getCertificate();

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

    }).catch(function(err, data) {
    	next(err);
    	console.warn(data.message);
	});
});

module.exports = router;
