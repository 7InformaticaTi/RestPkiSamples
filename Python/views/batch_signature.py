import base64
import os
import uuid

from lacunarestpki import PadesSignatureStarter, StandardSignaturePolicies, StandardSecurityContexts, \
    PadesVisualPositioningPresets, PadesSignatureFinisher
from util import restpki_client, STATIC_FOLDER, APPDATA_FOLDER
from flask import Blueprint, render_template, json, request

# Create a blueprint for this view for its routes to be reachable
blueprint = Blueprint('batch_signature', __name__)


@blueprint.route('/batch-signature')
def batch_siganture():
    """
        This function renders the batch signature page.

        Notice that the only thing we'll do on the server-side at this point is determine the IDs of the documents
        to be signed. The page will handle each document one by one and will call the server asynchronously to
        start and complete each signature.
    """

    documents_ids = json.dumps([('%02d' % x) for x in range(1, 31)])

    return render_template('batch-signature.html', documents_ids=documents_ids)


@blueprint.route('/batch-signature/start', methods=['POST'])
def start():
    """
        This function is called asynchronously via AJAX by the batch signature page for each document being signed. It
        receives the ID of the document and initiates a PAdES signature using REST PKI and returns a JSON with the
        token, which identifies this signature process, to be used in the next signature steps
        (see batch-signature-form.js).
    """

    # Get the document id for this signature (received from the POST call, see batch-signature-form.js)
    _id = request.args['id']

    # Read the PDF stamp image
    f = open('static/PdfStamp.png', 'rb')
    pdf_stamp = f.read()
    f.close()

    # Instantiate the PadesSignatureStarter class, responsible for receiving the signature elements and start the
    # signature process
    signature_starter = PadesSignatureStarter(restpki_client)

    # Set the document to be signed based on its ID
    signature_starter.set_pdf_path('%s/%02d.pdf' % (STATIC_FOLDER, int(_id)))

    # Set the signature policy
    signature_starter.signature_policy_id = StandardSignaturePolicies.PADES_BASIC

    # Set a SecurityContext to be used to determine trust in the certificate chain
    signature_starter.security_context_id = StandardSecurityContexts.PKI_BRAZIL
    # Note: By changing the SecurityContext above you can accept only certificates from a certain PKI, for instance,
    # ICP-Brasil (lacunarestpki.StandardSecurityContexts.PKI_BRAZIL).

    # Set the visual representation for the signature
    signature_starter.visual_representation = ({

        'text': {
            # The tags {{signerName}} and {{signerNationalId}} will be substituted according to the user's
            # certificate
            # signerName -> full name of the signer
            # signerNationalId -> if the certificate is ICP-Brasil, contains the signer's CPF
            'text': 'Signed by {{signerName}} ({{signerNationalId}})',
            # Specify that the signing time should also be rendered
            'includeSigningTime': True,
            # Optionally set the horizontal alignment of the text ('Left' or 'Right'), if not set the default is
            # Left
            'horizontalAlign': 'Left'
        },

        'image': {
            # We'll use as background the image that we've read above
            'resource': {
                'content': base64.b64encode(pdf_stamp),
                'mimeType': 'image/png'
            },
            # Opacity is an integer from 0 to 100 (0 is completely transparent, 100 is completely opaque).
            'opacity': 50,

            # Align the image to the right
            'horizontalAlign': 'Right'
        },

        # Position of the visual representation. We have encapsulated this code in a function to include several
        # possibilities depending on the argument passed to the function. Experiment changing the argument to see
        # different examples of signature positioning (valid values are 1-6). Once you decide which is best for
        # your case, you can place the code directly here.
        'position': get_visual_representation_position(1)
    })

    # Call the start_with_webpki() method, which initiates the signature. This yields the token, a 43-character
    # case-sensitive URL-safe string, which identifies this signature process. We'll use this value to call the
    # signWithRestPki() method on the Web PKI component (see batch-signature-form.js) and also to
    # complete the signature after the form is submitted (see method complete()). This should not be
    # mistaken with the API access token.
    token = signature_starter.start_with_webpki()

    return json.dumps(token)


@blueprint.route('/batch-signature/complete', methods=['POST'])
def complete():
    """
        This function is called asynchronously via AJAX by the batch signature page for each document being signed. It
        receives the token, that identifies the signature process. We'll call REST PKI to complete this signature and
        return a JSON with the saved filename so that the page can render a link to it.
    """

    # Get the token for this signature (received from the post call, see batch-signature-form.php)
    token = request.args['token']

    # Instantiate the PadesSignatureFinisher class, responsible for completing the signature process
    signature_finisher = PadesSignatureFinisher(restpki_client)

    # Set the token
    signature_finisher.token = token

    # Call the finish() method, which finalizes the signature process and returns the signed PDF
    signature_finisher.finish()

    # Get information about the certificate used by the user to sign the file. This method must only be called after
    # calling the finish() method.
    signer_cert = signature_finisher.certificate

    # At this point, you'd typically store the signed PDF on your database. For demonstration purposes, we'll
    # store the PDF on a temporary folder publicly accessible and render a link to it.

    filename = '%s.pdf' % (str(uuid.uuid1()))
    signature_finisher.write_signed_pdf(os.path.join(APPDATA_FOLDER, filename))

    return json.dumps(filename)


def get_visual_representation_position(sample_number):
    """
        This function is called by the pades_signature function. It contains examples of signature visual representation
        positionings.
    """
    if sample_number == 1:
        # Example #1: automatic positioning on footnote. This will insert the signature, and future signatures,
        # ordered as a footnote of the last page of the document
        return PadesVisualPositioningPresets.get_footnote(restpki_client)
    elif sample_number == 2:
        # Example #2: get the footnote positioning preset and customize it
        visual_position = PadesVisualPositioningPresets.get_footnote(restpki_client)
        visual_position['auto']['container']['left'] = 2.54
        visual_position['auto']['container']['bottom'] = 2.54
        visual_position['auto']['container']['right'] = 2.54
        return visual_position
    elif sample_number == 3:
        # Example #3: automatic positioning on new page. This will insert the signature, and future signatures,
        # in a new page appended to the end of the document.
        return PadesVisualPositioningPresets.get_new_page(restpki_client)
    elif sample_number == 4:
        # Example #4: get the "new page" positioning preset and customize it
        visual_position = PadesVisualPositioningPresets.get_new_page(restpki_client)
        visual_position['auto']['container']['left'] = 2.54
        visual_position['auto']['container']['top'] = 2.54
        visual_position['auto']['container']['right'] = 2.54
        visual_position['auto']['signatureRectangleSize']['width'] = 5
        visual_position['auto']['signatureRectangleSize']['height'] = 3
        return visual_position
    elif sample_number == 5:
        # Example #5: manual positioning
        return {
            'pageNumber': 0,
            # zero means the signature will be placed on a new page appended to the end of the document
            'measurementUnits': 'Centimeters',
            # define a manual position of 5cm x 3cm, positioned at 1 inch from the left and bottom margins
            'manual': {
                'left': 2.54,
                'bottom': 2.54,
                'width': 5,
                'height': 3
            }
        }
    elif sample_number == 6:
        # Example #6: custom auto positioning
        return {
            'pageNumber': -1,
            # negative values represent pages counted from the end of the document (-1 is last page)
            'measurementUnits': 'Centimeters',
            'auto': {
                # Specification of the container where the signatures will be placed, one after the other
                'container': {
                    # Specifying left and right (but no width) results in a variable-width container with the given
                    # margins
                    'left': 2.54,
                    'right': 2.54,
                    # Specifying bottom and height (but no top) results in a bottom-aligned fixed-height container
                    'bottom': 2.54,
                    'height': 12.31
                },
                # Specification of the size of each signature rectangle
                'signatureRectangleSize': {
                    'width': 5,
                    'height': 3
                },
                # The signatures will be placed in the container side by side. If there's no room left, the
                # signatures will "wrap" to the next row. The value below specifies the vertical distance between
                # rows
                'rowSpacing': 1
            }
        }
    else:
        return None
