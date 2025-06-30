from flask import Blueprint, current_app, jsonify, request

from .utils import set_group_id, validate_client_certificate

blueprint = Blueprint(
    'new_group',
    __name__,
    url_prefix='/new-group'
)

@blueprint.route('/<string:group_id>')
def set_new_group_id(group_id):
    """Set new group id callback function

    Arguments:
        group_id(str): Group id

    Returns:
        json: Result message
    """
    try:
        # Get client certificate from request environment
        client_cert = request.environ.get('X-SSL-Client-Cert')
        if not client_cert:
            raise ValueError("Client certificate is required.")
    
        # Validate client certificate
        error_message = validate_client_certificate(client_cert)
        if error_message:
            raise ValueError(error_message)

        set_group_id(group_id)
        return jsonify({
            'result': 'OK',
            'message': 'Success.'
        })
    except Exception as ex:
        current_app.logger.error(ex)
        return jsonify({
            'result': 'NG',
            'message': str(ex)
        })