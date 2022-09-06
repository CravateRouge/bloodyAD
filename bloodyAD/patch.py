import ldap3

SIGN = 'sign'
ENCRYPT = 'ENCRYPT'

from ldap3.core.connection import *
def __init__(self,
                 server,
                 user=None,
                 password=None,
                 session_security=None,
                 auto_bind=AUTO_BIND_DEFAULT,
                 version=3,
                 authentication=None,
                 client_strategy=SYNC,
                 auto_referrals=True,
                 auto_range=True,
                 sasl_mechanism=None,
                 sasl_credentials=None,
                 check_names=True,
                 collect_usage=False,
                 read_only=False,
                 lazy=False,
                 raise_exceptions=False,
                 pool_name=None,
                 pool_size=None,
                 pool_lifetime=None,
                 cred_store=None,
                 fast_decoder=True,
                 receive_timeout=None,
                 return_empty_attributes=True,
                 use_referral_cache=False,
                 auto_escape=True,
                 auto_encode=True,
                 pool_keepalive=None,
                 source_address=None,
                 source_port=None,
                 source_port_list=None):
        conf_default_pool_name = get_config_parameter('DEFAULT_THREADED_POOL_NAME')
        self.connection_lock = RLock()  # re-entrant lock to ensure that operations in the Connection object are executed atomically in the same thread
        with self.connection_lock:
            if client_strategy not in CLIENT_STRATEGIES:
                self.last_error = 'unknown client connection strategy'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPUnknownStrategyError(self.last_error)

            self.strategy_type = client_strategy
            self.user = user
            self.password = password

            if not authentication and self.user:
                self.authentication = SIMPLE
            elif not authentication:
                self.authentication = ANONYMOUS
            elif authentication in [SIMPLE, ANONYMOUS, SASL, NTLM]:
                self.authentication = authentication
            else:
                self.last_error = 'unknown authentication method'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPUnknownAuthenticationMethodError(self.last_error)

            self.version = version
            self.auto_referrals = True if auto_referrals else False
            self.request = None
            self.response = None
            self.result = None
            self.bound = False
            self.listening = False
            self.closed = True
            self.last_error = None
            if auto_bind is False:  # compatibility with older version where auto_bind was a boolean
                self.auto_bind = AUTO_BIND_DEFAULT
            elif auto_bind is True:
                self.auto_bind = AUTO_BIND_NO_TLS
            else:
                self.auto_bind = auto_bind
            self.sasl_mechanism = sasl_mechanism
            self.sasl_credentials = sasl_credentials
            self._usage = ConnectionUsage() if collect_usage else None
            self.socket = None
            self.tls_started = False
            self.sasl_in_progress = False
            self.read_only = read_only
            self._context_state = []
            self._deferred_open = False
            self._deferred_bind = False
            self._deferred_start_tls = False
            self._bind_controls = None
            self._executing_deferred = False
            self.lazy = lazy
            self.pool_name = pool_name if pool_name else conf_default_pool_name
            self.pool_size = pool_size
            self.cred_store = cred_store
            self.pool_lifetime = pool_lifetime
            self.pool_keepalive = pool_keepalive
            self.starting_tls = False
            self.check_names = check_names
            self.raise_exceptions = raise_exceptions
            self.auto_range = True if auto_range else False
            self.extend = ExtendedOperationsRoot(self)
            self._entries = []
            self.fast_decoder = fast_decoder
            self.receive_timeout = receive_timeout
            self.empty_attributes = return_empty_attributes
            self.use_referral_cache = use_referral_cache
            self.auto_escape = auto_escape
            self.auto_encode = auto_encode
            self._digest_md5_kic = None
            self._digest_md5_kis = None
            self._digest_md5_kcc_cipher = None
            self._digest_md5_kcs_cipher = None
            self._digest_md5_sec_num = 0
            self.krb_ctx = None

            if session_security and not (self.authentication == NTLM or self.sasl_mechanism == GSSAPI):
                self.last_error = '"session_security" option only available for NTLM and GSSAPI'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPInvalidValueError(self.last_error)
            self.session_security = session_security
            
            port_err = check_port_and_port_list(source_port, source_port_list)
            if port_err:
                if log_enabled(ERROR):
                    log(ERROR, port_err)
                raise LDAPInvalidPortError(port_err)
            # using an empty string to bind a socket means "use the default as if this wasn't provided" because socket
            # binding requires that you pass something for the ip if you want to pass a specific port
            self.source_address = source_address if source_address is not None else ''
            # using 0 as the source port to bind a socket means "use the default behavior of picking a random port from
            # all ports as if this wasn't provided" because socket binding requires that you pass something for the port
            # if you want to pass a specific ip
            self.source_port_list = [0]
            if source_port is not None:
                self.source_port_list = [source_port]
            elif source_port_list is not None:
                self.source_port_list = source_port_list[:]

            if isinstance(server, STRING_TYPES):
                server = Server(server)
            if isinstance(server, SEQUENCE_TYPES):
                server = ServerPool(server, ROUND_ROBIN, active=True, exhaust=True)

            if isinstance(server, ServerPool):
                self.server_pool = server
                self.server_pool.initialize(self)
                self.server = self.server_pool.get_current_server(self)
            else:
                self.server_pool = None
                self.server = server

            # if self.authentication == SIMPLE and self.user and self.check_names:
            #     self.user = safe_dn(self.user)
            #     if log_enabled(EXTENDED):
            #         log(EXTENDED, 'user name sanitized to <%s> for simple authentication via <%s>', self.user, self)

            if self.strategy_type == SYNC:
                self.strategy = SyncStrategy(self)
            elif self.strategy_type == SAFE_SYNC:
                self.strategy = SafeSyncStrategy(self)
            elif self.strategy_type == SAFE_RESTARTABLE:
                self.strategy = SafeRestartableStrategy(self)
            elif self.strategy_type == ASYNC:
                self.strategy = AsyncStrategy(self)
            elif self.strategy_type == LDIF:
                self.strategy = LdifProducerStrategy(self)
            elif self.strategy_type == RESTARTABLE:
                self.strategy = RestartableStrategy(self)
            elif self.strategy_type == REUSABLE:
                self.strategy = ReusableStrategy(self)
                self.lazy = False
            elif self.strategy_type == MOCK_SYNC:
                self.strategy = MockSyncStrategy(self)
            elif self.strategy_type == MOCK_ASYNC:
                self.strategy = MockAsyncStrategy(self)
            elif self.strategy_type == ASYNC_STREAM:
                self.strategy = AsyncStreamStrategy(self)
            else:
                self.last_error = 'unknown strategy'
                if log_enabled(ERROR):
                    log(ERROR, '%s for <%s>', self.last_error, self)
                raise LDAPUnknownStrategyError(self.last_error)

            # maps strategy functions to connection functions
            self.send = self.strategy.send
            self.open = self.strategy.open
            self.get_response = self.strategy.get_response
            self.post_send_single_response = self.strategy.post_send_single_response
            self.post_send_search = self.strategy.post_send_search

            if not self.strategy.no_real_dsa:
                self._do_auto_bind()
            # else:  # for strategies with a fake server set get_info to NONE if server hasn't a schema
            #     if self.server and not self.server.schema:
            #         self.server.get_info = NONE
            if log_enabled(BASIC):
                if get_library_log_hide_sensitive_data():
                    log(BASIC, 'instantiated Connection: <%s>', self.repr_with_sensitive_data_stripped())
                else:
                    log(BASIC, 'instantiated Connection: <%r>', self)
Connection.__init__ = __init__

def do_ntlm_bind(self,
                     controls):
        if log_enabled(BASIC):
            log(BASIC, 'start NTLM BIND operation via <%s>', self)
        self.last_error = None
        with self.connection_lock:
            if not self.sasl_in_progress:
                self.sasl_in_progress = True  # ntlm is same of sasl authentication
                try:
                    # additional import for NTLM
                    from ldap3.utils.ntlm import NtlmClient
                    domain_name, user_name = self.user.split('\\', 1)
                    self.ntlm_client = NtlmClient(user_name=user_name, domain=domain_name, password=self.password)
                    if self.session_security == ENCRYPT:
                        self.ntlm_client.confidentiality = True

                    # as per https://msdn.microsoft.com/en-us/library/cc223501.aspx
                    # send a sicilyPackageDiscovery request (in the bindRequest)
                    request = bind_operation(self.version, 'SICILY_PACKAGE_DISCOVERY', self.ntlm_client)
                    if log_enabled(PROTOCOL):
                        log(PROTOCOL, 'NTLM SICILY PACKAGE DISCOVERY request sent via <%s>', self)
                    response = self.post_send_single_response(self.send('bindRequest', request, controls))
                    if not self.strategy.sync:
                        _, result = self.get_response(response)
                    else:
                        result = response[0]
                    if 'server_creds' in result:
                        sicily_packages = result['server_creds'].decode('ascii').split(';')
                        if 'NTLM' in sicily_packages:  # NTLM available on server
                            request = bind_operation(self.version, 'SICILY_NEGOTIATE_NTLM', self.ntlm_client)
                            if log_enabled(PROTOCOL):
                                log(PROTOCOL, 'NTLM SICILY NEGOTIATE request sent via <%s>', self)
                            response = self.post_send_single_response(self.send('bindRequest', request, controls))
                            if not self.strategy.sync:
                                _, result = self.get_response(response)
                            else:
                                if log_enabled(PROTOCOL):
                                    log(PROTOCOL, 'NTLM SICILY NEGOTIATE response <%s> received via <%s>', response[0],
                                        self)
                                result = response[0]

                            if result['result'] == RESULT_SUCCESS:
                                request = bind_operation(self.version, 'SICILY_RESPONSE_NTLM', self.ntlm_client,
                                                         result['server_creds'])
                                if log_enabled(PROTOCOL):
                                    log(PROTOCOL, 'NTLM SICILY RESPONSE NTLM request sent via <%s>', self)
                                response = self.post_send_single_response(self.send('bindRequest', request, controls))
                                if not self.strategy.sync:
                                    _, result = self.get_response(response)
                                else:
                                    if log_enabled(PROTOCOL):
                                        log(PROTOCOL, 'NTLM BIND response <%s> received via <%s>', response[0], self)
                                    result = response[0]
                    else:
                        result = None
                finally:
                    self.sasl_in_progress = False

                if log_enabled(BASIC):
                    log(BASIC, 'done SASL NTLM operation, result <%s>', result)

                return result
Connection.do_ntlm_bind = do_ntlm_bind

from ldap3.protocol.sasl.kerberos import *
from ldap3.protocol.sasl.kerberos import _common_determine_target_name, _common_determine_authz_id_and_creds
def _common_process_end_token_get_security_layers(negotiated_token, session_security=None):
    """ Process the response we got at the end of our SASL negotiation wherein the server told us what
    minimum security layers we need, and return a bytearray for the client security layers we want.
    This function throws an error on a malformed token from the server.
    The ldap3 library does not support security layers, and only supports authentication with kerberos,
    so an error will be thrown for any tokens that indicate a security layer requirement.
    """
    if len(negotiated_token) != 4:
        raise LDAPCommunicationError("Incorrect response from server")

    server_security_layers = negotiated_token[0]
    if not isinstance(server_security_layers, int):
        server_security_layers = ord(server_security_layers)
    if server_security_layers in (0, NO_SECURITY_LAYER):
        if negotiated_token[1:] != '\x00\x00\x00':
            raise LDAPCommunicationError("Server max buffer size must be 0 if no security layer")
    security_layer = CONFIDENTIALITY_PROTECTION if session_security else NO_SECURITY_LAYER 
    if not (server_security_layers & security_layer):
        raise LDAPCommunicationError("Server doesn't support the security level asked")

    # this is here to encourage anyone implementing client security layers to do it
    # for both windows and posix
    client_security_layers = bytearray([security_layer, 0, 0, 0])
    return client_security_layers
ldap3.protocol.sasl.kerberos._common_process_end_token_get_security_layers = _common_process_end_token_get_security_layers

def _posix_sasl_gssapi(connection, controls):
    """ Performs a bind using the Kerberos v5 ("GSSAPI") SASL mechanism
    from RFC 4752 using the gssapi package that works natively on most
    posix operating systems.
    """
    target_name = gssapi.Name(_common_determine_target_name(connection), gssapi.NameType.hostbased_service)
    authz_id, creds = _common_determine_authz_id_and_creds(connection)

    ctx = gssapi.SecurityContext(name=target_name, mech=gssapi.MechType.kerberos, creds=creds,
                                 channel_bindings=get_channel_bindings(connection.socket))
    in_token = None
    try:
        while True:
            out_token = ctx.step(in_token)
            if out_token is None:
                out_token = ''
            result = send_sasl_negotiation(connection, controls, out_token)
            in_token = result['saslCreds']
            try:
                # This raised an exception in gssapi<1.1.2 if the context was
                # incomplete, but was fixed in
                # https://github.com/pythongssapi/python-gssapi/pull/70
                if ctx.complete:
                    break
            except gssapi.exceptions.MissingContextError:
                pass

        unwrapped_token = ctx.unwrap(in_token)
        client_security_layers = _common_process_end_token_get_security_layers(unwrapped_token.message, connection.session_security)
        out_token = ctx.wrap(bytes(client_security_layers)+authz_id, False)
        connection.krb_ctx = ctx
        return send_sasl_negotiation(connection, controls, out_token.message)
    except (gssapi.exceptions.GSSError, LDAPCommunicationError):
        abort_sasl_negotiation(connection, controls)
        raise
ldap3.protocol.sasl.kerberos._posix_sasl_gssapi = _posix_sasl_gssapi

def _windows_sasl_gssapi(connection, controls):
    """ Performs a bind using the Kerberos v5 ("GSSAPI") SASL mechanism
    from RFC 4752 using the winkerberos package that works natively on most
    windows operating systems.
    """
    target_name = _common_determine_target_name(connection)
    # initiation happens before beginning the SASL bind when using windows kerberos
    authz_id, _ = _common_determine_authz_id_and_creds(connection)
    gssflags = (
            winkerberos.GSS_C_MUTUAL_FLAG |
            winkerberos.GSS_C_SEQUENCE_FLAG |
            winkerberos.GSS_C_INTEG_FLAG |
            winkerberos.GSS_C_CONF_FLAG
    )
    _, ctx = winkerberos.authGSSClientInit(target_name, gssflags=gssflags)

    in_token = b''
    try:
        negotiation_complete = False
        while not negotiation_complete:
            # GSSAPI is a "client goes first" SASL mechanism. Send the first "response" to the server and
            # recieve its first challenge.
            # Despite this, we can get channel binding, which includes CBTs for windows environments computed from
            # the peer certificate, before starting.
            status = winkerberos.authGSSClientStep(ctx, base64.b64encode(in_token).decode('utf-8'),
                                                   channel_bindings=get_channel_bindings(connection.socket))
            # figure out if we're done with our sasl negotiation
            negotiation_complete = (status == winkerberos.AUTH_GSS_COMPLETE)
            out_token = winkerberos.authGSSClientResponse(ctx) or ''
            out_token_bytes = base64.b64decode(out_token)
            result = send_sasl_negotiation(connection, controls, out_token_bytes)
            in_token = result['saslCreds'] or b''

        winkerberos.authGSSClientUnwrap(ctx,base64.b64encode(in_token).decode('utf-8'))
        negotiated_token = ''
        if winkerberos.authGSSClientResponse(ctx):
            negotiated_token = base64.standard_b64decode(winkerberos.authGSSClientResponse(ctx))
        client_security_layers = _common_process_end_token_get_security_layers(negotiated_token, connection.session_security)
        # manually construct a message indicating use of authorization-only layer
        # see winkerberos example: https://github.com/mongodb/winkerberos/blob/master/test/test_winkerberos.py
        authz_only_msg = base64.b64encode(bytes(client_security_layers) + authz_id).decode('utf-8')
        winkerberos.authGSSClientWrap(ctx, authz_only_msg)
        out_token = winkerberos.authGSSClientResponse(ctx) or ''
        connection.krb_ctx = ctx
        return send_sasl_negotiation(connection, controls, base64.b64decode(out_token))
    except (winkerberos.GSSError, LDAPCommunicationError):
        abort_sasl_negotiation(connection, controls)
        raise
ldap3.protocol.sasl.kerberos._windows_sasl_gssapi = _windows_sasl_gssapi

from ldap3.strategy.base import *
def sending(self, ldap_message):
    if log_enabled(NETWORK):
        log(NETWORK, 'sending 1 ldap message for <%s>', self.connection)
    try:
        encoded_message = encode(ldap_message)
        if self.connection.sasl_mechanism == DIGEST_MD5 and self.connection._digest_md5_kic and not self.connection.sasl_in_progress:
            # If we are using DIGEST-MD5 and LDAP signing is enabled: add a signature to the message
            sec_num = self.connection._digest_md5_sec_num  # added underscore GC
            kic = self.connection._digest_md5_kic  # lowercase GC
            signature = bytes.fromhex(md5_hmac(kic, int(sec_num).to_bytes(4, 'big') + encoded_message)[0:20])
            payload = encoded_message + signature
            if self.connection._digest_md5_kcc_cipher:
                payload = self.connection._digest_md5_kcc_cipher.encrypt(payload)
            # RFC 2831 sign: encoded_message = sizeOf(encoded_message + signature + 0x0001 + secNum) + encoded_message + signature + 0x0001 + secNum
            # RFC 2831 encrypt: encoded_message = sizeOf(ciphertext + 0x0001 +secNum) + CIPHER(encoded_message + pad + signature) + 0x0001 + secNum
            encoded_message = int(len(payload) + 2 + 4).to_bytes(4, 'big') + payload + int(1).to_bytes(2, 'big') + int(sec_num).to_bytes(4, 'big')
            self.connection._digest_md5_sec_num += 1
        elif self.connection.session_security == ENCRYPT and not self.connection.sasl_in_progress:
            if self.connection.authentication == NTLM:
                # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/115f9c7d-bc30-4262-ae96-254555c14ea6
                encoded_message = self.connection.ntlm_client.seal(encoded_message)
            elif self.connection.sasl_mechanism == GSSAPI:
                if posix_gssapi_unavailable:
                    import winkerberos
                    winkerberos.authGSSClientWrap(self.connection.krb_ctx, base64.b64encode(encoded_message).decode('utf-8'), None, 1)
                    encoded_message = base64.b64decode(winkerberos.authGSSClientResponse(self.connection.krb_ctx))
                else:
                    encoded_message = self.connection.krb_ctx.wrap(encoded_message, True).message
            encoded_message = int(len(encoded_message)).to_bytes(4, 'big') + encoded_message

        self.connection.socket.sendall(encoded_message)
        if log_enabled(EXTENDED):
            log(EXTENDED, 'ldap message sent via <%s>:%s', self.connection, format_ldap_message(ldap_message, '>>'))
        if log_enabled(NETWORK):
            log(NETWORK, 'sent %d bytes via <%s>', len(encoded_message), self.connection)
    except socket.error as e:
        self.connection.last_error = 'socket sending error' + str(e)
        encoded_message = None
        if log_enabled(ERROR):
            log(ERROR, '<%s> for <%s>', self.connection.last_error, self.connection)
        # raise communication_exception_factory(LDAPSocketSendError, exc)(self.connection.last_error)
        raise communication_exception_factory(LDAPSocketSendError, type(e)(str(e)))(self.connection.last_error)
    if self.connection.usage:
        self.connection._usage.update_transmitted_message(self.connection.request, len(encoded_message))
BaseStrategy.sending = sending

from ldap3.strategy.sync import *
def receiving(self):
    """
    Receives data over the socket
    Checks if the socket is closed
    """
    messages = []
    receiving = True
    unprocessed = b''
    data = b''
    get_more_data = True
    # exc = None  # not needed here GC
    sasl_total_bytes_received = 0
    sasl_received_data = b''  # used to verify the signature
    sasl_next_packet = b''
    # sasl_signature = b'' # not needed here? GC
    # sasl_sec_num = b'' # used to verify the signature  # not needed here, reformatted to lowercase GC
    sasl_buffer_length = -1  # added, not initialized? GC
    while receiving:
        if get_more_data:
            try:
                data = self.connection.socket.recv(self.socket_size)
            except (OSError, socket.error, AttributeError) as e:
                self.connection.last_error = 'error receiving data: ' + str(e)
                try:  # try to close the connection before raising exception
                    self.close()
                except (socket.error, LDAPExceptionError):
                    pass
                if log_enabled(ERROR):
                    log(ERROR, '<%s> for <%s>', self.connection.last_error, self.connection)
                # raise communication_exception_factory(LDAPSocketReceiveError, exc)(self.connection.last_error)
                raise communication_exception_factory(LDAPSocketReceiveError, type(e)(str(e)))(self.connection.last_error)

            # If we are using DIGEST-MD5 and LDAP signing is set : verify & remove the signature from the message
            if (self.connection._digest_md5_kis or self.connection.session_security == ENCRYPT) and not self.connection.sasl_in_progress:
                data = sasl_next_packet + data

                if sasl_received_data == b'' or sasl_next_packet:
                    # Remove the sizeOf(encoded_message + signature + 0x0001 + secNum) from data.
                    sasl_buffer_length = int.from_bytes(data[0:4], "big")
                    data = data[4:]
                sasl_next_packet = b''
                sasl_total_bytes_received += len(data)
                sasl_received_data += data

                if sasl_total_bytes_received >= sasl_buffer_length:
                    # When the LDAP response is splitted accross multiple TCP packets, the SASL buffer length is equal to the MTU of each packet..Which is usually not equal to self.socket_size
                    # This means that the end of one SASL packet/beginning of one other....could be located in the middle of data
                    # We are using "sasl_received_data" instead of "data" & "unprocessed" for this reason

                    sasl_next_packet = sasl_received_data[sasl_buffer_length:]  # the last "data" variable may contain another sasl packet. We'll process it at the next iteration.

                    if self.connection.sasl_mechanism == DIGEST_MD5:
                        # structure of messages when LDAP signing is enabled : sizeOf(encoded_message + signature + 0x0001 + secNum) + encoded_message + signature + 0x0001 + secNum
                        sasl_sec_num = sasl_received_data[sasl_buffer_length - 4:sasl_buffer_length]
                        sasl_received_data = sasl_received_data[:sasl_buffer_length-6] # Removing secNum and the message type number to fit also encryption
                        sasl_buffer_length = len(sasl_received_data) # We can do that because len(ciphertext) == len(plaintext) for RC4
                        if self.connection._digest_md5_kcs_cipher:
                            # structure of messages when LDAP encryption is enabled: sizeOf(ciphertext + 0x0001 + secNum) + CIPHER(encoded_message + pad+ signature) + 0x0001 + secNum
                            sasl_received_data = self.connection._digest_md5_kcs_cipher.decrypt(sasl_received_data)
                        sasl_signature = sasl_received_data[sasl_buffer_length - 10:]
                        sasl_received_data = sasl_received_data[:sasl_buffer_length - 10]  # retrieve encoded_message
                        kis = self.connection._digest_md5_kis  # renamed to lowercase GC
                        calculated_signature = bytes.fromhex(md5_hmac(kis, sasl_sec_num + sasl_received_data)[0:20])
                        if sasl_signature != calculated_signature:
                            raise LDAPSignatureVerificationFailedError("Signature verification failed for the recieved LDAP message number " + str(int.from_bytes(sasl_sec_num, 'big')) + ". Expected signature " + calculated_signature.hex() + " but got " + sasl_signature.hex() + ".")

                    elif self.connection.authentication == NTLM:
                        sasl_received_data = self.connection.ntlm_client.unseal(sasl_received_data[:sasl_buffer_length])
                    
                    elif self.connection.sasl_mechanism == GSSAPI:
                        if posix_gssapi_unavailable:
                            import winkerberos
                            winkerberos.authGSSClientUnwrap(self.connection.krb_ctx, base64.b64encode(sasl_received_data[:sasl_buffer_length]).decode('utf-8'))
                            sasl_received_data = base64.b64decode(winkerberos.authGSSClientResponse(self.connection.krb_ctx))
                        else:
                            sasl_received_data = self.connection.krb_ctx.unwrap(sasl_received_data[:sasl_buffer_length]).message
                    
                    sasl_total_bytes_received = 0
                    unprocessed += sasl_received_data
                    sasl_received_data = b''
            else:
                unprocessed += data
        if len(data) > 0:
            length = BaseStrategy.compute_ldap_message_size(unprocessed)
            if length == -1:  # too few data to decode message length
                get_more_data = True
                continue
            if len(unprocessed) < length:
                get_more_data = True
            else:
                if log_enabled(NETWORK):
                    log(NETWORK, 'received %d bytes via <%s>', len(unprocessed[:length]), self.connection)
                messages.append(unprocessed[:length])
                unprocessed = unprocessed[length:]
                get_more_data = False
                if len(unprocessed) == 0:
                    receiving = False
        else:
            receiving = False

    if log_enabled(NETWORK):
        log(NETWORK, 'received %d ldap messages via <%s>', len(messages), self.connection)
    return messages
SyncStrategy.receiving = receiving

from ldap3.utils.ntlm import *
CLIENT = 'CLIENT'
SERVER = 'SERVER'
def __init__(self, domain, user_name, password):
    self.client_config_flags = 0
    self.exported_session_key = None
    self.negotiated_flags = None
    self.user_name = user_name
    self.user_domain = domain
    self.no_lm_response_ntlm_v1 = None
    self.client_blocked = False
    self.client_block_exceptions = []
    self.client_require_128_bit_encryption = None
    self.max_life_time = None
    self.client_signing_key = None
    self.client_handle = None
    self.sequence_number = 0
    self.server_handle = None
    self.server_signing_key = None
    self.integrity = False
    self.replay_detect = False
    self.sequence_detect = False
    self.confidentiality = False
    self.datagram = False
    self.identity = False
    self.client_supplied_target_name = None
    self.client_channel_binding_unhashed = None
    self.unverified_target_name = None
    self._password = password
    self.server_challenge = None
    self.server_target_name = None
    self.server_target_info = None
    self.server_version = None
    self.server_av_netbios_computer_name = None
    self.server_av_netbios_domain_name = None
    self.server_av_dns_computer_name = None
    self.server_av_dns_domain_name = None
    self.server_av_dns_forest_name = None
    self.server_av_target_name = None
    self.server_av_flags = None
    self.server_av_timestamp = None
    self.server_av_single_host_data = None
    self.server_av_channel_bindings = None
    self.server_av_flag_constrained = None
    self.server_av_flag_integrity = None
    self.server_av_flag_target_spn_untrusted = None
    self.current_encoding = None
    self.client_challenge = None
    self.server_target_info_raw = None
NtlmClient.__init__ = __init__

def create_negotiate_message(self):
        """
        Microsoft MS-NLMP 2.2.1.1
        """
        self.reset_client_flags()
        client_flag = [FLAG_REQUEST_TARGET,
                              FLAG_NEGOTIATE_128,
                              FLAG_NEGOTIATE_NTLM,
                              FLAG_NEGOTIATE_ALWAYS_SIGN,
                              FLAG_NEGOTIATE_OEM,
                              FLAG_NEGOTIATE_UNICODE,
                              FLAG_NEGOTIATE_EXTENDED_SESSIONSECURITY]
        if self.confidentiality:
            client_flag.append(FLAG_NEGOTIATE_SEAL)
        self.set_client_flag(client_flag)

        message = NTLM_SIGNATURE  # 8 bytes
        message += pack('<I', NTLM_MESSAGE_TYPE_NTLM_NEGOTIATE)  # 4 bytes
        message += pack('<I', self.client_config_flags)  # 4 bytes
        message += self.pack_field('', 40)  # domain name field  # 8 bytes
        if self.get_client_flag(FLAG_NEGOTIATE_VERSION):  # version 8 bytes - used for debug in ntlm
            message += pack_windows_version(True)
        else:
            message += pack_windows_version(False)
        return message
NtlmClient.create_negotiate_message = create_negotiate_message

def compute_nt_response(self):
        if not self.user_name and not self._password:  # anonymous authentication
            return b''

        self.client_challenge = urandom(8)
        temp = b''
        temp += pack('<B', 1)  # ResponseVersion - 1 byte
        temp += pack('<B', 1)  # HiResponseVersion - 1 byte
        temp += pack('<H', 0)  # Z(2)
        temp += pack('<I', 0)  # Z(4) - total Z(6)
        temp += self.pack_windows_timestamp()  # time - 8 bytes
        temp += self.client_challenge  # random client challenge - 8 bytes
        temp += pack('<I', 0)  # Z(4)
        temp += self.server_target_info_raw
        temp += pack('<I', 0)  # Z(4)
        response_key_nt = self.ntowf_v2()
        nt_proof_str = hmac.new(response_key_nt, self.server_challenge + temp, digestmod=hashlib.md5).digest()
        nt_challenge_response = nt_proof_str + temp
        if self.confidentiality:
            self.exported_session_key = self._kxkey(response_key_nt, nt_proof_str)
            self._sealkey()
            self._signkey()
        return nt_challenge_response
NtlmClient.compute_nt_response = compute_nt_response

def _kxkey(self, response_key_nt, nt_proof_str):
        session_base_key = hmac.new(response_key_nt, nt_proof_str, digestmod=hashlib.md5).digest()
        return session_base_key
setattr(NtlmClient, '_kxkey', _kxkey)

def _sealkey(self):
    from Cryptodome.Cipher import ARC4
    client_sealing_key = hashlib.new('MD5', self.exported_session_key + b'session key to client-to-server sealing key magic constant\x00').digest()
    server_sealing_key = hashlib.new('MD5', self.exported_session_key + b'session key to server-to-client sealing key magic constant\x00').digest()
    self.client_handle = ARC4.new(client_sealing_key)
    self.server_handle = ARC4.new(server_sealing_key)
setattr(NtlmClient, '_sealkey', _sealkey)

def _signkey(self):
    self.client_signing_key = hashlib.new('MD5', self.exported_session_key + b'session key to client-to-server signing key magic constant\x00').digest()
    self.server_signing_key = hashlib.new('MD5', self.exported_session_key + b'session key to server-to-client signing key magic constant\x00').digest()
setattr(NtlmClient, '_signkey', _signkey)

def sign(self, message, seqnum, side=CLIENT):
    signing_key = None
    if side == CLIENT:
        signing_key = self.client_signing_key
    else:
        signing_key = self.server_signing_key
    version = pack("<I", 1)
    checksum = hmac.new(signing_key, seqnum + message, digestmod=hashlib.md5).digest()[:8]
    return version + checksum + seqnum
setattr(NtlmClient, 'sign', sign)

def seal(self, message):
    payload = self.sign(message, pack("<I", self.sequence_number)) + self.client_handle.encrypt(message)
    self.sequence_number += 1
    return payload
setattr(NtlmClient, 'seal', seal)

def unseal(self, sealed_message):
    message = self.server_handle.decrypt(sealed_message[16:])
    calculated_signature = self.sign(message, sealed_message[12:16], SERVER)
    if calculated_signature != sealed_message[:16]:
        raise LDAPSignatureVerificationFailedError("Signature verification failed for the received LDAP message number " + str(self.sequence_number) + ". Expected signature " + sealed_message[:16].hex() + " but got " + calculated_signature.hex() + ".")
    return message
setattr(NtlmClient, 'unseal', unseal)
