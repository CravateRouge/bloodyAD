from msldap.client import MSLDAPClient
from msldap import logger
from typing import List, Tuple, Dict
from msldap.commons.common import MSLDAPClientStatus
from msldap.protocol.messages import Control


async def clientPagedsearch(
    self,
    query: str,
    attributes: List[str],
    controls: List[Tuple[str, str, str]] = None,
    tree: str = None,
    search_scope: int = 2,
    raw: bool = False,
):
    """
    Performs a paged search on the AD, using the filter and attributes as a normal query does.
        !The LDAP connection MUST be active before invoking this function!

    :param query: LDAP query filter
    :type query: str
    :param attributes: List of requested attributes
    :type attributes: List[str]
    :param controls: additional controls to be passed in the query
    :type controls: dict
    :param tree: Base tree to perform the search on
    :type tree: str
    :param search_scope: LDAP search scope
    :type search_scope: int
    :param raw: Return the attributes without conversion
    :type raw: bool

    :return: Async generator which yields (`dict`, None) tuple on success or (None, `Exception`) on error
    :rtype: Iterator[(:class:`dict`, :class:`Exception`)]

    """
    logger.debug(
        "Paged search, filter: %s attributes: %s" % (query, ",".join(attributes))
    )
    if self._con.status != MSLDAPClientStatus.RUNNING:
        if self._con.status == MSLDAPClientStatus.ERROR:
            print("There was an error in the connection!")
            return

    if tree is None:
        tree = self._tree
    if tree is None:
        raise Exception("BIND first!")
    t = []
    for x in attributes:
        t.append(x.encode())
    attributes = t

    t = []
    if controls is not None:
        for control in controls:
            t.append(
                Control({
                    "controlType": control[0].encode(),
                    "criticality": control[1],
                    "controlValue": control[2],
                })
            )

    controls = t

    async for entry, err in self._con.pagedsearch(
        tree,
        query,
        attributes=attributes,
        size_limit=self.ldap_query_page_size,
        controls=controls,
        rate_limit=self.ldap_query_ratelimit,
        search_scope=search_scope,
        raw=raw,
    ):

        if err is not None:
            yield None, err
            return
        if entry["objectName"] == "" and entry["attributes"] == "":
            # searchresref...
            continue
        # print('et %s ' % entry)
        yield entry, None


MSLDAPClient.pagedsearch = clientPagedsearch


# MODIFICATIONS:
# Add the encode arg to be able to pass already encoded value directly
async def modify(
    self,
    dn: str,
    changes: Dict[str, object],
    controls: Dict[str, object] = None,
    encode=True,
):
    """
            Performs the modify operation.

            :param dn: The DN of the object whose attributes are to be modified
            :type dn: str
            :param changes: Describes the changes to be made on the object. Must be a dictionary of the following format: {'attribute': [('change_type', [value])]}
            :type changes: dict
            :param controls: additional controls to be passed in the query
            :type controls: dict
    :param encode: encode the changes provided before sending them to the server
    :type encode: bool
            :return: A tuple of (True, None) on success or (False, Exception) on error.
            :rtype: (:class:`bool`, :class:`Exception`)
    """
    if controls is None:
        controls = []
    controls_conv = []
    for control in controls:
        controls_conv.append(Control(control))
    return await self._con.modify(dn, changes, controls=controls_conv, encode=encode)


MSLDAPClient.modify = modify


import asyncio
from msldap.protocol.messages import (
    LDAPMessage,
    BindRequest,
    protocolOp,
    AuthenticationChoice,
    SaslCredentials,
    SearchRequest,
    AttributeDescription,
    Filter,
    Filters,
    Controls,
    Control,
    SearchControlValue,
    AddRequest,
    ModifyRequest,
    DelRequest,
    ExtendedRequest,
    ExtendedResponse,
)
from msldap.commons.exceptions import (
    LDAPBindException,
    LDAPAddException,
    LDAPModifyException,
    LDAPDeleteException,
    LDAPSearchException,
)
from msldap.connection import MSLDAPClientConnection
from msldap.protocol.typeconversion import (
    MSLDAP_BUILTIN_ATTRIBUTE_TYPES,
    LDAP_WELL_KNOWN_ATTRS,
)


def convert_attributes(x, raw=False):
    t = {}
    for e in x:
        # print(e)
        k = e["type"].decode()
        # print('k: %s' % k)
        if raw:
            t[k] = e["attributes"]
        else:
            if k in MSLDAP_BUILTIN_ATTRIBUTE_TYPES:
                t[k] = MSLDAP_BUILTIN_ATTRIBUTE_TYPES[k](e["attributes"], False)
            elif k in LDAP_WELL_KNOWN_ATTRS:
                t[k] = LDAP_WELL_KNOWN_ATTRS[k](e["attributes"], False)
            else:
                logger.debug("Unknown type! %s data: %s" % (k, e["attributes"]))
                t[k] = e["attributes"]
    return t


def convert_result(x, raw=False):
    # print(x)
    # import traceback
    # traceback.print_stack()
    return {
        "objectName": x["objectName"].decode(),
        "attributes": convert_attributes(x["attributes"], raw),
    }


async def pagedsearch(
    self,
    base: str,
    query: str,
    attributes: List[str],
    search_scope: int = 2,
    size_limit: int = 1000,
    typesOnly: bool = False,
    derefAliases: bool = 0,
    timeLimit: int = None,
    controls: List[Control] = None,
    rate_limit: int = 0,
    raw: bool = False,
):
    """
    Paged search is the same as the search operation and uses it under the hood. Adds automatic control to read all results in a paged manner.

    :param base: base tree on which the search should be performed
    :type base: str
    :param query: filter query that defines what should be searched for
    :type query: str
    :param attributes: a list of attributes to be included in the response
    :type attributes: List[str]
    :param search_scope: Specifies the search operation's scope. Default: 2 (Subtree)
    :type search_scope: int
    :param types_only: indicates whether the entries returned should include attribute types only or both types and values. Default: False (both)
    :type types_only: bool
    :param size_limit: Size limit of result elements per query. Default: 1000
    :type size_limit: int
    :param derefAliases: Specifies the behavior on how aliases are dereferenced. Default: 0 (never)
    :type derefAliases: int
    :param timeLimit: Maximum time the search should take. If time limit reached the server SHOULD return an error
    :type timeLimit: int
    :param controls: additional controls to be passed in the query
    :type controls: dict
    :param rate_limit: time to sleep bwetween each query
    :type rate_limit: float
    :param raw: Return the attributes without conversion
    :type raw: bool

    :return: Async generator which yields (`dict`, None) tuple on success or (None, `Exception`) on error
    :rtype: Iterator[(:class:`dict`, :class:`Exception`)]
    """

    if self.status != MSLDAPClientStatus.RUNNING:
        yield None, Exception("Connection not running! Probably encountered an error")
        return
    try:
        cookie = b""
        while True:
            await asyncio.sleep(rate_limit)
            ctrl_list_temp = [
                Control({
                    "controlType": b"1.2.840.113556.1.4.319",
                    "controlValue": SearchControlValue({
                        "size": size_limit, "cookie": cookie
                    }).dump(),
                })
            ]
            if controls is not None:
                ctrl_list_temp.extend(controls)

            ctrs = Controls(ctrl_list_temp)

            async for res, err in self.search(
                base,
                query,
                attributes,
                search_scope=search_scope,
                size_limit=size_limit,
                types_only=typesOnly,
                derefAliases=derefAliases,
                timeLimit=timeLimit,
                controls=ctrs,
                return_done=True,
            ):
                if err is not None:
                    yield (None, err)
                    return

                if "resultCode" in res["protocolOp"]:
                    if res["protocolOp"]["resultCode"] != "success":
                        raise LDAPSearchException(
                            res["protocolOp"]["resultCode"],
                            res["protocolOp"]["diagnosticMessage"],
                        )
                    try:
                        for control in res["controls"]:
                            if control["controlType"] == b"1.2.840.113556.1.4.319":
                                try:
                                    cookie = SearchControlValue.load(
                                        control["controlValue"]
                                    ).native["cookie"]
                                except Exception as e:
                                    raise e
                                break
                    except TypeError:
                        pass
                        # Is it really important that SearchControl is missing?
                        # raise Exception("SearchControl missing from server response!")
                else:
                    yield (convert_result(res["protocolOp"], raw), None)

            if cookie == b"":
                break

    except Exception as e:
        yield (None, e)


MSLDAPClientConnection.pagedsearch = pagedsearch

from msldap.protocol.typeconversion import (
    MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC,
    MSLDAP_BUILTIN_ATTRIBUTE_TYPES,
    LDAP_WELL_KNOWN_ATTRS,
    multi_bytes,
    single_bytes,
)
from msldap.protocol.messages import Attribute, Change, PartialAttribute


# MODIFICATIONS:
# Replacing all single by multi because we doesn't need to ensure only one change has been provided for single attributes, the server will tell it for us.
# Handle raw changes values with encode param
def encode_changes(x, encode=True):
    logger.debug("Encode changes: %s" % x)
    res = []
    for k in x:
        lookup_table = None
        if k in MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC:
            lookup_table = MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC
        elif k in MSLDAP_BUILTIN_ATTRIBUTE_TYPES:
            lookup_table = MSLDAP_BUILTIN_ATTRIBUTE_TYPES
        elif k in LDAP_WELL_KNOWN_ATTRS:
            lookup_table = LDAP_WELL_KNOWN_ATTRS
        else:
            raise Exception('Unknown conversion type for key "%s"' % k)

        for mod, value in x[k]:
            encoder = lookup_table[k]
            splitted_name = encoder.__name__.split("_")
            if isinstance(value, list) and "single" == splitted_name[0]:
                if len(value) > 1:
                    raise TypeError(
                        f"{k} takes only one value but multiple values have been given."
                    )
                value = value[0]
            if not encode and splitted_name[1] != ["bytes"]:
                if splitted_name[0] == "single":
                    encoder = single_bytes
                else:
                    encoder = multi_bytes
            res.append(
                Change({
                    "operation": mod,
                    "modification": PartialAttribute({
                        "type": k.encode(), "attributes": encoder(value, True)
                    }),
                })
            )
            # print(lookup_table[k](value, True))
    return res


# MODIFICATIONS:
# Add the encode arg to be able to pass already encoded value directly
async def modify(
    self,
    entry: str,
    changes: Dict[str, object],
    controls: List[Control] = None,
    encode=True,
):
    """
    Performs the modify operation.

    :param entry: The DN of the object whose attributes are to be modified
    :type entry: str
    :param changes: Describes the changes to be made on the object. Must be a dictionary of the following format: {'attribute': [('change_type', [value])]}
    :type changes: dict
    :param controls: additional controls to be passed in the query
    :type controls: List[class:`Control`]
    :param encode: encode the changes provided before sending them to the server
    :type encode: bool
    :return: A tuple of (True, None) on success or (False, Exception) on error.
    :rtype: (:class:`bool`, :class:`Exception`)
    """
    try:
        req = {"object": entry.encode(), "changes": encode_changes(changes, encode)}
        br = {"modifyRequest": ModifyRequest(req)}
        msg = {"protocolOp": protocolOp(br)}
        if controls is not None:
            msg["controls"] = controls

        msg_id = await self.send_message(msg)
        results = await self.recv_message(msg_id)
        if isinstance(results[0], Exception):
            return False, results[0]

        for message in results:
            msg_type = message["protocolOp"].name
            message = message.native
            if msg_type == "modifyResponse":
                if message["protocolOp"]["resultCode"] != "success":
                    return False, LDAPModifyException(
                        entry,
                        message["protocolOp"]["resultCode"],
                        message["protocolOp"]["diagnosticMessage"],
                    )

        return True, None
    except Exception as e:
        return False, e


MSLDAPClientConnection.modify = modify


def encode_attributes(x):
    """converts a dict to attributelist"""
    res = []
    for k in x:
        lookup_table = None
        if k in MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC:
            lookup_table = MSLDAP_BUILTIN_ATTRIBUTE_TYPES_ENC
        elif k in MSLDAP_BUILTIN_ATTRIBUTE_TYPES:
            lookup_table = MSLDAP_BUILTIN_ATTRIBUTE_TYPES
        elif k in LDAP_WELL_KNOWN_ATTRS:
            lookup_table = LDAP_WELL_KNOWN_ATTRS
        else:
            raise Exception('Unknown conversion type for key "%s"' % k)

        res.append(
            Attribute({"type": k.encode(), "attributes": lookup_table[k](x[k], True)})
        )

    return res


async def add(self, entry: str, attributes: Dict[str, object]):
    """
    Performs the add operation.

    :param entry: The DN of the object to be added
    :type entry: str
    :param attributes: Attributes to be used in the operation
    :type attributes: dict
    :return: A tuple of (True, None) on success or (False, Exception) on error.
    :rtype: (:class:`bool`, :class:`Exception`)
    """
    try:
        req = {"entry": entry.encode(), "attributes": encode_attributes(attributes)}
        logger.debug(req)
        br = {"addRequest": AddRequest(req)}
        msg = {"protocolOp": protocolOp(br)}

        msg_id = await self.send_message(msg)
        results = await self.recv_message(msg_id)
        if isinstance(results[0], Exception):
            return False, results[0]

        for message in results:
            msg_type = message["protocolOp"].name
            message = message.native
            if msg_type == "addResponse":
                if message["protocolOp"]["resultCode"] != "success":
                    return False, LDAPAddException(
                        entry,
                        message["protocolOp"]["resultCode"],
                        message["protocolOp"]["diagnosticMessage"],
                    )

        return True, None
    except Exception as e:
        return False, e


MSLDAPClientConnection.add = add
