# coding=utf-8
import logger

from appilog.common.system.types import ObjectStateHolder
from appilog.common.system.types.vectors import ObjectStateHolderVector

from ip_address_formatting import ipFormatting


def _getOptionalTriggerParameter(parameterName, framework, defaultValue=None):
    value = framework.getDestinationAttribute(parameterName)
    if value and value.lower() == 'na':
        value = defaultValue
    return value

def _addAttributeDecodedIp(vector, list_ip, ca_id, global_id):
    hostOsh = ObjectStateHolder("cc_gnezdo_shd")
    hostOsh.setStringAttribute("global_id", global_id)
    hostOsh.setStringAttribute("ca_id", ca_id)
    hostOsh.setStringAttribute("decoded_ip", ", ".join(list_ip))

    vector.add(hostOsh)


def DiscoveryMain(Framework):
    OSHVResult = ObjectStateHolderVector()

    string_list_ip = list()

    # cc_ip_address
    cc_ip_address_name = Framework.getTriggerCIDataAsList('cc_ip_address_name')
    cc_ip_address_location = Framework.getTriggerCIDataAsList('cc_ip_address_location')

    # IpAddress - Name (key)
    ip = Framework.getDestinationAttribute('ip_addresses')

    description = _getOptionalTriggerParameter('description', Framework)
    firmware = _getOptionalTriggerParameter('firmware', Framework)
    global_id = Framework.getTriggerCIData('global_id')
    model = _getOptionalTriggerParameter('model', Framework)
    name = _getOptionalTriggerParameter('name', Framework)
    rack = _getOptionalTriggerParameter('rack', Framework)
    serial = _getOptionalTriggerParameter('serial', Framework)
    site = _getOptionalTriggerParameter('site', Framework)
    sm_id = _getOptionalTriggerParameter('sm_id', Framework)
    vendor = _getOptionalTriggerParameter('vendor', Framework)
    ca_id = Framework.getDestinationAttribute('ca_id')

    location = "GNEZDO_SHD"

    def _createCCIpAddressCI(ip):

        hostOshMy = ObjectStateHolder("cc_ip_address")
        hostOshMy.setStringAttribute("name", ip)

        multi_flag = False
        location_value = ""
        for i in range(len(cc_ip_address_name)):
            if ip == cc_ip_address_name[i] and location != cc_ip_address_location[i]:
                Framework.reportWarning("Warning! {} the ip address is already among the CI. Met in {}".format(ip, cc_ip_address_location[i]))
                multi_flag = True
                location_value = cc_ip_address_location[i] + ', '
                break

        if multi_flag:
            hostOshMy.setAttribute("ca_multiple_entry", True)
            hostOshMy.setStringAttribute("ca_multiple_entry_location", location_value + location)
        else:
            hostOshMy.setStringAttribute("description", description)
            hostOshMy.setStringAttribute("ca_firmware", firmware)
            hostOshMy.setStringAttribute("ca_global_id", global_id)
            hostOshMy.setStringAttribute("ca_model", model)
            hostOshMy.setStringAttribute("ca_name", name)
            hostOshMy.setStringAttribute("ca_rack", rack)
            hostOshMy.setStringAttribute("ca_serial", serial)
            hostOshMy.setStringAttribute("site", site)
            hostOshMy.setStringAttribute("ca_sm_id", sm_id)
            hostOshMy.setStringAttribute("ca_vendor", vendor)
            hostOshMy.setStringAttribute("ca_location", location)

        OSHVResult.add(hostOshMy)

    try:
        ip_list = None
        if ";" in ip:
            ip_list = ip.split(";")

            # Форматирование каждого элемента
            for i in range(len(ip_list)):
                ip_list[i] = ip_list[i].replace(' ', '')

        result = None
        if ip_list:
            for ip in ip_list:
                result = ipFormatting(ip)
                if result is None:
                    continue

                for clear_ip in result:
                    string_list_ip.append(clear_ip)
                    _createCCIpAddressCI(clear_ip)

            if result is None:
                raise Exception("Bad ip addresses", ip_list)
        else:
            ip_formatted = ip.replace(' ', '')
            result = ipFormatting(ip_formatted)

            if result is None:
                raise Exception("Bad ip address", ip_formatted)

            for clear_ip in result:
                string_list_ip.append(clear_ip)
                _createCCIpAddressCI(clear_ip)

    except:
        raise Exception("Bad ip address", ip)

    _addAttributeDecodedIp(OSHVResult, string_list_ip, ca_id, global_id)

    return OSHVResult