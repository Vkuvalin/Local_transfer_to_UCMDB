# coding=utf-8
import logger

from appilog.common.system.types import ObjectStateHolder
from appilog.common.system.types.vectors import ObjectStateHolderVector
from ip_address_formatting import ipFormatting


ip_addresses = dict()
def ipAddressesAddDict(list_ip_addresses, location):
    for ip in list_ip_addresses:
        ip_addresses[ip] = ip_addresses.get(ip, [0, ""])
        ip_addresses[ip][0] += 1

        if ip_addresses[ip][1] == "":
            ip_addresses[ip][1] = location
        else:
            if location not in ip_addresses[ip][1]:
                ip_addresses[ip][1] = "{}, {}".format(ip_addresses[ip][1], location)


def parseListCcIpAddresses(framework):
    list_name_cc_ip_addresses = framework.getTriggerCIDataAsList('cc_ip_address_name')
    list_location_cc_ip_address = framework.getTriggerCIDataAsList('cc_ip_address_location')

    for i in range(len(list_name_cc_ip_addresses)):
        if list_location_cc_ip_address[i] == "UCMDB":
            ipAddressesAddDict(list_name_cc_ip_addresses[i].split(), list_location_cc_ip_address[i])


def _verificationParameter(parameterName, defaultValue=None):
    value = parameterName
    if value and value.lower() == 'na':
        value = defaultValue
    return value


def incomingDataProcessing(framework, ip_array, create_function, location):
    for num in range(len(ip_array)):
        ip = ip_array[num]
        try:
            ip_list = None
            if ";" in ip:
                ip_list = ip.split(";")

                for i in range(len(ip_list)):
                    ip_list[i] = ip_list[i].replace(' ', '')

            result = None
            if ip_list:
                for ip in ip_list:

                    result = ipFormatting(ip)
                    if result is None:
                        continue

                    ipAddressesAddDict(result, location)
                    for clear_ip in result:
                        create_function(clear_ip, num)

                if result is None:
                    framework.reportWarning("Bad ip addresses - {}".format(ip_list))

            else:
                ip_formatted = ip.replace(' ', '')
                result = ipFormatting(ip_formatted)

                if result is None:
                    framework.reportWarning("Bad ip address - {}".format(ip_formatted))
                    continue

                ipAddressesAddDict(result, location)
                for clear_ip in result:
                    create_function(clear_ip, num)

        except:
            framework.reportWarning("Bad ip address - {}.".format(ip))


def DiscoveryMain(Framework):
    OSHVResult = ObjectStateHolderVector()

    # Наполняет dict идентифицированными ip'адресами из cc_ip_address
    parseListCcIpAddresses(Framework)

    # HOST_OS
    host_os_ip = Framework.getTriggerCIDataAsList('host_os_ip')

    host_os_description = Framework.getTriggerCIDataAsList('host_os_description')
    host_os_global_id = Framework.getTriggerCIDataAsList('host_os_global_id')
    host_os_model = Framework.getTriggerCIDataAsList('host_os_model')
    host_os_os_name = Framework.getTriggerCIDataAsList('host_os_os_name')
    host_os_name = Framework.getTriggerCIDataAsList('host_os_name')
    host_os_serial = Framework.getTriggerCIDataAsList('host_os_serial')
    host_os_sm_id = Framework.getTriggerCIDataAsList('host_os_sm_id')
    host_os_vendor = Framework.getTriggerCIDataAsList('host_os_vendor')
    host_os_dns_name = Framework.getTriggerCIDataAsList('host_os_dns_name')

    host_os_location = "GNEZDO_HOST_OS"

    def _createCCIpAddressHostOs(ip, num):
        hostOsh = ObjectStateHolder("cc_ip_address")
        hostOsh.setStringAttribute("name", ip)

        if ip_addresses[ip][0] > 1:
            hostOsh.setAttribute("ca_multiple_entry", True)
            hostOsh.setStringAttribute("ca_multiple_entry_location", ip_addresses[ip][1])
        else:
            hostOsh.setStringAttribute("description", _verificationParameter(host_os_description[num]))
            hostOsh.setStringAttribute("ca_global_id", _verificationParameter(host_os_global_id[num]))
            hostOsh.setStringAttribute("ca_model", _verificationParameter(host_os_model[num]))
            hostOsh.setStringAttribute("ca_node_os_name", _verificationParameter(host_os_os_name[num]))
            hostOsh.setStringAttribute("ca_name", _verificationParameter(host_os_name[num]))
            hostOsh.setStringAttribute("ca_serial", _verificationParameter(host_os_serial[num]))
            hostOsh.setStringAttribute("ca_sm_id", _verificationParameter(host_os_sm_id[num]))
            hostOsh.setStringAttribute("ca_node_os_vendor", _verificationParameter(host_os_vendor[num]))
            hostOsh.setStringAttribute("ca_primary_dns_name", _verificationParameter(host_os_dns_name[num]))

            if _verificationParameter(host_os_model[num]) and _verificationParameter(host_os_vendor[num]):
                hostOsh.setAttribute("ca_identification", True)

            hostOsh.setStringAttribute("ca_location", host_os_location)

        OSHVResult.add(hostOsh)


    # SAN
    san_ip = Framework.getTriggerCIDataAsList('san_ip')

    san_description = Framework.getTriggerCIDataAsList('san_description')
    san_firmware = Framework.getTriggerCIDataAsList('san_firmware')
    san_global_id = Framework.getTriggerCIDataAsList('san_global_id')
    san_model = Framework.getTriggerCIDataAsList('san_model')
    san_name = Framework.getTriggerCIDataAsList('san_name')
    san_rack = Framework.getTriggerCIDataAsList('san_rack')
    san_serial = Framework.getTriggerCIDataAsList('san_serial')
    san_site = Framework.getTriggerCIDataAsList('san_site')
    san_sm_id = Framework.getTriggerCIDataAsList('san_sm_id')
    san_vendor = Framework.getTriggerCIDataAsList('san_vendor')
    san_bucket = Framework.getTriggerCIDataAsList('san_bucket')
    san_config = Framework.getTriggerCIDataAsList('san_config')

    san_location = "GNEZDO_SAN"

    def _createCCIpAddressSan(ip, num):

        hostOsh = ObjectStateHolder("cc_ip_address")
        hostOsh.setStringAttribute("name", ip)

        if ip_addresses[ip][0] > 1:
            hostOsh.setAttribute("ca_multiple_entry", True)
            hostOsh.setStringAttribute("ca_multiple_entry_location", ip_addresses[ip][1])
        else:
            hostOsh.setStringAttribute("description", _verificationParameter(san_description[num]))
            hostOsh.setStringAttribute("ca_firmware", _verificationParameter(san_firmware[num]))
            hostOsh.setStringAttribute("ca_global_id", _verificationParameter(san_global_id[num]))
            hostOsh.setStringAttribute("ca_model", _verificationParameter(san_model[num]))
            hostOsh.setStringAttribute("ca_name", _verificationParameter(san_name[num]))
            hostOsh.setStringAttribute("ca_rack", _verificationParameter(san_rack[num]))
            hostOsh.setStringAttribute("ca_serial", _verificationParameter(san_serial[num]))
            hostOsh.setStringAttribute("site", _verificationParameter(san_site[num]))
            hostOsh.setStringAttribute("ca_sm_id", _verificationParameter(san_sm_id[num]))
            hostOsh.setStringAttribute("ca_vendor", _verificationParameter(san_vendor[num]))
            hostOsh.setStringAttribute("ca_bucket", _verificationParameter(san_bucket[num]))
            hostOsh.setStringAttribute("ca_config", _verificationParameter(san_config[num]))

            if _verificationParameter(san_model[num]) and _verificationParameter(san_vendor[num]):
                hostOsh.setAttribute("ca_identification", True)

            hostOsh.setStringAttribute("ca_location", san_location)

        OSHVResult.add(hostOsh)


    # SERVER
    server_ip = Framework.getTriggerCIDataAsList('server_ip')

    server_datacenter = Framework.getTriggerCIDataAsList('server_datacenter')
    server_dcroom = Framework.getTriggerCIDataAsList('server_dcroom')
    server_description = Framework.getTriggerCIDataAsList('server_description')
    server_dns_name = Framework.getTriggerCIDataAsList('server_dns_name')
    server_global_id = Framework.getTriggerCIDataAsList('server_global_id')
    server_ids = Framework.getTriggerCIDataAsList('server_ids')
    server_interface = Framework.getTriggerCIDataAsList('server_interface')
    server_model = Framework.getTriggerCIDataAsList('server_model')
    server_name = Framework.getTriggerCIDataAsList('server_name')
    server_rack = Framework.getTriggerCIDataAsList('server_rack')
    server_serial = Framework.getTriggerCIDataAsList('server_serial')
    server_vendor = Framework.getTriggerCIDataAsList('server_vendor')

    server_location = "GNEZDO_SERVER"

    def _createCCIpAddressServer(ip, num):

        hostOsh = ObjectStateHolder("cc_ip_address")
        hostOsh.setStringAttribute("name", ip)

        if ip_addresses[ip][0] > 1:
            hostOsh.setAttribute("ca_multiple_entry", True)
            hostOsh.setStringAttribute("ca_multiple_entry_location", ip_addresses[ip][1])
        else:
            hostOsh.setStringAttribute("ca_datacenter", _verificationParameter(server_datacenter[num]))
            hostOsh.setStringAttribute("ca_dcroom", _verificationParameter(server_dcroom[num]))
            hostOsh.setStringAttribute("description", _verificationParameter(server_description[num]))
            hostOsh.setStringAttribute("ca_primary_dns_name", _verificationParameter(server_dns_name[num]))
            hostOsh.setStringAttribute("ca_global_id", _verificationParameter(server_global_id[num]))
            hostOsh.setStringAttribute("ca_ids", _verificationParameter(server_ids[num]))
            hostOsh.setStringAttribute("ca_interface", _verificationParameter(server_interface[num]))
            hostOsh.setStringAttribute("ca_model", _verificationParameter(server_model[num]))
            hostOsh.setStringAttribute("ca_name", _verificationParameter(server_name[num]))
            hostOsh.setStringAttribute("ca_rack", _verificationParameter(server_rack[num]))
            hostOsh.setStringAttribute("ca_serial", _verificationParameter(server_serial[num]))
            hostOsh.setStringAttribute("ca_vendor", _verificationParameter(server_vendor[num]))

            if _verificationParameter(server_model[num]) and _verificationParameter(server_vendor[num]):
                hostOsh.setAttribute("ca_identification", True)

            hostOsh.setStringAttribute("ca_location", server_location)

        OSHVResult.add(hostOsh)


    # SHD
    shd_ip = Framework.getTriggerCIDataAsList('shd_ip')

    shd_description = Framework.getTriggerCIDataAsList('shd_description')
    shd_firmware = Framework.getTriggerCIDataAsList('shd_firmware')
    shd_global_id = Framework.getTriggerCIDataAsList('shd_global_id')
    shd_model = Framework.getTriggerCIDataAsList('shd_model')
    shd_name = Framework.getTriggerCIDataAsList('shd_name')
    shd_rack = Framework.getTriggerCIDataAsList('shd_rack')
    shd_serial = Framework.getTriggerCIDataAsList('shd_serial')
    shd_site = Framework.getTriggerCIDataAsList('shd_site')
    shd_sm_id = Framework.getTriggerCIDataAsList('shd_sm_id')
    shd_vendor = Framework.getTriggerCIDataAsList('shd_vendor')

    shd_location = "GNEZDO_SHD"

    def _createCCIpAddressShd(ip, num):
        hostOsh = ObjectStateHolder("cc_ip_address")
        hostOsh.setStringAttribute("name", ip)

        if ip_addresses[ip][0] > 1:
            hostOsh.setAttribute("ca_multiple_entry", True)
            hostOsh.setStringAttribute("ca_multiple_entry_location", ip_addresses[ip][1])
        else:
            hostOsh.setStringAttribute("description", _verificationParameter(shd_description[num]))
            hostOsh.setStringAttribute("ca_firmware", _verificationParameter(shd_firmware[num]))
            hostOsh.setStringAttribute("ca_global_id", _verificationParameter(shd_global_id[num]))
            hostOsh.setStringAttribute("ca_model", _verificationParameter(shd_model[num]))
            hostOsh.setStringAttribute("ca_name", _verificationParameter(shd_name[num]))
            hostOsh.setStringAttribute("ca_rack", _verificationParameter(shd_rack[num]))
            hostOsh.setStringAttribute("ca_serial", _verificationParameter(shd_serial[num]))
            hostOsh.setStringAttribute("site", _verificationParameter(shd_site[num]))
            hostOsh.setStringAttribute("ca_sm_id", _verificationParameter(shd_sm_id[num]))
            hostOsh.setStringAttribute("ca_vendor", _verificationParameter(shd_vendor[num]))

            if _verificationParameter(shd_model[num]) and _verificationParameter(shd_vendor[num]):
                hostOsh.setAttribute("ca_identification", True)

            hostOsh.setStringAttribute("ca_location", shd_location)

        OSHVResult.add(hostOsh)


    # SRK
    srk_ip = Framework.getTriggerCIDataAsList('srk_ip')

    srk_config = Framework.getTriggerCIDataAsList('srk_config')
    srk_description = Framework.getTriggerCIDataAsList('srk_description')
    srk_dns_name = Framework.getTriggerCIDataAsList('srk_dns_name')
    srk_firmware = Framework.getTriggerCIDataAsList('srk_firmware')
    srk_global_id = Framework.getTriggerCIDataAsList('srk_global_id')
    srk_model = Framework.getTriggerCIDataAsList('srk_model')
    srk_name = Framework.getTriggerCIDataAsList('srk_name')
    srk_rack = Framework.getTriggerCIDataAsList('srk_rack')
    srk_serial = Framework.getTriggerCIDataAsList('srk_serial')
    srk_site = Framework.getTriggerCIDataAsList('srk_site')
    srk_vendor = Framework.getTriggerCIDataAsList('srk_vendor')

    srk_location = "GNEZDO_SRK"

    def _createCCIpAddressSrk(ip, num):

        hostOsh = ObjectStateHolder("cc_ip_address")
        hostOsh.setStringAttribute("name", ip)

        if ip_addresses[ip][0] > 1:
            hostOsh.setAttribute("ca_multiple_entry", True)
            hostOsh.setStringAttribute("ca_multiple_entry_location", ip_addresses[ip][1])
        else:
            hostOsh.setStringAttribute("ca_config", _verificationParameter(srk_config[num]))
            hostOsh.setStringAttribute("description", _verificationParameter(srk_description[num]))
            hostOsh.setStringAttribute("ca_primary_dns_name", _verificationParameter(srk_dns_name[num]))
            hostOsh.setStringAttribute("ca_firmware", _verificationParameter(srk_firmware[num]))
            hostOsh.setStringAttribute("ca_global_id", _verificationParameter(srk_global_id[num]))
            hostOsh.setStringAttribute("ca_model", _verificationParameter(srk_model[num]))
            hostOsh.setStringAttribute("ca_name", _verificationParameter(srk_name[num]))
            hostOsh.setStringAttribute("ca_rack", _verificationParameter(srk_rack[num]))
            hostOsh.setStringAttribute("ca_serial", _verificationParameter(srk_serial[num]))
            hostOsh.setStringAttribute("site", _verificationParameter(srk_site[num]))
            hostOsh.setStringAttribute("ca_vendor", _verificationParameter(srk_vendor[num]))

            if _verificationParameter(srk_model[num]) and _verificationParameter(srk_vendor[num]):
                hostOsh.setAttribute("ca_identification", True)

            hostOsh.setStringAttribute("ca_location", srk_location)

        OSHVResult.add(hostOsh)


    # VRM
    vrm_ip = Framework.getTriggerCIDataAsList('vrm_ip')

    vrm_description = Framework.getTriggerCIDataAsList('vrm_description')
    vrm_global_id = Framework.getTriggerCIDataAsList('vrm_global_id')
    vrm_name = Framework.getTriggerCIDataAsList('vrm_name')
    vrm_os_name = Framework.getTriggerCIDataAsList('vrm_os_name')
    vrm_serial = Framework.getTriggerCIDataAsList('vrm_serial')
    vrm_vendor = Framework.getTriggerCIDataAsList('vrm_vendor')

    vrm_location = "GNEZDO_VRM"

    def _createCCIpAddressVrm(ip, num):

        hostOsh = ObjectStateHolder("cc_ip_address")
        hostOsh.setStringAttribute("name", ip)

        if ip_addresses[ip][0] > 1:
            hostOsh.setAttribute("ca_multiple_entry", True)
            hostOsh.setStringAttribute("ca_multiple_entry_location", ip_addresses[ip][1])
        else:
            hostOsh.setStringAttribute("description", _verificationParameter(vrm_description[num]))
            hostOsh.setStringAttribute("ca_global_id", _verificationParameter(vrm_global_id[num]))
            hostOsh.setStringAttribute("ca_name", _verificationParameter(vrm_name[num]))
            hostOsh.setStringAttribute("ca_node_os_name", _verificationParameter(vrm_os_name[num]))
            hostOsh.setStringAttribute("ca_serial", _verificationParameter(vrm_serial[num]))
            hostOsh.setStringAttribute("ca_vendor", _verificationParameter(vrm_vendor[num]))

            # Или тогда как?
            if _verificationParameter(vrm_os_name[num]) and _verificationParameter(vrm_vendor[num]):
                hostOsh.setAttribute("ca_identification", True)

            hostOsh.setStringAttribute("ca_location", vrm_location)

        OSHVResult.add(hostOsh)


    incomingDataProcessing(Framework, host_os_ip, _createCCIpAddressHostOs, host_os_location)
    incomingDataProcessing(Framework, san_ip, _createCCIpAddressSan, san_location)
    incomingDataProcessing(Framework, server_ip, _createCCIpAddressServer, server_location)
    incomingDataProcessing(Framework, shd_ip, _createCCIpAddressShd, shd_location)
    incomingDataProcessing(Framework, srk_ip, _createCCIpAddressSrk, srk_location)
    incomingDataProcessing(Framework, vrm_ip, _createCCIpAddressVrm, vrm_location)
    logger.debug('Process completed')

    for i in range(0, OSHVResult.size(), 15000):
        limit = (i + 15000) if limit >= OSHVResult.size() else OSHVResult.size()

        vector = OSHVResult.getSubVector(i, limit)
        Framework.sendObjects(vector)
        Framework.flushObjects()
        vector.clear()

    return None