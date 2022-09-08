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

def getParametr(parameterName, num):
    return None if parameterName == 'NA' else parameterName[num]

def getDomain(dns, defaultValue=None):
    if not dns.replace('.', '').isdigit() and '.' in dns:
        return dns[dns.find('.')+1:]
    else:
        return defaultValue

def _createCCIpAddress(ip_ci, num, OSHVResult, description='NA', ca_global_id='NA', ca_model='NA', ca_node_os_name='NA',
             ca_name='NA', ca_serial='NA', ca_sm_id='NA', ca_node_os_vendor='NA', ca_primary_dns_name='NA',
             ca_device_type='NA', ca_firmware='NA', ca_rack='NA', site='NA', ca_vendor='NA',
             ca_bucket='NA', ca_config='NA', ca_datacenter='NA', ca_dcroom='NA',
             ca_interface='NA', ca_location='NA', ca_ids='NA'):


    hostOsh = ObjectStateHolder("cc_ip_address")
    hostOsh.setStringAttribute("name", ip_ci)
    if ip_addresses[ip_ci][0] > 1:
        hostOsh.setAttribute("ca_multiple_entry", True)
        hostOsh.setStringAttribute("ca_multiple_entry_location", ip_addresses[ip_ci][1])
    else:
        hostOsh.setStringAttribute("ca_primary_dns_name", None if ca_primary_dns_name == 'NA' else ca_primary_dns_name[num])
        hostOsh.setStringAttribute("ca_primary_dns_name", getParametr(ca_primary_dns_name, num))
        hostOsh.setStringAttribute("ca_node_os_vendor", getParametr(ca_node_os_vendor, num))
        hostOsh.setStringAttribute("ca_device_type", ca_device_type)
        hostOsh.setStringAttribute("ca_firmware", getParametr(ca_firmware, num))
        hostOsh.setStringAttribute("ca_rack", getParametr(ca_rack, num))
        hostOsh.setStringAttribute("site", getParametr(site, num))
        hostOsh.setStringAttribute("ca_ids", getParametr(ca_ids, num))
        hostOsh.setStringAttribute("ca_name", getParametr(ca_name, num))
        hostOsh.setStringAttribute("ca_vendor", getParametr(ca_vendor, num))
        hostOsh.setStringAttribute("ca_bucket", getParametr(ca_bucket, num))
        hostOsh.setStringAttribute("ca_config", getParametr(ca_config, num))
        hostOsh.setStringAttribute("ca_dcroom", getParametr(ca_dcroom, num))
        hostOsh.setStringAttribute("ca_serial", getParametr(ca_serial, num))
        hostOsh.setStringAttribute("ca_model", getParametr(ca_model, num))
        hostOsh.setStringAttribute("ca_sm_id", getParametr(ca_sm_id, num))
        hostOsh.setStringAttribute("ca_interface", getParametr(ca_interface, num))
        hostOsh.setStringAttribute("description", getParametr(description, num))
        hostOsh.setStringAttribute("ca_global_id", getParametr(ca_global_id, num))
        hostOsh.setStringAttribute("ca_datacenter", getParametr(ca_datacenter, num))
        hostOsh.setStringAttribute("ca_node_os_name", getParametr(ca_node_os_name, num))

        if getParametr(ca_primary_dns_name, num):
            domain = getDomain(getParametr(ca_primary_dns_name, num))
            hostOsh.setStringAttribute("ca_domain", domain)
        if getParametr(ca_sm_id, num):
            hostOsh.setAttribute("ca_identification", True)

        hostOsh.setStringAttribute("ca_location", ca_location)

    OSHVResult.add(hostOsh)


def incomingDataProcessing(framework, ip_array, location, OSHVResult, **sort):
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
                        _createCCIpAddress(clear_ip, num, OSHVResult, **sort)

                if result is None:
                    framework.reportWarning("From {}. Bad ip addresses - {}".format(location, ip_list))

            else:
                ip_formatted = ip.replace(' ', '')
                result = ipFormatting(ip_formatted)
                if result is None:
                    framework.reportWarning("From {}. Bad ip address - {}".format(location, ip_formatted))
                    continue

                ipAddressesAddDict(result, location)
                for clear_ip in result:
                    _createCCIpAddress(clear_ip, num, OSHVResult, **sort)

        except:
            framework.reportWarning("From {}. Bad ip address - {}".format(location, ip))


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
    host_device_type = 'Хост ОС'
    host_os_location = "GNEZDO_HOST_OS"

    incomingDataProcessing(Framework, host_os_ip, host_os_location, OSHVResult, description=host_os_description,
                           ca_global_id=host_os_global_id, ca_model=host_os_model, ca_node_os_name=host_os_os_name,
                           ca_sm_id=host_os_sm_id, ca_node_os_vendor=host_os_vendor,
                           ca_primary_dns_name=host_os_dns_name,
                           ca_location=host_os_location, ca_name=host_os_name, ca_serial=host_os_serial,
                           ca_device_type=host_device_type)


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
    san_device_type = 'Коммутатор SAN'
    san_location = "GNEZDO_SAN"

    incomingDataProcessing(Framework, san_ip, san_location, OSHVResult, ca_location=san_location,
                           description=san_description, ca_global_id=san_global_id, ca_model=san_model, ca_name=san_name,
                           ca_rack=san_rack, ca_serial=san_serial, ca_sm_id=san_sm_id, ca_device_type=san_device_type,
                           ca_firmware=san_firmware, site=san_site, ca_vendor=san_vendor, ca_bucket=san_bucket, ca_config=san_config)


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
    server_sm_id = Framework.getTriggerCIDataAsList('server_cmdbid')
    server_device_type = 'Физический сервер'
    server_location = "GNEZDO_SERVER"

    incomingDataProcessing(Framework, server_ip, server_location, OSHVResult, ca_datacenter=server_datacenter,
                           ca_dcroom=server_dcroom, description=server_description, ca_primary_dns_name=server_dns_name,
                           ca_global_id=server_global_id, ca_ids=server_ids, ca_interface=server_interface,
                           ca_model=server_model, ca_name=server_name, ca_rack=server_rack, ca_serial=server_serial,
                           ca_node_os_vendor=server_vendor, ca_sm_id=server_sm_id, ca_device_type=server_device_type,
                           ca_location=server_location)


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
    shd_device_type = 'СХД'


    shd_location = "GNEZDO_SHD"

    incomingDataProcessing(Framework, shd_ip, shd_location, OSHVResult, ca_datacenter=server_datacenter,
                           ca_dcroom=server_dcroom, description=shd_description, ca_primary_dns_name=server_dns_name,
                           ca_global_id=shd_global_id, ca_ids=server_ids, ca_interface=server_interface,
                           ca_model=shd_model, ca_name=shd_name, ca_rack=shd_rack, ca_serial=shd_serial,
                           ca_node_os_vendor=server_vendor, ca_sm_id=shd_sm_id, ca_device_type=shd_device_type,
                           ca_firmware=shd_firmware, site=shd_site, ca_vendor=shd_vendor, ca_location=shd_location)


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
    srk_sm_id = Framework.getTriggerCIDataAsList('srk_sm_id')
    srk_device_type = 'СРК'


    srk_location = "GNEZDO_SRK"

    incomingDataProcessing(Framework, srk_ip, srk_location, OSHVResult,
                           description=srk_description, ca_primary_dns_name=srk_dns_name, ca_global_id=srk_global_id,
                           ca_model=srk_model, ca_name=srk_name, ca_rack=srk_rack, ca_serial=srk_serial,
                           ca_sm_id=srk_sm_id,
                           ca_device_type=srk_device_type, ca_firmware=srk_firmware, site=srk_site,
                           ca_vendor=srk_vendor,
                           ca_location=srk_location, ca_config=srk_config)


    # VRM
    vrm_ip = Framework.getTriggerCIDataAsList('vrm_ip')

    vrm_description = Framework.getTriggerCIDataAsList('vrm_description')
    vrm_global_id = Framework.getTriggerCIDataAsList('vrm_global_id')
    vrm_name = Framework.getTriggerCIDataAsList('vrm_name')
    vrm_os_name = Framework.getTriggerCIDataAsList('vrm_os_name')
    vrm_serial = Framework.getTriggerCIDataAsList('vrm_serial')
    vrm_vendor = Framework.getTriggerCIDataAsList('vrm_vendor')
    vrm_sm_id = Framework.getTriggerCIDataAsList('vrm_sm_id')
    vrm_device_type = 'ВРМ'


    vrm_location = "GNEZDO_VRM"

    incomingDataProcessing(Framework, vrm_ip, vrm_location, OSHVResult, ca_node_os_name=vrm_os_name,
                           description=vrm_description, ca_global_id=vrm_global_id, ca_name=vrm_name,
                           ca_serial=vrm_serial, ca_sm_id=vrm_sm_id, ca_device_type=vrm_device_type,
                           ca_vendor=vrm_vendor, ca_location=vrm_location)

    logger.debug('----------------------------Process completed----------------------------')

    # Загрузка resultVector в ucmdb пачками
    for i in range(0, OSHVResult.size(), 15000):
        limit = i + 15000
        if limit >= OSHVResult.size():
            limit = OSHVResult.size()

        vector = OSHVResult.getSubVector(i, limit)
        Framework.sendObjects(vector)
        Framework.flushObjects()
        vector.clear()

    return None
