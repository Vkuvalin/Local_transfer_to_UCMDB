# coding=utf-8
import logger
import netutils
from java.util import Properties

import socket
import re

from appilog.common.system.types import ObjectStateHolder
from appilog.common.system.types.vectors import ObjectStateHolderVector

from com.hp.ucmdb.discovery.common import CollectorsConstants
from com.hp.ucmdb.discovery.library.clients import ClientsConsts
from com.hp.ucmdb.api import UcmdbServiceFactory



def getDomain(dns, defaultValue=None):
    if not dns.replace('.', '').isdigit() and '.' in dns:
        return dns[dns.find('.') + 1:]
    else:
        return defaultValue

def dictionaryFillingLinks(link_list, dict):
    for link in link_list:
        pattern = r"end1=(.*)\,\send2=(.*)\}"
        result = re.finditer(pattern, str(link))

        for j in result:
            dict[j.group(1)] = dict.get(j.group(1), [])
            dict[j.group(1)].append(j.group(2))

def dictionaryFillingLinksNodeIp(link_list, dict):
    for link in link_list:
        pattern = r"end1=(.*)\,\send2=(.*)\}"
        result = re.finditer(pattern, str(link))

        for j in result:
            dict[j.group(2)] = dict.get(j.group(2), [])
            dict[j.group(2)].append(j.group(1))

def dictionaryFillingCiID(topology, ci_list, dict):
    for ci in ci_list:
        ci_id = ci.getId()
        ci_id_string = ci_id.getAsString()
        dict[ci_id_string] = topology.getCI(ci_id)

def getCred(framework, ucmdb_ip):
    credentials = netutils.getAvailableProtocols(framework, ClientsConsts.SSH_PROTOCOL_NAME, ucmdb_ip)
    props = Properties()
    props.setProperty(CollectorsConstants.DESTINATION_DATA_IP_ADDRESS, ucmdb_ip)

    for cred_id in credentials:
        user_label = framework.getProtocolProperty(cred_id, CollectorsConstants.PROTOCOL_ATTRIBUTE_USER_LABEL, '')
        if user_label == "cc_ip_address":
            username = framework.getProtocolProperty(cred_id, CollectorsConstants.PROTOCOL_ATTRIBUTE_USERNAME, '')
            return cred_id, props
    return None

def getSubnet(ip, mask):
    convert_mask = 0

    def number_of_set_bits(x):
        n = 0
        while x:
            n += x & 1
            x = x >> 1
        return n

    for num in mask.split('.'):
        convert_mask += number_of_set_bits(int(num))

    return "{}/{}".format(ip, convert_mask)


def DiscoveryMain(Framework):
    OSHVResult = ObjectStateHolderVector()

    location = "UCMDB"

    # Получение необходимых данных для соединения
    ucmdb_ip = Framework.getParameter('ucmdb_ip')
    ucmdb_port = int(Framework.getParameter('ucmdb_port'))
    query_name = Framework.getParameter('query_name')

    cred, _ = getCred(Framework, ucmdb_ip)
    username = Framework.getProtocolProperty(cred, CollectorsConstants.PROTOCOL_ATTRIBUTE_USERNAME, '')
    password = Framework.getProtocolProperty(cred, CollectorsConstants.PROTOCOL_ATTRIBUTE_PASSWORD, '')


    # Создание соединения
    provider = UcmdbServiceFactory.getServiceProvider("https", ucmdb_ip, ucmdb_port)
    ucmdbService = provider.connect(provider.createCredentials(username, password),
                                    provider.createClientContext("ucmdb-internal"))

    # Работа с query
    queryService = ucmdbService.getTopologyQueryService()
    executableQuery = queryService.createExecutableQuery(query_name)
    topology = queryService.executeQuery(executableQuery)

    # Получение списков КЕ
    ip_addresses = topology.getCIsByName('IpAddress')

    nodes = topology.getCIsByName('NODE')
    nodes_dict = dict()

    interfaces = topology.getCIsByName('INTERFACE')
    interfaces_dict = dict()

    ipservices = topology.getCIsByName('IP_SERVICE')
    ipservices_dict = dict()

    # Наполенение словарей КЕ
    dictionaryFillingCiID(topology, nodes, nodes_dict)
    dictionaryFillingCiID(topology, interfaces, interfaces_dict)
    dictionaryFillingCiID(topology, ipservices, ipservices_dict)



    # Получение линков
    node_ip = topology.getRelationsByName("node_ip")
    node_ip_dict = dict()

    node_interface = topology.getRelationsByName("node_interface")
    node_interface_dict = dict()

    node_ipservice = topology.getRelationsByName("node_ipservice")
    node_ipservice_dict = dict()

    # Наполенение словарей линков
    dictionaryFillingLinksNodeIp(node_ip, node_ip_dict)
    dictionaryFillingLinks(node_interface, node_interface_dict)
    dictionaryFillingLinks(node_ipservice, node_ipservice_dict)


    # ------------ip_addresses-----------

    for ip in ip_addresses:
        ip_name = ip.getPropertyValue("name")
        ip_global_id = ip.getPropertyValue("global_id")
        ip_netaddr = ip.getPropertyValue("ip_netaddr")
        ip_netmask = ip.getPropertyValue("ip_netmask")

        # Создание КЕ cc_ip_address
        hostOsh = ObjectStateHolder("cc_ip_address")
        hostOsh.setStringAttribute("name", ip_name)  # Ключ

        # DNS name and Domain
        dns_name = socket.gethostbyaddr(ip_name)[0]
        dns_name = None if dns_name == ip_name else dns_name

        domain = None
        if dns_name:
            domain = getDomain(dns_name)

        hostOsh.setStringAttribute("ca_primary_dns_name", dns_name)
        hostOsh.setStringAttribute("ca_domain", domain)

        if ip_netaddr and ip_netmask:
            hostOsh.setStringAttribute("ca_subnet", getSubnet(ip_netaddr, ip_netmask))
        else:
            hostOsh.setStringAttribute("ca_subnet", "{}/32".format(ip_name))


        try:
            if node_ip_dict[ip_global_id]:
                node = nodes_dict[node_ip_dict[ip_global_id][0]]
                # ------------nodes-----------

                # GET
                node_name = node.getPropertyValue("name")
                node_global_id = node.getPropertyValue("global_id")
                node_root_class = node.getPropertyValue("root_class")
                node_host_osinstalltype = node.getPropertyValue("host_osinstalltype")
                node_discovered_model = node.getPropertyValue("discovered_model")
                node_os_description = node.getPropertyValue("os_description")
                node_discovered_os_name = node.getPropertyValue("discovered_os_name")
                node_discovered_os_vendor = node.getPropertyValue("discovered_os_vendor")
                node_discovered_os_version = node.getPropertyValue("discovered_os_version")
                node_role = node.getPropertyValue("node_role")
                node_serial_number = node.getPropertyValue("serial_number")
                node_cc_sm_ciid = node.getPropertyValue("cc_sm_ciid")
                node_device_type = node.getPropertyValue("ca_device_type")

                # SEND
                hostOsh.setStringAttribute("ca_node_type", node_root_class)
                hostOsh.setStringAttribute("ca_node_os_vendor", node_discovered_os_vendor)
                hostOsh.setStringAttribute("ca_name", node_name)
                hostOsh.setStringAttribute("ca_global_id", node_global_id)
                hostOsh.setStringAttribute("ca_node_role", node_role)
                hostOsh.setStringAttribute("ca_node_os_install_type", node_host_osinstalltype)
                hostOsh.setStringAttribute("ca_model", node_discovered_model)
                hostOsh.setStringAttribute("ca_node_os_version", node_discovered_os_version)
                hostOsh.setStringAttribute("ca_serial", node_serial_number)
                hostOsh.setStringAttribute("ca_sm_id", node_cc_sm_ciid)
                hostOsh.setStringAttribute("ca_location", location)
                hostOsh.setStringAttribute("ca_device_type", node_device_type)

                if node_discovered_os_name:
                    hostOsh.setStringAttribute("ca_node_os_name", "{} ({})".format(node_discovered_os_name, node_os_description) if node_os_description else node_discovered_os_name)
                if node_cc_sm_ciid:
                    hostOsh.setAttribute("ca_identification", True)
                if node_os_description:
                    hostOsh.setStringAttribute("ca_node_os_accuracy", "100" + '%')


                try:
                    if node_interface_dict[node_global_id]:
                        # ------------interfaces-----------
                        list_interfaces = list()

                        for id in node_interface_dict[node_global_id]:
                            interface = interfaces_dict[id]
                            interface_mac_address = interface.getPropertyValue("mac_address")
                            list_interfaces.append(interface_mac_address)

                        hostOsh.setStringAttribute("ca_interface", '; '.join(list_interfaces))
                except:
                    pass

                try:
                    if node_ipservice_dict[node_global_id]:
                        # ------------ipservices-----------
                        addressesList = list()
                        for id in node_ipservice_dict[node_global_id]:
                            ipservice = ipservices_dict[id]
                            ipservice_ipserver_address = ipservice.getPropertyValue("ipserver_address")
                            ipservice_service_names = ipservice.getPropertyValue("service_names")

                            if ipservice_ipserver_address:
                                if ipservice_service_names:
                                    addressesList.append("{} ({})".format(ipservice_ipserver_address, ipservice_service_names.replace("[", '').replace("]", '')))
                                else:
                                    addressesList.append(ipservice_ipserver_address)

                        hostOsh.setStringAttribute("ca_ip_service_endpoint_network_port_info", '; '.join(addressesList))
                except:
                    pass
        except:
            pass

        OSHVResult.add(hostOsh)

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
