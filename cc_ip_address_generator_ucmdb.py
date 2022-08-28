#coding=utf-8
import logger
import socket

from appilog.common.system.types import ObjectStateHolder
from appilog.common.system.types.vectors import ObjectStateHolderVector


def formatInterface(interface):
    charList = list(interface)
    formatedInterface = ""
    for i in range(len(charList)):
        formatedInterface += charList[i]
        if i % 2 and i != len(charList) - 1:
            formatedInterface += ":"
    return formatedInterface

def formatFrameworkValue(value):
    if value == "NA":
        value = None
    return value

def formatRoleValue(role_value):
    new_role_value_list = []
    if role_value:
        if "server" in role_value:
            new_role_value_list.append("server")
        elif "router" in role_value:
            new_role_value_list.append("router")
        elif "desktop" in role_value:
            new_role_value_list.append("desktop")
        elif "virtualized_system" in role_value:
            new_role_value_list.append("virtualized_system")

    return new_role_value_list


def DiscoveryMain(Framework):
    OSHVResult = ObjectStateHolderVector()

    # IpAddress - Name (key)
    ip = Framework.getDestinationAttribute('ip_address')

    # Mac
    interfaces = Framework.getTriggerCIDataAsList('mac_address')
    interfacesList = []
    for interface in interfaces:
        if interface != "NA":
            interfacesList.append(formatInterface(interface))

    # Node
    hostClass = formatFrameworkValue(Framework.getDestinationAttribute('ci_type'))
    os_name = formatFrameworkValue(Framework.getDestinationAttribute('os_name'))
    os_vendor = formatFrameworkValue(Framework.getDestinationAttribute('os_vendor'))
    role = formatFrameworkValue(Framework.getDestinationAttribute('role'))
    if role:
        role = formatRoleValue(role)

    host_name = formatFrameworkValue(Framework.getDestinationAttribute('host_name'))
    os_description = formatFrameworkValue(Framework.getDestinationAttribute('os_description'))
    global_id = formatFrameworkValue(Framework.getDestinationAttribute('global_id'))
    serial = formatFrameworkValue(Framework.getDestinationAttribute('serial'))
    model = formatFrameworkValue(Framework.getDestinationAttribute('model'))
    os_version = formatFrameworkValue(Framework.getDestinationAttribute('os_version'))
    host_osinstalltype = formatFrameworkValue(Framework.getDestinationAttribute('host_osinstalltype'))


    # ServiceEndpointNetwork
    addresses = formatFrameworkValue(Framework.getTriggerCIDataAsList('address'))
    serviceNames = formatFrameworkValue(Framework.getTriggerCIDataAsList('serviceName'))
    dns_name = socket.gethostbyaddr(ip)[0]
    dns_name = None if dns_name == ip else dns_name

    addressesList = []
    for i in range(len(addresses)):
        if addresses[i] != "NA":
            if serviceNames[i] != "NA":
                addressesList.append("{} ({})".format(addresses[i], serviceNames[i].replace("[", '').replace("]", '')))
            else:
                addressesList.append(addresses[i])

    location = "UCMDB"


    # --------------------------------- Creating -----------------------------
    hostOshMy = ObjectStateHolder("cc_ip_address")
    hostOshMy.setStringAttribute("name", ip)  # Ключ


    if host_name:
        hostOshMy.setStringAttribute("ca_interface", '; '.join(interfacesList) if len(interfacesList) != 0 else None)
        hostOshMy.setStringAttribute("ca_node_type", hostClass)

        if os_name:
            hostOshMy.setStringAttribute("ca_node_os_name", "{} ({})".format(os_name, os_description) if os_description else os_name)

        hostOshMy.setStringAttribute("ca_node_os_vendor", os_vendor)
        hostOshMy.setStringAttribute("ca_name", host_name)
        hostOshMy.setStringAttribute("ca_global_id", global_id)
        hostOshMy.setStringAttribute("ca_primary_dns_name", dns_name)
        hostOshMy.setStringAttribute("ca_ip_service_endpoint_network_port_info", '; '.join(addressesList) if len(addressesList) != 0 else None)
        hostOshMy.setStringAttribute("ca_node_role", ', '.join(role) if role else None)
        hostOshMy.setStringAttribute("ca_node_os_install_type", host_osinstalltype)
        hostOshMy.setStringAttribute("ca_model", model)
        hostOshMy.setStringAttribute("ca_node_os_version", os_version)
        hostOshMy.setStringAttribute("ca_serial", serial)
        hostOshMy.setStringAttribute("ca_location", location)

        # Что тут будет являться типом уст-ва? Не лучше брать модель?
        if (role or model) and os_vendor:
            hostOshMy.setAttribute("ca_identification", True)

        if os_description:
            hostOshMy.setStringAttribute("ca_node_os_accuracy", "100" + '%')

    OSHVResult.add(hostOshMy)

    return OSHVResult