# coding=utf-8
import modeling
import netutils
import shellutils

from appilog.common.system.types.vectors import ObjectStateHolderVector
from com.hp.ucmdb.discovery.library.clients import ClientsConsts
import logger


def resolveHostNameByDnsList(ip, localShell, dnsList):
    hostName = None
    if localShell:
        dnsResolver = netutils.DNSResolver(localShell)
    for dns in dnsList:
        hostName = dnsResolver.resolveDnsNameByNslookup(ip, dns)
        if hostName:
            return hostName
    return None

def sendObjectsIntoUcmdb(Framework, OSHVResult):
    for i in range(0, OSHVResult.size(), 15000):
        limit = i + 15000
        if limit >= OSHVResult.size():
            limit = OSHVResult.size()

        vector = OSHVResult.getSubVector(i, limit)
        Framework.sendObjects(vector)
        Framework.flushObjects()
        vector.clear()


def DiscoveryMain(Framework):
    OSHVResult = ObjectStateHolderVector()
    ips = Framework.getTriggerCIDataAsList('ip_address')
    ip_ids = Framework.getTriggerCIDataAsList('ip_id')

    dnsServers = Framework.getParameter('dnsServers') or None
    localShell = None

    if dnsServers:
        dnsServers = [dnsServer for dnsServer in dnsServers.split(',') if dnsServer and dnsServer.strip()] or None

    if dnsServers:
        localShell = shellutils.ShellUtils(Framework.createClient(ClientsConsts.LOCAL_SHELL_PROTOCOL_NAME))

    index = 0
    for ip in ips:

        ip_id = ip_ids[index]
        index = index + 1

        if dnsServers:
            dnsName = resolveHostNameByDnsList(ip, localShell, dnsServers)
        else:
            dnsName = netutils.getHostName(ip, None)

        logger.debug('dns, %s:%s' % (ip, dnsName))

        if dnsName == None:
            continue
        else:
            # Set ip DNS by dnsName
            ipOSH = modeling.createOshByCmdbIdString('ip_address', ip_id)
            ipOSH.setAttribute('name', ip)
            ipOSH.setAttribute('authoritative_dns_name', dnsName)
            OSHVResult.add(ipOSH)

    if not OSHVResult.size():
        logger.reportError("Cannot resolve host from DNS")

    if localShell is not None:
        try:
            localShell.close()
            localShell = None
        except:
            pass

    sendObjectsIntoUcmdb(Framework, OSHVResult)

    return None