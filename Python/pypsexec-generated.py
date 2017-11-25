#!/usr/bin/python
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# PSEXEC like functionality example using RemComSvc (https://github.com/kavika13/RemCom)
#
# Author:
#  beto (@agsolino)
#
# Reference for:
#  DCE/RPC and SMB.

# NOTE: The following two lines are only required for CentOS 6 to override
# the default pycrypto version.
#__requires__ = [ 'pycrypto>=2.6' ]
#import pkg_resources

import sys
import os
import cmd
import logging
from threading import Thread, Lock
import argparse
import random
import string
import time

from impacket.examples import logger
from impacket import version, smb
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport
from impacket.structure import Structure

# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Service Install Helper library used by psexec and smbrelayx
# You provide an already established connection and an exefile 
# (or class that mimics a file class) and this will install and 
# execute the service, and then uninstall (install(), uninstall().
# It tries to take care as much as possible to leave everything clean.
#
# Author:
#  Alberto Solino (@agsolino)
#

import random
import string

from impacket.dcerpc.v5 import transport, srvs, scmr
from impacket import smb,smb3, LOG
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_WRITE_DATA, FILE_DIRECTORY_FILE

class ServiceInstall:
    def __init__(self, SMBObject, exeFile, serviceName = None, binaryServiceName = None, reInstall = False, unInstall = False):
        self._reInstall = reInstall
        self._unInstall = unInstall
        self._rpctransport = 0
        if not serviceName:
            self.__service_name = ''.join([random.choice(string.letters) for i in range(4)])
            self._reInstall = self._unInstall = True
        else:
            self.__service_name = serviceName
        if not binaryServiceName:
            self.__binary_service_name = ''.join([random.choice(string.letters) for i in range(8)]) + '.exe'
            self._reInstall = self._unInstall = True
        else:
            self.__binary_service_name = binaryServiceName
        self.__exeFile = exeFile

        # We might receive two different types of objects, always end up
        # with a SMBConnection one
        if isinstance(SMBObject, smb.SMB) or isinstance(SMBObject, smb3.SMB3):
            self.connection = SMBConnection(existingConnection = SMBObject)
        else:
            self.connection = SMBObject

        self.share = ''
 
    def getShare(self):
        return self.share

    def getShares(self):
        # Setup up a DCE SMBTransport with the connection already in place
        LOG.debug("Requesting shares on %s....." % (self.connection.getRemoteHost()))
        try: 
            self._rpctransport = transport.SMBTransport(self.connection.getRemoteHost(),
                                                        self.connection.getRemoteHost(),filename = r'\srvsvc',
                                                        smb_connection = self.connection)
            dce_srvs = self._rpctransport.get_dce_rpc()
            dce_srvs.connect()

            dce_srvs.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrShareEnum(dce_srvs, 1)
            return resp['InfoStruct']['ShareInfo']['Level1']
        except:
            LOG.critical("Error requesting shares on %s, aborting....." % (self.connection.getRemoteHost()))
            raise

# Check for an existing service by our specified name.
# Note that this will create and delete a service manager handle
# in cases where none is passed to it...for example when testing
# from the main code. When that is used, it will assume that it
# should start the service if it's not already started.
    def checkService(self, start = False, handle = None):
        autostart = False
        if handle == None:
            svcManager = self.openSvcManager()
            if svcManager != 0:
                autostart = True
            else:
                LOG.error('Unable to open SvcManager in checkService')
                return False
        else:
            svcManager = handle
        LOG.debug("Checking for service %s on %s....." % (self.__service_name, self.connection.getRemoteHost()))
        resp = False
        try:
            resp =  scmr.hROpenServiceW(self.rpcsvc, svcManager, self.__service_name+'\x00')
        except Exception as e:
            if str(e).find('ERROR_SERVICE_DOES_NOT_EXIST') >= 0:
                # We're good, pass the exception
                resp = False
                pass
            else:
                raise e
        if autostart:
            if resp != False:
# Check running status
                LOG.debug("Checking running status of service")
                stat = scmr.hRQueryServiceStatus(self.rpcsvc, resp['lpServiceHandle'])
                if stat['lpServiceStatus']['dwCurrentState'] != scmr.SERVICE_RUNNING and start:
                    LOG.debug('Starting non-running service %s.....' % self.__service_name)
                    try:
                        scmr.hRStartServiceW(self.rpcsvc, resp['lpServiceHandle'])
                    except:
                        pass
                else:
                    LOG.debug("Service is running")
                scmr.hRCloseServiceHandle(self.rpcsvc, resp['lpServiceHandle'])
                resp = True
            scmr.hRCloseServiceHandle(self.rpcsvc, svcManager)
        if resp == False or resp == True:
            return resp
        else:
            return resp['lpServiceHandle']

    def createService(self, handle, path):
        resp = self.checkService(False, handle)
        if resp != False:
            if not self._reInstall:
                return resp
            else:
                # It exists, remove it
                scmr.hRDeleteService(self.rpcsvc, resp['lpServiceHandle'])
                scmr.hRCloseServiceHandle(self.rpcsvc, resp['lpServiceHandle'])

        LOG.debug("Creating service %s on %s....." % (self.__service_name, self.connection.getRemoteHost()))

        # Create the service
        command = '%s\\%s' % (path, self.__binary_service_name)
        try: 
            resp = scmr.hRCreateServiceW(self.rpcsvc, handle,self.__service_name + '\x00', self.__service_name + '\x00',
                                         lpBinaryPathName=command + '\x00')
        except:
            LOG.critical("Error creating service %s on %s" % (self.__service_name, self.connection.getRemoteHost()))
            raise
        else:
            return resp['lpServiceHandle']

    def openSvcManager(self):
        LOG.debug("Opening SVCManager on %s....." % self.connection.getRemoteHost())
        # Setup up a DCE SMBTransport with the connection already in place
        self._rpctransport = transport.SMBTransport(self.connection.getRemoteHost(), self.connection.getRemoteHost(),
                                                    filename = r'\svcctl', smb_connection = self.connection)
        self.rpcsvc = self._rpctransport.get_dce_rpc()
        self.rpcsvc.connect()
        self.rpcsvc.bind(scmr.MSRPC_UUID_SCMR)
        try:
            resp = scmr.hROpenSCManagerW(self.rpcsvc)
        except:
            LOG.critical("Error opening SVCManager on %s....." % self.connection.getRemoteHost())
            raise Exception('Unable to open SVCManager')
        else:
            return resp['lpScHandle']

    def copy_file(self, src, tree, dst):
        LOG.debug("Uploading file %s" % dst)
        if isinstance(src, str):
            # We have a filename
            fh = open(src, 'rb')
        else:
            # We have a class instance, it must have a read method
            fh = src
        f = dst
        pathname = string.replace(f,'/','\\')
        try:
            self.connection.putFile(tree, pathname, fh.read)
        except:
            LOG.critical("Error uploading file %s, aborting....." % dst)
            raise
        fh.close()

    def findWritableShare(self, shares):
        # Check we can write a file on the shares, stop in the first one
        writeableShare = None
        for i in shares['Buffer']:
            if i['shi1_type'] == srvs.STYPE_DISKTREE or i['shi1_type'] == srvs.STYPE_SPECIAL:
               share = i['shi1_netname'][:-1]
               tid = 0
               try:
                   tid = self.connection.connectTree(share)
                   self.connection.openFile(tid, '\\', FILE_WRITE_DATA, creationOption=FILE_DIRECTORY_FILE)
               except:
                   LOG.critical("share '%s' is not writable." % share)
                   pass
               else:
                   LOG.debug('Found writable share %s' % share)
                   writeableShare = str(share)
                   break
               finally:
                   if tid != 0:
                       self.connection.disconnectTree(tid)
        return writeableShare

    def install(self):
        if self.connection.isGuestSession():
            LOG.critical("Authenticated as Guest. Aborting")
            self.connection.logoff()
            del self.connection
        else:
            fileCopied = False
            serviceCreated = False
            # Do the stuff here
            try:
                # Let's get the shares
                shares = self.getShares()
                self.share = self.findWritableShare(shares)
                if self.share is None:
                    return False
                self.copy_file(self.__exeFile ,self.share,self.__binary_service_name)
                fileCopied = True
                svcManager = self.openSvcManager()
                if svcManager != 0:
                    serverName = self.connection.getServerName()
                    if self.share.lower() == 'admin$':
                        path = '%systemroot%'
                    else:
                        if serverName != '':
                           path = '\\\\%s\\%s' % (serverName, self.share)
                        else:
                           path = '\\\\127.0.0.1\\' + self.share 
                    service = self.createService(svcManager, path)
                    serviceCreated = True
                    if service != 0:
                        # Start service
                        LOG.debug('Starting service %s.....' % self.__service_name)
                        try:
                            scmr.hRStartServiceW(self.rpcsvc, service)
                        except:
                            pass
                        scmr.hRCloseServiceHandle(self.rpcsvc, service)
                    scmr.hRCloseServiceHandle(self.rpcsvc, svcManager)
                    return True
            except Exception as e:
                LOG.critical("Error performing the installation, cleaning up: %s" %e)
                try:
                    scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
                except:
                    pass
                if fileCopied is True:
                    try:
                        self.connection.deleteFile(self.share, self.__binary_service_name)
                    except:
                        pass
                if serviceCreated is True:
                    try:
                        scmr.hRDeleteService(self.rpcsvc, service)
                    except:
                        pass
            return False
      
    def uninstall(self):
        fileCopied = True
        serviceCreated = True
        # Do the stuff here
        try:
            # Let's get the shares
            svcManager = self.openSvcManager()
            if svcManager != 0:
                resp = scmr.hROpenServiceW(self.rpcsvc, svcManager, self.__service_name+'\x00')
                service = resp['lpServiceHandle'] 
                LOG.debug('Stoping service %s.....' % self.__service_name)
                try:
                    scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
                except:
                    pass
                LOG.debug('Removing service %s.....' % self.__service_name)
                scmr.hRDeleteService(self.rpcsvc, service)
                scmr.hRCloseServiceHandle(self.rpcsvc, service)
                scmr.hRCloseServiceHandle(self.rpcsvc, svcManager)
            LOG.debug('Removing file %s.....' % self.__binary_service_name)
            self.connection.deleteFile(self.share, self.__binary_service_name)
        except Exception:
            LOG.critical("Error performing the uninstallation, cleaning up" )
            try:
                scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
            except:
                pass
            if fileCopied is True:
                try:
                    self.connection.deleteFile(self.share, self.__binary_service_name)
                except:
                    try:
                        self.connection.deleteFile(self.share, self.__binary_service_name)
                    except:
                        pass
                    pass
            if serviceCreated is True:
                try:
                    scmr.hRDeleteService(self.rpcsvc, service)
                except:
                    pass


# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# REMCOMSVC library. It provides a way to retrieve the RemComSvc binary file to be
# uploaded to the target machine. This is used by psexec and smbrelayx
#
# If you want to compile this file yourself, get the source code from 
# https://github.com/kavika13/RemCom, compile RemComSvc project, and 
# dump the binary (hexlify) in this file, on the REMCOMSVC variable
#
# Author:
#  Alberto Solino (@agsolino)
#
# Copyright note in remcomsvc.cpp:
#
# Copyright (c) 2006 Talha Tariq [ talha.tariq@gmail.com ] 
# All rights are reserved.
#
# Permission to use, copy, modify, and distribute this software 
# for any purpose and without any fee is hereby granted, 
# provided this notice is included in its entirety in the 
# documentation and in the source files.
# 
# This software and any related documentation is provided "as is" 
# without any warranty of any kind, either express or implied, 
# including, without limitation, the implied warranties of 
# merchantability or fitness for a particular purpose. The entire 
# risk arising out of use or performance of the software remains 
# with you. 
# 
# $Author:	Talha Tariq [ talha.tariq@gmail.com ] 
# 		uses some code from xCmd by Zoltan Csizmadia
# $Revision:	Talha Tariq [ talha.tariq@gmail.com ] 	
# $Revision:	Andres Ederra 
#

import binascii

class RemComSvc:
    def __init__(self):
        self.binary = binascii.unhexlify(REMCOMSVC)
        self.offset = 0

    def read(self, amount):
        # Returns amount of bytes and updates the offset within REMCOMSVC variable
        data =  self.binary[self.offset:self.offset+amount]
        self.offset += amount
        return data

    def seek(self, offset):
        self.offset = offset

    def close(self):
        return
        

REMCOMSVC='4d5a90000300000004000000ffff0000b800000000000000400000000000' \
'000000000000000000000000000000000000000000000000000000000000d80000000e' \
'1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f74206265' \
'2072756e20696e20444f53206d6f64652e0d0d0a24000000000000008030ee41c45180' \
'12c4518012c4518012cd291512d4518012cd290312a4518012e397fb12c1518012c451' \
'8112b4518012cd290412e5518012cd291112c551801252696368c45180120000000000' \
'0000000000000000000000504500004c010500b1cf23500000000000000000e0000201' \
'0b010900009400000044000000000000a61d00000010000000b0000000004000001000' \
'0000020000050000000000000005000000000000000030010000040000bc3801000300' \
'40810000100000100000000010000010000000000000100000000000000000000000c4' \
'c800003c00000000100100b40100000000000000000000000000000000000000200100' \
'1409000000000000000000000000000000000000000000000000000000000000000000' \
'0080c4000040000000000000000000000000b000008801000000000000000000000000' \
'00000000000000000000000000002e74657874000000c4930000001000000094000000' \
'040000000000000000000000000000200000602e726461746100009821000000b00000' \
'0022000000980000000000000000000000000000400000402e646174610000002c2e00' \
'0000e000000010000000ba0000000000000000000000000000400000c02e7273726300' \
'0000b4010000001001000002000000ca0000000000000000000000000000400000402e' \
'72656c6f630000a40f0000002001000010000000cc0000000000000000000000000000' \
'4000004200000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'00000000000000000000000000005357683f000f0033db5353ff1520b040008bf83bfb' \
'746a5668ff010f0068c8b1400057ff1524b040008bf03bf3750b57ff1528b040005e5f' \
'5bc356ff152cb04000a100ef40006804ef400050c70508ef400001000000891d18ef40' \
'00891d1cef4000891d10ef4000891d14ef4000ff1530b04000568b3528b04000ffd657' \
'ffd65e5f5bc3cccccccccccccccccccccccc558bec8b450883e801740da100ef400068' \
'04ef400050eb348b0d20ef400051ff1578b040008b1500ef400033c06804ef4000a310' \
'ef4000c70508ef400001000000a318ef4000a31cef400052ff1530b0400085c07506ff' \
'1580b040005dc20400558bec83ec30a100e0400033c58945fc5356578b7d08897de0ff' \
'1564b0400033db505368ffff1f00895de8c745ec3200000033f6885df4885df5885df6' \
'885df7885df8c645f905895ddc895de4895df0891fff1568b040008d4de8516a085089' \
'45d8ff150cb0400085c0750eff1580b040008945f0e9380100008b55ec5253ff156cb0' \
'40008bf03bf3750eff1580b040008945f0e9190100008b4dec8b55e88b1d10b040008d' \
'45ec5051566a0252ffd38b3d80b0400085c07553ffd783f87a740affd78945f0e9e700' \
'000056ff1570b040008b45ec506a00ff156cb040008bf085f6750affd78945f0e9c400' \
'00008b55ec8b45e88d4dec5152566a0250ffd385c0750affd78945f0e9a50000008b1d' \
'14b040008d4ddc516a006a006a006a006a006a006a006a046a018d55f452ffd385c075' \
'07ffd78945f0eb788d45e4506a006a006a006a006a006a006a006a066a018d4df451ff' \
'd385c07507ffd78945f0eb5133db391e763d8d7e048d9b000000008b4ddc8b078b5704' \
'51508945d08955d4ff1518b0400085c0757b8b55e48b45d05250ff1518b0400085c075' \
'744383c7083b1e72cc8b45e08338007506c700010000008b45e48b3d1cb0400085c074' \
'0350ffd78b45dc85c0740350ffd785f6740756ff1570b040008b45e88b3574b0400085' \
'c0740350ffd68b45d885c0740350ffd68b4dfc8b45f05f5e33cd5be8790500008be55d' \
'c38b4de0c70100000000eba28b55e0c70201000000eb97cccccccccc5633f668901040' \
'0068d4b14000c70504ef400030000000c70508ef400002000000c7050cef4000010000' \
'00893510ef4000893514ef4000893518ef400089351cef4000ff1508b04000a300ef40' \
'003bc6744e6804ef400050c70508ef400004000000893518ef400089351cef4000ff15' \
'30b0400085c0750aff1580b040005ec2080056565656ff1560b0400056566830184000' \
'a320ef4000e8cd05000083c40c5ec20800cccccccccccccccccccccccc558bec83ec14' \
'8d45fc50c745ecc8b14000c745f010134000c745f400000000c745f800000000c745fc' \
'01000000e8fefcffff83c404837dfc00750d68dcb14000e82e06000083c4048d4dec51' \
'ff1504b040008be55dc3cccccccccccccccccccc558bec83ec20535633c0578945f889' \
'45fc6a018d45e050c745f400000000ff1534b040006a006a006a018d4de051ff1500b0' \
'40008b750c8b7d08814e2c0001000083c8ff89463c8946388946408b8708110000508d' \
'9f0c110000536834b240008d55e06824b240006830ef4000c745f40c0000008955f8c7' \
'45fc01000000e8550600008b8f0811000051536814b240006824b240006838f04000e8' \
'390600008b970811000052536804b240006824b240006840f14000e81d0600008b3d58' \
'b0400083c43c8d45f4506aff6a006a0068ff0000006a046a026830ef4000ffd78d4df4' \
'516aff6a006a0068ff0000006a046a026840f1400089463cffd78d55f4526aff6a006a' \
'0068ff0000008946406a046a016838f04000ffd78b4e3c89463883f9ff7432837e40ff' \
'742c83f8ff74278b3d5cb040006a0051ffd78b46386a0050ffd78b4e406a0051ffd75f' \
'5eb8010000005b8be55dc38b3d74b0400051ffd78b564052ffd78b463850ffd75f5e33' \
'c05b8be55dc3cccccccccccccccccccccccccc558bec81ec60010000a100e0400033c5' \
'8945fc568b7508578b7d0c6a448d85a0feffff6a0050e8b50500008d8da0feffff5156' \
'c785a0feffff44000000e83efeffff83c41485c075155fb8020000005e8b4dfc33cde8' \
'700200008be55dc353568d95f8feffff6844b2400052c70700000000c785f4feffff00' \
'000000e8d70400000fbe860010000083c40c8d8e00100000f7d81bc023c18d8de4feff' \
'ff518d95a0feffff52508b86041100006a000d00000008506a016a006a008d8df8feff' \
'ff516a00ff154cb0400085c0743f8b85e4feffffc7070000000083be10120000008bd8' \
'75326aff50ff1550b040005753ff1554b040008b85f4feffff5b5f5e8b4dfc33cde8c2' \
'0100008be55dc3c785f4feffff010000008b4dfc8b85f4feffff5b5f33cd5ee8a10100' \
'008be55dc3cccccc558becb828120000e823050000a100e0400033c58945fc568b7508' \
'6828ef4000ff1544b0400033c0508985e0edffff8985e4edffff8d85dcedffff506814' \
'1200008d8de8edffff5156ff157cb0400085c0743e83bddcedffff0074358d95e4edff' \
'ff528d85e8edffff50e861feffff83c4086a008d8dd8edffff516a088d95e0edffff52' \
'568985e0edffffff153cb0400056ff1540b0400056ff1574b040006828ef4000ff1548' \
'b04000833d28ef4000005e750ca120ef400050ff1578b040008b4dfc33cde8d0000000' \
'8be55dc3cccc558bec83ec20538b1d00b0400056578b3d34b0400033c08945f88945fc' \
'6a018d45e050c745f400000000ffd76a016a006a018d4de051ffd38d45f4506aff6a00' \
'6a0068ff0000006a046a038d55e06848b24000c745f40c0000008955f8c745fc010000' \
'00ff1558b040008bf085f674a56a0056ff155cb04000566a0068d0164000e854010000' \
'83c40ceb8acccccccccc566a006a0068a0174000e83b0100008b3550b0400083c40ca1' \
'20ef40006a0a50ffd685c075f2e8a5f7ffff8b0d20ef400051ff1574b040005ec33b0d' \
'00e040007502f3c3e937050000833d240e41000056741568240e4100e8030d00005985' \
'c07406ff15240e4100e8a40800008bf085f674168b460483f8ff740750ff1574b04000' \
'56e84b0a0000596a00ff1584b04000cc6a0c68f0c44000e81a120000e8e70800008365' \
'fc00ff7058ff505459e896ffffff8b45ec8b088b09894de45051e8921000005959c38b' \
'65e8ff75e4e801100000cc8bff558bece8bf060000e8b406000050e89406000085c075' \
'1fff7508e8a206000050e8d606000085c07528ff1580b0400050ff1584b040008b4d08' \
'8b51548950548b51588950588b510451895004e87e080000833d280e41000074156828' \
'0e4100e8270c00005985c07406ff15280e4100e849ffffffcc8bff558bec5153578b7d' \
'0833db895dfc3bfb7520e88b1300005353535353c70016000000e86816000083c41483' \
'c8ffe98100000056e81806000068140200006a01e87a1400008bf059593bf3744ae8ed' \
'070000ff706c56e8840600008b45105959566a04566803194000ff750c897e54538946' \
'58ff158cb040008bf8897e043bfb740c57ff1588b0400083f8ff7523ff1580b0400089' \
'45fc56e84f13000059395dfc7409ff75fce81e1300005983c8ffeb028bc75e5f5bc9c3' \
'6a0c6810c54000e8a910000033c033f63975080f95c03bc6751de8cc120000c7001600' \
'00005656565656e8a915000083c41483c8ffeb5fe8c21500006a205b03c3506a01e8cd' \
'16000059598975fce8ab15000003c350e858170000598bf88d450c5056ff7508e89315' \
'000003c350e83d1900008945e4e88315000003c35057e8cb17000083c418c745fcfeff' \
'ffffe8090000008b45e4e85f100000c3e85d15000083c020506a01e8d81600005959c3' \
'a100e0400083c80133c9390544f240000f94c18bc1c38bff558bec83ec205333db395d' \
'0c751de8111200005353535353c70016000000e8ee14000083c41483c8ffeb4d8b4508' \
'3bc374dc568945e88945e08d45105053ff750c8d45e050c745e4ffffff7fc745ec4200' \
'0000e89118000083c410ff4de48bf078078b45e08818eb0c8d45e05053e80e24000059' \
'598bc65e5bc9c3cccccccccccccccccccccc8b54240c8b4c240485d2746933c08a4424' \
'0884c0751681fa00010000720e833de0fd4000007405e98a250000578bf983fa047231' \
'f7d983e103740c2bd1880783c70183e90175f68bc8c1e00803c18bc8c1e01003c18bca' \
'83e203c1e9027406f3ab85d2740a880783c70183ea0175f68b4424085fc38b442404c3' \
'cccccccccccc518d4c24042bc81bc0f7d023c88bc42500f0ffff3bc8720a8bc159948b' \
'00890424c32d001000008500ebe98bff558bec833d50f24000027405e841280000ff75' \
'08e88e26000068ff000000e8810a000059595dc36a146830c54000e8880e0000b84d5a' \
'0000663905000040007538a13c00400081b800004000504500007527b90b0100006639' \
'8818004000751983b8740040000e761033c93988e80040000f95c1894de4eb048365e4' \
'006a01e8112f00005985c075086a1ce86effffff59e8ae06000085c075086a10e85dff' \
'ffff59e8a22e00008365fc00e8452c000085c07d086a1be89509000059ff1590b04000' \
'a3200e4100e8f22a0000a348f24000e82d2a000085c07d086a08e86f09000059e8a427' \
'000085c07d086a09e85e090000596a01e8150a00005985c0740750e84b09000059a19c' \
'f54000a3a0f5400050ff3594f54000ff3590f54000e871f6ffff83c40c8945e0837de4' \
'00750650e88c0b0000e8b30b0000eb2e8b45ec8b088b09894ddc5051e80d0c00005959' \
'c38b65e88b45dc8945e0837de400750650e8720b0000e8920b0000c745fcfeffffff8b' \
'45e0e8880d0000c3e8472e0000e9a4feffff8bff558bec81ec28030000a360f3400089' \
'0d5cf34000891558f34000891d54f34000893550f34000893d4cf34000668c1578f340' \
'00668c0d6cf34000668c1d48f34000668c0544f34000668c2540f34000668c2d3cf340' \
'009c8f0570f340008b4500a364f340008b4504a368f340008d4508a374f340008b85e0' \
'fcffffc705b0f2400001000100a168f34000a364f24000c70558f24000090400c0c705' \
'5cf2400001000000a100e040008985d8fcffffa104e040008985dcfcffffff15a4b040' \
'00a3a8f240006a01e80b2e0000596a00ff15a0b040006868b24000ff159cb04000833d' \
'a8f240000075086a01e8e72d00005968090400c0ff1598b0400050ff1594b04000c9c3' \
'8bff558bec56ff3518e040008b35b0b04000ffd685c07421a114e0400083f8ff741750' \
'ff3518e04000ffd6ffd085c074088b80f8010000eb27be80b2400056ff15a8b0400085' \
'c0750b56e8480700005985c074186870b2400050ff15acb0400085c07408ff7508ffd0' \
'8945088b45085e5dc36a00e887ffffff59c38bff558bec56ff3518e040008b35b0b040' \
'00ffd685c07421a114e0400083f8ff741750ff3518e04000ffd6ffd085c074088b80fc' \
'010000eb27be80b2400056ff15a8b0400085c0750b56e8cd0600005985c07418689cb2' \
'400050ff15acb0400085c07408ff7508ffd08945088b45085e5dc3ff15b4b04000c204' \
'008bff558becff7508ff3518e04000ff15b0b04000ffd05dc20400a114e04000c38bff' \
'56ff3518e04000ff15b0b040008bf085f6751bff3580f54000e845ffffff598bf056ff' \
'3518e04000ff15b8b040008bc65ec38bff558becff750cff7508ff3584f54000e81bff' \
'ffff59ffd05dc20800a114e0400083f8ff741650ff3588f54000e8fefeffff59ffd083' \
'0d14e04000ffa118e0400083f8ff740e50ff15bcb04000830d18e04000ffe9812c0000' \
'6a0c6850c54000e8820a0000be80b2400056ff15a8b0400085c0750756e8d105000059' \
'8945e48b7508c7465c00b3400033ff47897e1485c074246870b24000508b1dacb04000' \
'ffd38986f8010000689cb24000ff75e4ffd38986fc010000897e70c686c800000043c6' \
'864b01000043c7466840e740006a0de8352d0000598365fc00ff7668ff1544b04000c7' \
'45fcfeffffffe83e0000006a0ce8142d000059897dfc8b450c89466c85c07508a130e7' \
'400089466cff766ce8722e000059c745fcfeffffffe815000000e8050a0000c333ff47' \
'8b75086a0de8fc2b000059c36a0ce8f32b000059c38bff5657ff1580b04000ff3514e0' \
'40008bf8e874feffffffd08bf085f6754e68140200006a01e8ce0c00008bf0595985f6' \
'743a56ff3514e04000ff3584f54000e8abfdffff59ffd085c074186a0056e8c5feffff' \
'5959ff15c4b04000834e04ff8906eb0956e8bc0b00005933f657ff15c0b040005f8bc6' \
'5ec38bff56e87fffffff8bf085f675086a10e8ae040000598bc65ec36a086878c54000' \
'e8080900008b750885f60f84f80000008b462485c0740750e86f0b0000598b462c85c0' \
'740750e8610b0000598b463485c0740750e8530b0000598b463c85c0740750e8450b00' \
'00598b464085c0740750e8370b0000598b464485c0740750e8290b0000598b464885c0' \
'740750e81b0b0000598b465c3d00b34000740750e80a0b0000596a0de8a72b00005983' \
'65fc008b7e6885ff741a57ff1548b0400085c0750f81ff40e74000740757e8dd0a0000' \
'59c745fcfeffffffe8570000006a0ce86e2b000059c745fc010000008b7e6c85ff7423' \
'57e8642d0000593b3d30e74000741481ff58e64000740c833f00750757e8702b000059' \
'c745fcfeffffffe81e00000056e8850a000059e845080000c204008b75086a0de83d2a' \
'000059c38b75086a0ce8312a000059c38bff558bec833d14e04000ff744b837d080075' \
'2756ff3518e040008b35b0b04000ffd685c07413ff3514e04000ff3518e04000ffd6ff' \
'd08945085e6a00ff3514e04000ff3584f54000e8e0fbffff59ffd0ff7508e878feffff' \
'a118e0400083f8ff74096a0050ff15b8b040005dc38bff5657be80b2400056ff15a8b0' \
'400085c0750756e8c2020000598bf885ff0f845e0100008b35acb0400068ccb2400057' \
'ffd668c0b2400057a37cf54000ffd668b4b2400057a380f54000ffd668acb2400057a3' \
'84f54000ffd6833d7cf54000008b35b8b04000a388f540007416833d80f5400000740d' \
'833d84f5400000740485c07524a1b0b04000a380f54000a1bcb04000c7057cf54000a3' \
'1f4000893584f54000a388f54000ff15b4b04000a318e0400083f8ff0f84cc000000ff' \
'3580f5400050ffd685c00f84bb000000e8f4040000ff357cf54000e868faffffff3580' \
'f54000a37cf54000e858faffffff3584f54000a380f54000e848faffffff3588f54000' \
'a384f54000e838faffff83c410a388f54000e80528000085c0746568d4214000ff357c' \
'f54000e892faffff59ffd0a314e0400083f8ff744868140200006a01e8820900008bf0' \
'595985f6743456ff3514e04000ff3584f54000e85ffaffff59ffd085c0741b6a0056e8' \
'79fbffff5959ff15c4b04000834e04ff890633c040eb07e824fbffff33c05f5ec3cccc' \
'8bff558bec8b4d08b84d5a0000663901740433c05dc38b413c03c181385045000075ef' \
'33d2b90b010000663948180f94c28bc25dc3cccccccccccccccccccccc8bff558bec8b' \
'45088b483c03c80fb7411453560fb7710633d2578d44081885f6761b8b7d0c8b480c3b' \
'f972098b580803d93bfb720a4283c0283bd672e833c05f5e5b5dc3cccccccccccccccc' \
'cccccccc8bff558bec6afe68a0c5400068502b400064a1000000005083ec08535657a1' \
'00e040003145f833c5508d45f064a3000000008965e8c745fc000000006800004000e8' \
'2affffff83c40485c074558b45082d00004000506800004000e850ffffff83c40885c0' \
'743b8b4024c1e81ff7d083e001c745fcfeffffff8b4df064890d00000000595f5e5b8b' \
'e55dc38b45ec8b088b0133d23d050000c00f94c28bc2c38b65e8c745fcfeffffff33c0' \
'8b4df064890d00000000595f5e5b8be55dc38bff558bec57bfe803000057ff15c8b040' \
'00ff7508ff15a8b0400081c7e803000081ff60ea0000770485c074de5f5dc38bff558b' \
'ece8f81d0000ff7508e8451c0000ff351ce04000e897f8ffff68ff000000ffd083c40c' \
'5dc38bff558bec68e8b24000ff15a8b0400085c0741568d8b2400050ff15acb0400085' \
'c07405ff7508ffd05dc38bff558becff7508e8c8ffffff59ff7508ff15ccb04000cc6a' \
'08e81c27000059c36a08e83926000059c38bff558bec568bf0eb0b8b0685c07402ffd0' \
'83c6043b750872f05e5dc38bff558bec568b750833c0eb0f85c075108b0e85c97402ff' \
'd183c6043b750c72ec5e5dc38bff558bec833d180e410000741968180e4100e83cfeff' \
'ff5985c0740aff7508ff15180e410059e81d32000068a8b140006890b14000e8a1ffff' \
'ff595985c07542689c4b4000e8e7310000b888b14000c704248cb14000e863ffffff83' \
'3d1c0e41000059741b681c0e4100e8e4fdffff5985c0740c6a006a026a00ff151c0e41' \
'0033c05dc36a1868c0c54000e81b0300006a08e838260000598365fc0033db43391dbc' \
'f540000f84c5000000891db8f540008a4510a2b4f54000837d0c000f859d000000ff35' \
'100e4100e826f7ffff598bf8897dd885ff7478ff350c0e4100e811f7ffff598bf08975' \
'dc897de48975e083ee048975dc3bf77257e8edf6ffff390674ed3bf7724aff36e8e7f6' \
'ffff8bf8e8d7f6ffff8906ffd7ff35100e4100e8d1f6ffff8bf8ff350c0e4100e8c4f6' \
'ffff83c40c397de475053945e0740e897de4897dd88945e08bf08975dc8b7dd8eb9f68' \
'b8b14000b8acb14000e85ffeffff5968c0b14000b8bcb14000e84ffeffff59c745fcfe' \
'ffffffe81f000000837d10007528891dbcf540006a08e86624000059ff7508e8fcfdff' \
'ff33db43837d100074086a08e84d24000059c3e841020000c38bff558bec6a006a00ff' \
'7508e8c3feffff83c40c5dc38bff558bec6a006a01ff7508e8adfeffff83c40c5dc36a' \
'016a006a00e89dfeffff83c40cc36a016a016a00e88efeffff83c40cc38bff56e8e9f5' \
'ffff8bf056e84833000056e8d332000056e88105000056e8b832000056e8a332000056' \
'e88b30000056e81a00000056e86e3000006803294000e83bf5ffff83c424a31ce04000' \
'5ec3c38bff558bec515156e8aef7ffff8bf085f60f84460100008b565ca12ce0400057' \
'8b7d088bca533939740e8bd86bdb0c83c10c03da3bcb72ee6bc00c03c23bc873083939' \
'75048bc1eb0233c085c0740a8b5808895dfc85db750733c0e9fb00000083fb05750c83' \
'60080033c040e9ea00000083fb010f84de0000008b4e60894df88b4d0c894e608b4804' \
'83f9080f85b80000008b0d20e040008b3d24e040008bd103f93bd77d246bc90c8b7e5c' \
'83643908008b3d20e040008b1d24e040004203df83c10c3bd37ce28b5dfc8b008b7e64' \
'3d8e0000c07509c7466483000000eb5e3d900000c07509c7466481000000eb4e3d9100' \
'00c07509c7466484000000eb3e3d930000c07509c7466485000000eb2e3d8d0000c075' \
'09c7466482000000eb1e3d8f0000c07509c7466486000000eb0e3d920000c07507c746' \
'648a000000ff76646a08ffd359897e64eb078360080051ffd38b45f85989466083c8ff' \
'5b5f5ec9c3cccc68502b400064ff35000000008b442410896c24108d6c24102be05356' \
'57a100e040003145fc33c5508965e8ff75f88b45fcc745fcfeffffff8945f88d45f064' \
'a300000000c38b4df064890d00000000595f5f5e5b8be55d51c3cccccccccccccccccc' \
'cccccccccccc8bff558bec83ec18538b5d0c568b7308333500e04000578b06c645ff00' \
'c745f4010000008d7b1083f8fe740d8b4e0403cf330c38e8e1ecffff8b4e0c8b460803' \
'cf330c38e8d1ecffff8b4508f64004660f85160100008b4d108d55e88953fc8b5b0c89' \
'45e8894dec83fbfe745f8d49008d045b8b4c86148d4486108945f08b008945f885c974' \
'148bd7e8dc310000c645ff0185c07c407f478b45f88bd883f8fe75ce807dff0074248b' \
'0683f8fe740d8b4e0403cf330c38e85eecffff8b4e0c8b560803cf330c3ae84eecffff' \
'8b45f45f5e5b8be55dc3c745f400000000ebc98b4d08813963736de07529833d040e41' \
'0000742068040e4100e843f9ffff83c40485c0740f8b55086a0152ff15040e410083c4' \
'088b4d0ce87f3100008b450c39580c74126800e04000578bd38bc8e8823100008b450c' \
'8b4df889480c8b0683f8fe740d8b4e0403cf330c38e8cbebffff8b4e0c8b560803cf33' \
'0c3ae8bbebffff8b45f08b48088bd7e815310000bafeffffff39530c0f8452ffffff68' \
'00e04000578bcbe82d310000e91cffffff8bff558bec8b450833c93b04cd30e0400074' \
'134183f92d72f18d48ed83f911770e6a0d585dc38b04cd34e040005dc30544ffffff6a' \
'0e593bc81bc023c183c0085dc3e81ef4ffff85c07506b898e14000c383c008c3e80bf4' \
'ffff85c07506b89ce14000c383c00cc38bff558bec56e8e2ffffff8b4d08518908e882' \
'ffffff598bf0e8bcffffff89305e5dc36a0c68e0c54000e875fdffff8b750885f67475' \
'833dbcfc40000375436a04e882200000598365fc0056e886300000598945e485c07409' \
'5650e8a73000005959c745fcfeffffffe80b000000837de4007537ff7508eb0a6a04e8' \
'6e1f000059c3566a00ff35fcf94000ff15d0b0400085c07516e840ffffff8bf0ff1580' \
'b0400050e8f0feffff890659e839fdffffc38bff558bec565733f6ff7508e8283b0000' \
'8bf85985ff75273905c0f54000761f56ff15c8b040008d86e80300003b05c0f5400076' \
'0383c8ff8bf083f8ff75ca8bc75f5e5dc38bff558bec565733f66a00ff750cff7508e8' \
'a83b00008bf883c40c85ff75273905c0f54000761f56ff15c8b040008d86e80300003b' \
'05c0f54000760383c8ff8bf083f8ff75c38bc75f5e5dc38bff558bec565733f6ff750c' \
'ff7508e87c3c00008bf8595985ff752c39450c74273905c0f54000761f56ff15c8b040' \
'008d86e80300003b05c0f54000760383c8ff8bf083f8ff75c18bc75f5e5dc38bff558b' \
'ec8b4508a3c4f540005dc38bff558bec81ec28030000a100e0400033c58945fc83a5d8' \
'fcffff00536a4c8d85dcfcffff6a0050e870ecffff8d85d8fcffff898528fdffff8d85' \
'30fdffff83c40c89852cfdffff8985e0fdffff898ddcfdffff8995d8fdffff899dd4fd' \
'ffff89b5d0fdffff89bdccfdffff668c95f8fdffff668c8decfdffff668c9dc8fdffff' \
'668c85c4fdffff668ca5c0fdffff668cadbcfdffff9c8f85f0fdffff8b45048d4d04c7' \
'8530fdffff010001008985e8fdffff898df4fdffff8b49fc898de4fdffffc785d8fcff' \
'ff170400c0c785dcfcffff010000008985e4fcffffff15a4b040006a008bd8ff15a0b0' \
'40008d8528fdffff50ff159cb0400085c0750c85db75086a02e89d1c00005968170400' \
'c0ff1598b0400050ff1594b040008b4dfc33cd5be861e8ffffc9c38bff558becff35c4' \
'f54000e816efffff5985c074035dffe06a02e85e1c0000595de9b2feffffb8a0e14000' \
'c3a1000e4100566a145e85c07507b800020000eb063bc67d078bc6a3000e41006a0450' \
'e8dcfdffff5959a3e4fd400085c0751e6a04568935000e4100e8c3fdffff5959a3e4fd' \
'400085c075056a1a585ec333d2b9a0e14000eb05a1e4fd4000890c0283c12083c20481' \
'f920e440007cea6afe5e33d2b9b0e14000578bc2c1f8058b0485e0fc40008bfa83e71f' \
'c1e7068b040783f8ff74083bc6740485c07502893183c1204281f910e240007cce5f33' \
'c05ec3e86d3e0000803db4f54000007405e8363c0000ff35e4fd4000e861fcffff59c3' \
'8bff558bec568b7508b8a0e140003bf0722281fe00e44000771a8bce2bc8c1f90583c1' \
'1051e8da1c0000814e0c0080000059eb0a83c62056ff15d4b040005e5dc38bff558bec' \
'8b450883f8147d1683c01050e8ad1c00008b450c81480c00800000595dc38b450c83c0' \
'2050ff15d4b040005dc38bff558bec8b4508b9a0e140003bc1721f3d00e44000771881' \
'600cff7fffff2bc1c1f80583c01050e88a1b0000595dc383c02050ff15d8b040005dc3' \
'8bff558bec8b4d0883f9148b450c7d1381600cff7fffff83c11051e85b1b0000595dc3' \
'83c02050ff15d8b040005dc38bff558bec568b750856e8d23d000050e8683d00005959' \
'85c0747ce82bfeffff83c0203bf0750433c0eb0fe81bfeffff83c0403bf0756033c040' \
'ff05c8f54000f7460c0c010000754e53578d3c85ccf54000833f00bb00100000752053' \
'e8adfbffff59890785c075138d46146a02894608890658894618894604eb0d8b3f897e' \
'08893e895e18895e04814e0c0211000033c05f405beb0233c05e5dc38bff558bec837d' \
'08007427568b750cf7460c00100000741956e8303b000081660cffeeffff8366180083' \
'260083660800595e5dc38bff558bec8b4508568bf1c6460c0085c07563e8eceeffff89' \
'46088b486c890e8b4868894e048b0e3b0d30e7400074128b0d88ec40008548707507e8' \
'f81d000089068b46043b0568eb400074168b46088b0d88ec40008548707508e8742000' \
'008946048b4608f6407002751483487002c6460c01eb0a8b08890e8b40048946048bc6' \
'5e5dc20400f6410c407406837908007424ff4904780b8b118802ff010fb6c0eb0c0fbe' \
'c05150e8180c0000595983f8ff75030906c3ff06c38bff558bec568bf0eb138b4d108a' \
'4508ff4d0ce8b5ffffff833eff7406837d0c007fe75e5dc38bff558becf6470c405356' \
'8bf08bd97432837f0800752c8b45080106eb2b8a03ff4d088bcfe87dffffff43833eff' \
'7513e853f9ffff83382a750f8bcfb03fe864ffffff837d08007fd55e5b5dc38bff558b' \
'ec81ec78020000a100e0400033c58945fc538b5d0c568b750833c0578b7d14ff75108d' \
'8da4fdffff89b5b4fdffff89bddcfdffff8985b8fdffff8985f0fdffff8985ccfdffff' \
'8985e8fdffff8985d0fdffff8985c0fdffff8985c8fdffffe86cfeffff85f67535e8cb' \
'f8ffffc7001600000033c05050505050e8a6fbffff83c41480bdb0fdffff00740a8b85' \
'acfdffff836070fd83c8ffe9c80a0000f6460c40755e56e8383b000059bae0e4400083' \
'f8ff741b83f8fe74168bc883e11f8bf0c1fe05c1e106030cb5e0fc4000eb028bcaf641' \
'247f759183f8ff741983f8fe74148bc883e01fc1f905c1e00603048de0fc4000eb028b' \
'c2f64024800f8567ffffff33c93bd90f845dffffff8a13898dd8fdffff898de0fdffff' \
'898dbcfdffff8895effdffff84d20f841f0a00004383bdd8fdffff00899dc4fdffff0f' \
'8c0b0a00008ac22c203c5877110fbec20fbe8070b3400083e00f33f6eb0433f633c00f' \
'be84c190b340006a07c1f80459898594fdffff3bc10f87ad090000ff24855b3f400083' \
'8de8fdffffff89b590fdffff89b5c0fdffff89b5ccfdffff89b5d0fdffff89b5f0fdff' \
'ff89b5c8fdffffe9760900000fbec283e820744a83e803743683e80874254848741583' \
'e8030f8557090000838df0fdffff08e94b090000838df0fdffff04e93f090000838df0' \
'fdffff01e933090000818df0fdffff80000000e924090000838df0fdffff02e9180900' \
'0080fa2a752c83c70489bddcfdffff8b7ffc3bfe89bdccfdffff0f8df9080000838df0' \
'fdffff04f79dccfdffffe9e70800008b85ccfdffff6bc00a0fbeca8d4408d08985ccfd' \
'ffffe9cc08000089b5e8fdffffe9c108000080fa2a752683c70489bddcfdffff8b7ffc' \
'3bfe89bde8fdffff0f8da2080000838de8fdffffffe9960800008b85e8fdffff6bc00a' \
'0fbeca8d4408d08985e8fdffffe97b08000080fa49745580fa68744480fa6c741880fa' \
'770f8563080000818df0fdffff00080000e954080000803b6c751643818df0fdffff00' \
'100000899dc4fdffffe939080000838df0fdffff10e92d080000838df0fdffff20e921' \
'0800008a033c36751d807b013475174343818df0fdffff00800000899dc4fdffffe9fe' \
'0700003c33751d807b01327517434381a5f0fdffffff7fffff899dc4fdffffe9dd0700' \
'003c640f84d50700003c690f84cd0700003c6f0f84c50700003c750f84bd0700003c78' \
'0f84b50700003c580f84ad07000089b594fdffff8d85a4fdffff500fb6c25089b5c8fd' \
'ffffe8983a00005985c08a85effdffff5974228b8db4fdffff8db5d8fdffffe8a4fbff' \
'ff8a0343899dc4fdffff84c00f84a4fcffff8b8db4fdffff8db5d8fdffffe882fbffff' \
'e94d0700000fbec283f8640f8fe80100000f847902000083f8530f8ff20000000f8480' \
'00000083e8417410484874584848740848480f859205000080c220c78590fdffff0100' \
'00008895effdffff838df0fdffff4039b5e8fdffff8d9df4fdffffb800020000899de4' \
'fdffff8985a0fdffff0f8d48020000c785e8fdffff06000000e9a5020000f785f0fdff' \
'ff300800000f8598000000818df0fdffff00080000e989000000f785f0fdffff300800' \
'00750a818df0fdffff000800008b8de8fdffff83f9ff7505b9ffffff7f83c704f785f0' \
'fdffff1008000089bddcfdffff8b7ffc89bde4fdffff0f84b10400003bfe750ba124e4' \
'40008985e4fdffff8b85e4fdffffc785c8fdffff01000000e97f04000083e8580f84da' \
'020000484874792bc10f8427ffffff48480f859e04000083c704f785f0fdffff100800' \
'0089bddcfdffff74300fb747fc5068000200008d85f4fdffff508d85e0fdffff50e8db' \
'38000083c41085c0741fc785c0fdffff01000000eb138a47fc8885f4fdffffc785e0fd' \
'ffff010000008d85f4fdffff8985e4fdffffe9350400008b0783c70489bddcfdffff3b' \
'c6743b8b48043bce7434f785f0fdffff000800000fbf00898de4fdffff7414992bc2d1' \
'f8c785c8fdffff01000000e9f003000089b5c8fdffffe9e5030000a120e440008985e4' \
'fdffff50e85236000059e9ce03000083f8700f8ffb0100000f84e301000083f8650f8c' \
'bc03000083f8670f8e34feffff83f869747183f86e742883f86f0f85a0030000f685f0' \
'fdffff80c785e0fdffff080000007461818df0fdffff00020000eb558b3783c70489bd' \
'dcfdffffe8cbe0ffff85c00f842ffafffff685f0fdffff20740c668b85d8fdffff6689' \
'06eb088b85d8fdffff8906c785c0fdffff01000000e9a6040000838df0fdffff40c785' \
'e0fdffff0a0000008b8df0fdfffff7c1008000000f84a90100008b078b570483c708e9' \
'd5010000751180fa677565c785e8fdffff01000000eb593985e8fdffff7e068985e8fd' \
'ffff81bde8fdffffa30000007e3f8bb5e8fdffff81c65d01000056e83bf3ffff8a95ef' \
'fdffff598985bcfdffff85c074108985e4fdffff89b5a0fdffff8bd8eb0ac785e8fdff' \
'ffa300000033f68b0783c708898588fdffff8b47fc89858cfdffff8d85a4fdffff50ff' \
'b590fdffff0fbec2ffb5e8fdffff89bddcfdffff50ffb5a0fdffff8d8588fdffff5350' \
'ff3578ec4000e800e4ffff59ffd08bbdf0fdffff83c41c81e780000000742039b5e8fd' \
'ffff75188d85a4fdffff5053ff3584ec4000e8d1e3ffff59ffd0595980bdeffdffff67' \
'751c3bfe75188d85a4fdffff5053ff3580ec4000e8ace3ffff59ffd05959803b2d7511' \
'818df0fdffff0001000043899de4fdffff53e903feffffc785e8fdffff08000000898d' \
'b8fdffffeb2483e8730f84b6fcffff48480f8489feffff83e8030f85b6010000c785b8' \
'fdffff27000000f685f0fdffff80c785e0fdffff100000000f8469feffff8a85b8fdff' \
'ff0451c685d4fdffff308885d5fdffffc785d0fdffff02000000e945fefffff7c10010' \
'00000f854bfeffff83c704f6c120741889bddcfdfffff6c14074060fbf47fceb040fb7' \
'47fc99eb138b47fcf6c140740399eb0233d289bddcfdfffff6c140741b3bd67f177c04' \
'3bc67311f7d883d200f7da818df0fdffff00010000f785f0fdffff009000008bda8bf8' \
'750233db83bde8fdffff007d0cc785e8fdffff01000000eb1a83a5f0fdfffff7b80002' \
'00003985e8fdffff7e068985e8fdffff8bc70bc375062185d0fdffff8d75f38b85e8fd' \
'ffffff8de8fdffff85c07f068bc70bc3742d8b85e0fdffff9952505357e87435000083' \
'c13083f939899da0fdffff8bf88bda7e06038db8fdffff880e4eebbd8d45f32bc646f7' \
'85f0fdffff000200008985e0fdffff89b5e4fdffff746185c074078bce8039307456ff' \
'8de4fdffff8b8de4fdffffc6013040eb3e49663930740640403bce75f42b85e4fdffff' \
'd1f8eb283bfe750ba120e440008985e4fdffff8b85e4fdffffeb07498038007405403b' \
'ce75f52b85e4fdffff8985e0fdffff83bdc0fdffff000f855c0100008b85f0fdffffa8' \
'407432a9000100007409c685d4fdffff2deb18a8017409c685d4fdffff2beb0ba80274' \
'11c685d4fdffff20c785d0fdffff010000008b9dccfdffff2b9de0fdffff2b9dd0fdff' \
'fff685f0fdffff0c7517ffb5b4fdffff8d85d8fdffff536a20e870f5ffff83c40cffb5' \
'd0fdffff8bbdb4fdffff8d85d8fdffff8d8dd4fdffffe876f5fffff685f0fdffff0859' \
'741bf685f0fdffff04751257536a308d85d8fdffffe82ef5ffff83c40c83bdc8fdffff' \
'008b85e0fdffff746685c07e628bb5e4fdffff8985a0fdffff0fb706ff8da0fdffff50' \
'6a068d45f4508d8598fdffff465046e87533000083c41085c07528398598fdffff7420' \
'ffb598fdffff8d85d8fdffff8d4df4e8f1f4ffff83bda0fdffff005975b5eb1c838dd8' \
'fdffffffeb138b8de4fdffff508d85d8fdffffe8caf4ffff5983bdd8fdffff007c1bf6' \
'85f0fdffff04741257536a208d85d8fdffffe882f4ffff83c40c83bdbcfdffff007413' \
'ffb5bcfdffffe862eeffff83a5bcfdffff00598b9dc4fdffff8a038885effdffff84c0' \
'74138b8d94fdffff8bbddcfdffff8ad0e9e1f5ffff80bdb0fdffff00740a8b85acfdff' \
'ff836070fd8b85d8fdffff8b4dfc5f5e33cd5be812d9ffffc9c3906637400067354000' \
'97354000f5354000413640004c36400092364000c03740008bff558bec51568b750c56' \
'e83c30000089450c8b460c59a8827517e883edffffc70009000000834e0c2083c8ffe9' \
'2f010000a840740de868edffffc70022000000ebe35333dba8017416895e04a8100f84' \
'870000008b4e0883e0fe890e89460c8b460c83e0ef83c80289460c895e04895dfca90c' \
'010000752ce838f0ffff83c0203bf0740ce82cf0ffff83c0403bf0750dff750ce84f2f' \
'00005985c0750756e8833c000059f7460c08010000570f84800000008b46088b3e8d48' \
'01890e8b4e182bf8493bfb894e047e1d5750ff750ce8773b000083c40c8945fceb4d83' \
'c82089460c83c8ffeb798b4d0c83f9ff741b83f9fe74168bc183e01f8bd1c1fa05c1e0' \
'06030495e0fc4000eb05b8e0e44000f640042074146a02535351e8e032000023c283c4' \
'1083f8ff74258b46088a4d088808eb1633ff47578d450850ff750ce8083b000083c40c' \
'8945fc397dfc7409834e0c2083c8ffeb088b450825ff0000005f5b5ec9c3558bec83ec' \
'04897dfc8b7d088b4d0cc1e907660fefc0eb088da4240000000090660f7f07660f7f47' \
'10660f7f4720660f7f4730660f7f4740660f7f4750660f7f4760660f7f47708dbf8000' \
'00004975d08b7dfc8be55dc3558bec83ec10897dfc8b4508998bf833fa2bfa83e70f33' \
'fa2bfa85ff753c8b4d108bd183e27f8955f43bca74122bca5150e873ffffff83c4088b' \
'45088b55f485d274450345102bc28945f833c08b7df88b4df4f3aa8b4508eb2ef7df83' \
'c710897df033c08b7d088b4df0f3aa8b45f08b4d088b551003c82bd0526a0051e87eff' \
'ffff83c40c8b45088b7dfc8be55dc36a0c6800c64000e817e9ffff8365fc00660f28c1' \
'c745e401000000eb238b45ec8b008b003d050000c0740a3d1d0000c0740333c0c333c0' \
'40c38b65e88365e400c745fcfeffffff8b45e4e819e9ffffc38bff558bec83ec1833c0' \
'538945fc8945f48945f8539c588bc83500002000509d9c5a2bd1741f519d33c00fa289' \
'45f4895de88955ec894df0b8010000000fa28955fc8945f85bf745fc00000004740ee8' \
'5cffffff85c0740533c040eb0233c05bc9c3e899ffffffa3e0fd400033c0c38bff558b' \
'ec8b45088b00813863736de0752a8378100375248b40143d2005931974153d21059319' \
'740e3d2205931974073d004099017505e8e616000033c05dc204006884424000ff15a0' \
'b0400033c0c38bff558bec5151538b5d08565733f633ff897dfc3b1cfd28e440007409' \
'47897dfc83ff1772ee83ff170f83770100006a03e8dc3c00005983f8010f8434010000' \
'6a03e8cb3c00005985c0750d833d10e04000010f841b01000081fbfc0000000f844101' \
'00006890b94000bb1403000053bfd8f5400057e82e3c000083c40c85c0740d56565656' \
'56e883ebffff83c4146804010000bef1f54000566a00c605f5f6400000ff15e0b04000' \
'85c075266878b9400068fb02000056e8ec3b000083c40c85c0740f33c05050505050e8' \
'3febffff83c41456e8532c0000405983f83c763856e8462c000083ee3b03c66a03b9ec' \
'f840006874b940002bc85150e8f43a000083c41485c0741133f65656565656e8fceaff' \
'ff83c414eb0233f66870b940005357e85a3a000083c40c85c0740d5656565656e8d8ea' \
'ffff83c4148b45fcff34c52ce440005357e8353a000083c40c85c0740d5656565656e8' \
'b3eaffff83c41468102001006848b9400057e8a838000083c40ceb326af4ff15dcb040' \
'008bd83bde742483fbff741f6a008d45f8508d34fd2ce44000ff36e8912b00005950ff' \
'3653ff153cb040005f5e5bc9c36a03e8603b00005983f80174156a03e8533b00005985' \
'c0751f833d10e0400001751668fc000000e829feffff68ff000000e81ffeffff5959c3' \
'833d140e4100007505e863130000568b3548f240005733ff85f6751883c8ffe9a00000' \
'003c3d74014756e8192b0000598d7406018a0684c075ea6a044757e83fe9ffff8bf859' \
'59893d9cf5400085ff74cb8b3548f2400053eb4256e8e82a00008bd843803e3d597431' \
'6a0153e811e9ffff5959890785c0744e565350e8443a000083c40c85c0740f33c05050' \
'505050e897e9ffff83c41483c70403f3803e0075b9ff3548f24000e803e8ffff832548' \
'f2400000832700c705080e41000100000033c0595b5f5ec3ff359cf54000e8dde7ffff' \
'83259cf540000083c8ffebe48bff558bec518b4d105333c05689078bf28b550cc70101' \
'00000039450874098b5d088345080489138945fc803e22751033c03945fcb3220f94c0' \
'468945fceb3cff0785d274088a0688024289550c8a1e0fb6c35046e8943a00005985c0' \
'7413ff07837d0c00740a8b4d0c8a06ff450c8801468b550c8b4d1084db7432837dfc00' \
'75a980fb20740580fb09759f85d27404c642ff008365fc00803e000f84e90000008a06' \
'3c2074043c09750646ebf34eebe3803e000f84d0000000837d080074098b4508834508' \
'048910ff0133db4333c9eb024641803e5c74f9803e227526f6c101751f837dfc00740c' \
'8d460180382275048bf0eb0d33c033db3945fc0f94c08945fcd1e985c974124985d274' \
'04c6025c42ff0785c975f189550c8a0684c07455837dfc0075083c20744b3c09744785' \
'db743d0fbec05085d27423e8af3900005985c0740d8a068b4d0cff450c880146ff078b' \
'4d0c8a06ff450c8801eb0de88c3900005985c0740346ff07ff078b550c46e956ffffff' \
'85d27407c602004289550cff078b4d10e90effffff8b45085e5b85c07403832000ff01' \
'c9c38bff558bec83ec0c5333db5657391d140e41007505e8df1000006804010000bef0' \
'f840005653881df4f94000ff15e0b04000a1200e41008935acf540003bc374078945fc' \
'381875038975fc8b55fc8d45f85053538d7df4e80afeffff8b45f883c40c3dffffff3f' \
'734a8b4df483f9ff73428bf8c1e7028d040f3bc1723650e842e6ffff8bf0593bf37429' \
'8b55fc8d45f85003fe57568d7df4e8c9fdffff8b45f883c40c48a390f54000893594f5' \
'400033c0eb0383c8ff5f5e5bc9c38bff558beca1f8f9400083ec0c53568b35f4b04000' \
'5733db33ff3bc3752effd68bf83bfb740cc705f8f9400001000000eb23ff1580b04000' \
'83f878750a6a0258a3f8f94000eb05a1f8f9400083f8010f85810000003bfb750fffd6' \
'8bf83bfb750733c0e9ca0000008bc766391f740e404066391875f9404066391875f28b' \
'35f0b040005353532bc753d1f840505753538945f4ffd68945f83bc3742f50e868e5ff' \
'ff598945fc3bc374215353ff75f850ff75f4575353ffd685c0750cff75fce8b8e4ffff' \
'59895dfc8b5dfc57ff15ecb040008bc3eb5c83f80274043bc37582ff15e8b040008bf0' \
'3bf30f8472ffffff381e740a40381875fb40381875f62bc640508945f8e801e5ffff8b' \
'f8593bfb750c56ff15e4b04000e945ffffffff75f85657e88f37000083c40c56ff15e4' \
'b040008bc75f5e5bc9c36a546820c64000e8bae1ffff33ff897dfc8d459c50ff1500b1' \
'4000c745fcfeffffff6a406a205e56e8ebe4ffff59593bc70f8414020000a3e0fc4000' \
'8935c0fc40008d8800080000eb30c64004008308ffc640050a897808c6402400c64025' \
'0ac640260a897838c640340083c0408b0de0fc400081c1000800003bc172cc66397dce' \
'0f840a0100008b45d03bc70f84ff0000008b388d58048d043b8945e4be000800003bfe' \
'7c028bfec745e001000000eb5b6a406a20e85de4ffff595985c074568b4de08d0c8de0' \
'fc400089018305c0fc4000208d9000080000eb2ac64004008308ffc640050a83600800' \
'80602480c640250ac640260a83603800c640340083c0408b1103d63bc272d2ff45e039' \
'3dc0fc40007c9deb068b3dc0fc40008365e00085ff7e6d8b45e48b0883f9ff745683f9' \
'fe74518a03a801744ba808750b51ff15fcb0400085c0743c8b75e08bc6c1f80583e61f' \
'c1e606033485e0fc40008b45e48b0089068a0388460468a00f00008d460c50e8951100' \
'00595985c00f84c9000000ff4608ff45e0438345e404397de07c9333db8bf3c1e60603' \
'35e0fc40008b0683f8ff740b83f8fe7406804e0480eb72c646048185db75056af658eb' \
'0a8bc348f7d81bc083c0f550ff15dcb040008bf883ffff744385ff743f57ff15fcb040' \
'0085c07434893e25ff00000083f8027506804e0440eb0983f8037504804e040868a00f' \
'00008d460c50e8ff100000595985c07437ff4608eb0a804e0440c706feffffff4383fb' \
'030f8c67ffffffff35c0fc4000ff15f8b0400033c0eb1133c040c38b65e8c745fcfeff' \
'ffff83c8ffe8b8dfffffc38bff56b8e0c44000bee0c44000578bf83bc6730f8b0785c0' \
'7402ffd083c7043bfe72f15f5ec38bff56b8e8c44000bee8c44000578bf83bc6730f8b' \
'0785c07402ffd083c7043bfe72f15f5ec38bff558bec33c03945086a000f94c0680010' \
'000050ff1508b14000a3fcf9400085c075025dc333c040a3bcfc40005dc38bff558bec' \
'83ec10a100e040008365f8008365fc005357bf4ee640bbbb0000ffff3bc7740d85c374' \
'09f7d0a304e04000eb60568d45f850ff1518b140008b75fc3375f8ff1564b0400033f0' \
'ff15c4b0400033f0ff1514b1400033f08d45f050ff1510b140008b45f43345f033f03b' \
'f77507be4fe640bbeb0b85f375078bc6c1e0100bf0893500e04000f7d6893504e04000' \
'5e5f5bc9c38325b8fc400000c38bff565733f6bf00fa4000833cf52ce5400001751e8d' \
'04f528e54000893868a00f0000ff3083c718e8720f0000595985c0740c4683fe247cd2' \
'33c0405f5ec38324f528e540000033c0ebf18bff538b1d04b1400056be28e54000578b' \
'3e85ff7413837e0401740d57ffd357e867e0ffff8326005983c60881fe48e640007cdc' \
'be28e540005f8b0685c07409837e0401750350ffd383c60881fe48e640007ce65e5bc3' \
'8bff558bec8b4508ff34c528e54000ff15d8b040005dc36a0c6840c64000e893ddffff' \
'33ff47897de433db391dfcf940007518e815f7ffff6a1ee863f5ffff68ff000000e856' \
'd9ffff59598b75088d34f528e54000391e74048bc7eb6e6a18e85fe0ffff598bf83bfb' \
'750fe87cdfffffc7000c00000033c0eb516a0ae85900000059895dfc391e752c68a00f' \
'000057e8690e0000595985c0751757e895dfffff59e846dfffffc7000c000000895de4' \
'eb0b893eeb0757e87adfffff59c745fcfeffffffe8090000008b45e4e82bddffffc36a' \
'0ae828ffffff59c38bff558bec8b4508568d34c528e54000833e00751350e822ffffff' \
'5985c075086a11e84ad8ffff59ff36ff15d4b040005e5dc38bff558bec53568b75088b' \
'86bc00000033db573bc3746f3d58ed400074688b86b00000003bc3745e3918755a8b86' \
'b80000003bc374173918751350e8e8deffffffb6bc000000e85537000059598b86b400' \
'00003bc374173918751350e8c7deffffffb6bc000000e8ef3600005959ffb6b0000000' \
'e8afdeffffffb6bc000000e8a4deffff59598b86c00000003bc37444391875408b86c4' \
'0000002dfe00000050e883deffff8b86cc000000bf800000002bc750e870deffff8b86' \
'd00000002bc750e862deffffffb6c0000000e857deffff83c4108dbed40000008b073d' \
'98ec400074173998b4000000750f50e8d5340000ff37e830deffff59598d7e50c74508' \
'06000000817ff850e6400074118b073bc3740b3918750750e80bdeffff59395ffc7412' \
'8b47043bc3740b3918750750e8f4ddffff5983c710ff4d0875c756e8e5ddffff595f5e' \
'5b5dc38bff558bec53568b3544b04000578b7d0857ffd68b87b000000085c0740350ff' \
'd68b87b800000085c0740350ffd68b87b400000085c0740350ffd68b87c000000085c0' \
'740350ffd68d5f50c7450806000000817bf850e6400074098b0385c0740350ffd6837b' \
'fc00740a8b430485c0740350ffd683c310ff4d0875d68b87d400000005b400000050ff' \
'd65f5e5b5dc38bff558bec578b7d0885ff0f848300000053568b3548b0400057ffd68b' \
'87b000000085c0740350ffd68b87b800000085c0740350ffd68b87b400000085c07403' \
'50ffd68b87c000000085c0740350ffd68d5f50c7450806000000817bf850e640007409' \
'8b0385c0740350ffd6837bfc00740a8b430485c0740350ffd683c310ff4d0875d68b87' \
'd400000005b400000050ffd65e5b8bc75f5dc385ff743785c07433568b303bf7742857' \
'8938e8c1feffff5985f6741b56e845ffffff833e0059750f81fe58e64000740756e859' \
'fdffff598bc75ec333c0c36a0c6860c64000e8eed9ffffe8bbd0ffff8bf0a188ec4000' \
'8546707422837e6c00741ce8a4d0ffff8b706c85f675086a20e859d5ffff598bc6e801' \
'daffffc36a0ce8d8fcffff598365fc008d466c8b3d30e74000e869ffffff8945e4c745' \
'fcfeffffffe802000000ebc16a0ce8d3fbffff598b75e4c32da4030000742283e80474' \
'1783e80d740c48740333c0c3b804040000c3b812040000c3b804080000c3b811040000' \
'c38bff56578bf0680101000033ff8d461c5750e8d6c9ffff33c00fb7c88bc1897e0489' \
'7e08897e0cc1e1100bc18d7e10abababb940e7400083c40c8d461c2bcebf010100008a' \
'14018810404f75f78d861d010000be000100008a14088810404e75f75f5ec38bff558b' \
'ec81ec1c050000a100e0400033c58945fc53578d85e8faffff50ff7604ff151cb14000' \
'bf0001000085c00f84fb00000033c0888405fcfeffff403bc772f48a85eefaffffc685' \
'fcfeffff2084c0742e8d9deffaffff0fb6c80fb6033bc877162bc140508d940dfcfeff' \
'ff6a2052e813c9ffff83c40c438a034384c075d86a00ff760c8d85fcfaffffff760450' \
'578d85fcfeffff506a016a00e88a36000033db53ff76048d85fcfdffff5750578d85fc' \
'feffff5057ff760c53e89d3a000083c44453ff76048d85fcfcffff5750578d85fcfeff' \
'ff506800020000ff760c53e8783a000083c42433c00fb78c45fcfafffff6c101740e80' \
'4c061d108a8c05fcfdffffeb11f6c1027415804c061d208a8c05fcfcffff888c061d01' \
'0000eb08c684061d01000000403bc772beeb568d861d010000c785e4faffff9fffffff' \
'33c92985e4faffff8b95e4faffff8d840e1d01000003d08d5a2083fb19770c804c0e1d' \
'108ad180c220eb0f83fa19770e804c0e1d208ad180ea208810eb03c60000413bcf72c2' \
'8b4dfc5f33cd5be8e2c4ffffc9c36a0c6880c64000e852d7ffffe81fceffff8bf8a188' \
'ec4000854770741d837f6c0074178b776885f675086a20e8c2d2ffff598bc6e86ad7ff' \
'ffc36a0de841faffff598365fc008b77688975e43b3568eb4000743685f6741a56ff15' \
'48b0400085c0750f81fe40e74000740756e86cd9ffff59a168eb40008947688b3568eb' \
'40008975e456ff1544b04000c745fcfeffffffe805000000eb8e8b75e46a0de806f9ff' \
'ff59c38bff558bec83ec105333db538d4df0e874deffff891d74fb400083fefe751ec7' \
'0574fb400001000000ff1524b14000385dfc74458b4df8836170fdeb3c83fefd7512c7' \
'0574fb400001000000ff1520b14000ebdb83fefc75128b45f08b4004c70574fb400001' \
'000000ebc4385dfc74078b45f8836070fd8bc65bc9c38bff558bec83ec20a100e04000' \
'33c58945fc538b5d0c568b750857e864ffffff8bf833f6897d083bfe750e8bc3e8b7fc' \
'ffff33c0e99d0100008975e433c039b870eb40000f8491000000ff45e483c0303df000' \
'000072e781ffe8fd00000f847001000081ffe9fd00000f84640100000fb7c750ff1528' \
'b1400085c00f84520100008d45e85057ff151cb1400085c00f84330100006801010000' \
'8d431c5650e833c6ffff33d24283c40c897b0489730c3955e80f86f8000000807dee00' \
'0f84cf0000008d75ef8a0e84c90f84c20000000fb646ff0fb6c9e9a600000068010100' \
'008d431c5650e8ecc5ffff8b4de483c40c6bc9308975e08db180eb40008975e4eb2a8a' \
'460184c074280fb63e0fb6c0eb128b45e08a806ceb400008443b1d0fb64601473bf876' \
'ea8b7d084646803e0075d18b75e4ff45e083c608837de0048975e472e98bc7897b04c7' \
'430801000000e867fbffff6a0689430c8d43108d8974eb40005a668b31416689304140' \
'404a75f38bf3e8d7fbffffe9b7feffff804c031d04403bc176f64646807eff000f8534' \
'ffffff8d431eb9fe000000800808404975f98b4304e812fbffff89430c895308eb0389' \
'730833c00fb7c88bc1c1e1100bc18d7b10abababeba8393574fb40000f8558feffff83' \
'c8ff8b4dfc5f5e33cd5be8ddc1ffffc9c36a1468a0c64000e84dd4ffff834de0ffe816' \
'cbffff8bf8897ddce8dcfcffff8b5f688b7508e875fdffff8945083b43040f84570100' \
'006820020000e826d7ffff598bd885db0f8446010000b9880000008b77688bfbf3a583' \
'230053ff7508e8b8fdffff59598945e085c00f85fc0000008b75dcff7668ff1548b040' \
'0085c075118b46683d40e74000740750e848d6ffff59895e68538b3d44b04000ffd7f6' \
'4670020f85ea000000f60588ec4000010f85dd0000006a0de8c2f6ffff598365fc008b' \
'4304a384fb40008b4308a388fb40008b430ca38cfb400033c08945e483f8057d10668b' \
'4c431066890c4578fb400040ebe833c08945e43d010100007d0d8a4c181c888860e940' \
'0040ebe933c08945e43d000100007d108a8c181d010000888868ea400040ebe6ff3568' \
'eb4000ff1548b0400085c07513a168eb40003d40e74000740750e88fd5ffff59891d68' \
'eb400053ffd7c745fcfeffffffe802000000eb306a0de83bf5ffff59c3eb2583f8ff75' \
'2081fb40e74000740753e859d5ffff59e80ad5ffffc70016000000eb048365e0008b45' \
'e0e805d3ffffc3833d140e41000075126afde856feffff59c705140e41000100000033' \
'c0c38bff558bec51535657ff35100e4100e8d6c6ffffff350c0e41008bf8897dfce8c6' \
'c6ffff8bf059593bf70f82830000008bde2bdf8d430483f804727757e8113500008bf8' \
'8d4304593bf87348b8000800003bf873028bc703c73bc7720f50ff75fce8d9d5ffff59' \
'5985c075168d47103bc7724050ff75fce8c3d5ffff595985c07431c1fb02508d3498e8' \
'e1c5ffff59a3100e4100ff7508e8d3c5ffff890683c60456e8c8c5ffff59a30c0e4100' \
'8b450859eb0233c05f5e5bc9c38bff566a046a20e82dd5ffff8bf056e8a1c5ffff83c4' \
'0ca3100e4100a30c0e410085f675056a18585ec383260033c05ec36a0c68c0c64000e8' \
'aad1ffffe8a6cdffff8365fc00ff7508e8f8feffff598945e4c745fcfeffffffe80900' \
'00008b45e4e8c6d1ffffc3e885cdffffc38bff558becff7508e8b7fffffff7d81bc0f7' \
'd859485dc38bff565733ff8db760ec4000ff36e81ec5ffff83c70459890683ff2872e8' \
'5f5ec36a0868e0c64000e836d1ffffe803c8ffff8b407885c074168365fc00ffd0eb07' \
'33c040c38b65e8c745fcfeffffffe86d340000e84fd1ffffc368a6594000e8cdc4ffff' \
'59a390fb4000c38bff558bec8b4508a394fb4000a398fb4000a39cfb4000a3a0fb4000' \
'5dc38bff558bec8b45088b0d2ce0400056395004740f8bf16bf60c03750883c00c3bc6' \
'72ec6bc90c034d085e3bc17305395004740233c05dc3ff359cfb4000e8e1c4ffff59c3' \
'6a206800c74000e88ad0ffff33ff897de4897dd88b5d0883fb0b7f4c74158bc36a0259' \
'2bc174222bc174082bc174642bc17544e8b7c6ffff8bf8897dd885ff751483c8ffe961' \
'010000be94fb4000a194fb4000eb60ff775c8bd3e85dffffff8bf083c6088b06eb5a8b' \
'c383e80f743c83e806742b48741ce850d2ffffc7001600000033c05050505050e82bd5' \
'ffff83c414ebaebe9cfb4000a19cfb4000eb16be98fb4000a198fb4000eb0abea0fb40' \
'00a1a0fb4000c745e40100000050e81dc4ffff8945e05933c0837de0010f84d8000000' \
'3945e075076a03e8d3cdffff3945e4740750e8d1f2ffff5933c08945fc83fb08740a83' \
'fb0b740583fb04751b8b4f60894dd489476083fb0875408b4f64894dd0c747648c0000' \
'0083fb08752e8b0d20e04000894ddc8b0d24e040008b1520e0400003ca394ddc7d198b' \
'4ddc6bc90c8b575c89441108ff45dcebdbe885c3ffff8906c745fcfeffffffe8150000' \
'0083fb08751fff776453ff55e059eb198b5d088b7dd8837de40074086a00e85ff1ffff' \
'59c353ff55e05983fb08740a83fb0b740583fb0475118b45d489476083fb0875068b45' \
'd089476433c0e82ccfffffc38bff558bec8b4508a3a8fb40005dc38bff558bec8b4508' \
'a3b4fb40005dc38bff558bec8b4508a3b8fb40005dc36a106820c74000e8adceffff83' \
'65fc00ff750cff7508ff1530b140008945e4eb2f8b45ec8b008b008945e033c93d1700' \
'00c00f94c18bc1c38b65e8817de0170000c075086a08ff15c0b040008365e400c745fc' \
'feffffff8b45e4e89fceffffc38bff558bec8b4508a3bcfb40005dc38bff558becff35' \
'bcfb4000e883c2ffff5985c0740fff7508ffd05985c0740533c0405dc333c05dc3cccc' \
'5356578b5424108b4424148b4c2418555250515168585d400064ff3500000000a100e0' \
'400033c489442408648925000000008b4424308b58088b4c242c33198b700c83fefe74' \
'3b8b54243483fafe74043bf2762e8d34768d5cb3108b0b89480c837b040075cc680101' \
'00008b4308e83a330000b9010000008b4308e84c330000ebb0648f050000000083c418' \
'5f5e5bc38b4c2404f7410406000000b80100000074338b4424088b480833c8e8f2baff' \
'ff558b6818ff700cff7010ff7014e83effffff83c40c5d8b4424088b5424108902b803' \
'000000c3558b4c24088b29ff711cff7118ff7128e815ffffff83c40c5dc20400555657' \
'538bea33c033db33d233f633ffffd15b5f5e5dc38bea8bf18bc16a01e89732000033c0' \
'33db33c933d233ffffe6558bec5356576a006a0068ff5d400051e8bf4500005f5e5b5d' \
'c3558b6c24085251ff742414e8b4feffff83c40c5dc208008bff558bec8b0da0fc4000' \
'a1a4fc40006bc91403c8eb118b55082b500c81fa00001000720983c0143bc172eb33c0' \
'5dc38bff558bec83ec108b4d088b4110568b750c578bfe2b790c83c6fcc1ef0f8bcf69' \
'c9040200008d8c0144010000894df08b0e49894dfcf6c1010f85d3020000538d1c318b' \
'138955f48b56fc8955f88b55f4895d0cf6c2017574c1fa044a83fa3f76036a3f5a8b4b' \
'043b4b087542bb0000008083fa2073198bcad3eb8d4c0204f7d3215cb844fe0975238b' \
'4d082119eb1c8d4ae0d3eb8d4c0204f7d3219cb8c4000000fe0975068b4d082159048b' \
'5d0c8b53088b5b048b4dfc034df4895a048b550c8b5a048b5208895308894dfc8bd1c1' \
'fa044a83fa3f76036a3f5a8b5df883e301895df40f858f0000002b75f88b5df8c1fb04' \
'6a3f89750c4b5e3bde76028bde034df88bd1c1fa044a894dfc3bd676028bd63bda745e' \
'8b4d0c8b71043b7108753bbe0000008083fb2073178bcbd3eef7d62174b844fe4c0304' \
'75218b4d082131eb1a8d4be0d3eef7d621b4b8c4000000fe4c030475068b4d08217104' \
'8b4d0c8b71088b4904894e048b4d0c8b71048b4908894e088b750ceb038b5d08837df4' \
'0075083bda0f84800000008b4df08d0cd18b5904894e08895e048971048b4e04897108' \
'8b4e043b4e0875608a4c0204884d0ffec1884c020483fa207325807d0f00750e8bcabb' \
'00000080d3eb8b4d080919bb000000808bcad3eb8d44b8440918eb29807d0f0075108d' \
'4ae0bb00000080d3eb8b4d080959048d4ae0ba00000080d3ea8d84b8c400000009108b' \
'45fc8906894430fc8b45f0ff080f85f3000000a1c0fb400085c00f84d80000008b0db4' \
'fc40008b350cb140006800400000c1e10f03480cbb008000005351ffd68b0db4fc4000' \
'a1c0fb4000ba00000080d3ea095008a1c0fb40008b40108b0db4fc400083a488c40000' \
'0000a1c0fb40008b4010fe4843a1c0fb40008b4810807943007509836004fea1c0fb40' \
'00837808ff7565536a00ff700cffd6a1c0fb4000ff70106a00ff35fcf94000ff15d0b0' \
'40008b0da0fc4000a1c0fb40006bc9148b15a4fc40002bc88d4c11ec518d48145150e8' \
'742f00008b450883c40cff0da0fc40003b05c0fb40007604836d0814a1a4fc4000a3ac' \
'fc40008b4508a3c0fb4000893db4fc40005b5f5ec9c3a1b0fc4000568b35a0fc400057' \
'33ff3bf0753483c0106bc01450ff35a4fc400057ff35fcf94000ff1540b140003bc775' \
'0433c0eb788305b0fc4000108b35a0fc4000a3a4fc40006bf6140335a4fc400068c441' \
'00006a08ff35fcf94000ff1538b140008946103bc774c76a0468002000006800001000' \
'57ff153cb1400089460c3bc77512ff761057ff35fcf94000ff15d0b04000eb9b834e08' \
'ff893e897e04ff05a0fc40008b46108308ff8bc65f5ec38bff558bec51518b4d088b41' \
'0853568b71105733dbeb0303c04385c07df98bc369c0040200008d8430440100006a3f' \
'8945f85a89400889400483c0084a75f46a048bfb6800100000c1e70f03790c68008000' \
'0057ff153cb1400085c0750883c8ffe99d0000008d97007000008955fc3bfa77438bca' \
'2bcfc1e90c8d4710418348f8ff8388ec0f0000ff8d90fc0f000089108d90fcefffffc7' \
'40fcf00f0000895004c780e80f0000f00f000005001000004975cb8b55fc8b45f805f8' \
'0100008d4f0c8948048941088d4a0c89480889410483649e440033ff4789bc9ec40000' \
'008a46438ac8fec184c08b4508884e437503097804ba000000808bcbd3eaf7d2215008' \
'8bc35f5e5bc9c38bff558bec83ec0c8b4d088b411053568b7510578b7d0c8bd72b510c' \
'83c617c1ea0f8bca69c9040200008d8c0144010000894df48b4ffc83e6f0493bf18d7c' \
'39fc8b1f894d10895dfc0f8e55010000f6c3010f854501000003d93bf30f8f3b010000' \
'8b4dfcc1f90449894df883f93f76066a3f59894df88b5f043b5f087543bb0000008083' \
'f920731ad3eb8b4df88d4c0104f7d3215c9044fe0975268b4d082119eb1f83c1e0d3eb' \
'8b4df88d4c0104f7d3219c90c4000000fe0975068b4d082159048b4f088b5f04895904' \
'8b4f048b7f088979088b4d102bce014dfc837dfc000f8ea50000008b7dfc8b4d0cc1ff' \
'044f8d4c31fc83ff3f76036a3f5f8b5df48d1cfb895d108b5b048959048b5d10895908' \
'894b048b5904894b088b59043b590875578a4c0704884d13fec1884c070483ff20731c' \
'807d1300750e8bcfbb00000080d3eb8b4d0809198d4490448bcfeb20807d130075108d' \
'4fe0bb00000080d3eb8b4d080959048d8490c40000008d4fe0ba00000080d3ea09108b' \
'550c8b4dfc8d4432fc8908894c01fceb038b550c8d46018942fc894432f8e93c010000' \
'33c0e9380100000f8d2f0100008b5d0c2975108d4e01894bfc8d5c33fc8b7510c1fe04' \
'4e895d0c894bfc83fe3f76036a3f5ef645fc010f85800000008b75fcc1fe044e83fe3f' \
'76036a3f5e8b4f043b4f087542bb0000008083fe2073198bced3eb8d740604f7d3215c' \
'9044fe0e75238b4d082119eb1c8d4ee0d3eb8d4c0604f7d3219c90c4000000fe097506' \
'8b4d082159048b5d0c8b4f088b77048971048b77088b4f048971088b75100375fc8975' \
'10c1fe044e83fe3f76036a3f5e8b4df48d0cf18b7904894b08897b048959048b4b0489' \
'59088b4b043b4b0875578a4c0604884d0ffec1884c060483fe20731c807d0f00750e8b' \
'cebf00000080d3ef8b4d0809398d4490448bceeb20807d0f0075108d4ee0bf00000080' \
'd3ef8b4d080979048d8490c40000008d4ee0ba00000080d3ea09108b45108903894418' \
'fc33c0405f5e5bc9c38bff558bec83ec14a1a0fc40008b4d086bc0140305a4fc400083' \
'c11783e1f0894df0c1f904534983f92056577d0b83ceffd3ee834df8ffeb0d83c1e083' \
'caff33f6d3ea8955f88b0dacfc40008bd9eb118b53048b3b2355f823fe0bd7750a83c3' \
'14895d083bd872e83bd8757f8b1da4fc4000eb118b53048b3b2355f823fe0bd7750a83' \
'c314895d083bd972e83bd9755beb0c837b0800750a83c314895d083bd872f03bd87531' \
'8b1da4fc4000eb09837b0800750a83c314895d083bd972f03bd97515e8a0faffff8bd8' \
'895d0885db750733c0e90902000053e83afbffff598b4b1089018b43108338ff74e589' \
'1dacfc40008b43108b108955fc83faff74148b8c90c40000008b7c9044234df823fe0b' \
'cf75298365fc008b90c40000008d48448b392355f823fe0bd7750eff45fc8b91840000' \
'0083c104ebe78b55fc8bca69c9040200008d8c0144010000894df48b4c904433ff23ce' \
'75128b8c90c4000000234df86a205feb0303c94785c97df98b4df48b54f9048b0a2b4d' \
'f08bf1c1fe044e83fe3f894df87e036a3f5e3bf70f84010100008b4a043b4a08755c83' \
'ff20bb000000807d268bcfd3eb8b4dfc8d7c3804f7d3895dec235c8844895c8844fe0f' \
'75338b4dec8b5d08210beb2c8d4fe0d3eb8b4dfc8d8c88c40000008d7c3804f7d32119' \
'fe0f895dec750b8b5d088b4dec214b04eb038b5d08837df8008b4a088b7a048979048b' \
'4a048b7a088979080f848d0000008b4df48d0cf18b7904894a08897a048951048b4a04' \
'8951088b4a043b4a08755e8a4c0604884d0bfec183fe20884c06047d23807d0b00750b' \
'bf000000808bced3ef093b8bcebf00000080d3ef8b4dfc097c8844eb29807d0b00750d' \
'8d4ee0bf00000080d3ef097b048b4dfc8dbc88c40000008d4ee0be00000080d3ee0937' \
'8b4df885c9740b890a894c11fceb038b4df88b75f003d18d4e01890a894c32fc8b75f4' \
'8b0e8d7901893e85c9751a3b1dc0fb400075128b4dfc3b0db4fc400075078325c0fb40' \
'00008b4dfc89088d42045f5e5bc9c36a0c6840c74000e8fdc1ffff8365e4008b75083b' \
'35a8fc400077226a04e80be5ffff598365fc0056e8eefcffff598945e4c745fcfeffff' \
'ffe8090000008b45e4e809c2ffffc36a04e806e4ffff59c38bff558bec568b750883fe' \
'e00f87a100000053578b3d38b14000833dfcf94000007518e829dbffff6a1ee877d9ff' \
'ff68ff000000e86abdffff5959a1bcfc400083f801750e85f674048bc6eb0333c04050' \
'eb1c83f803750b56e853ffffff5985c0751685f675014683c60f83e6f0566a00ff35fc' \
'f94000ffd78bd885db752e6a0c5e3905e4fb40007415ff7508e8def2ffff5985c0740f' \
'8b7508e97bffffffe84cc3ffff8930e845c3ffff89305f8bc35beb1456e8b7f2ffff59' \
'e831c3ffffc7000c00000033c05e5dc36a0c6860c74000e8e4c0ffff8b4d0833ff3bcf' \
'762e6ae05833d2f7f13b450c1bc040751fe8fdc2ffffc7000c0000005757575757e8da' \
'c5ffff83c41433c0e9d50000000faf4d0c8bf18975083bf7750333f64633db895de483' \
'fee07769833dbcfc400003754b83c60f83e6f089750c8b45083b05a8fc400077376a04' \
'e893e3ffff59897dfcff7508e875fbffff598945e4c745fcfeffffffe85f0000008b5d' \
'e43bdf7411ff75085753e8dab0ffff83c40c3bdf7561566a08ff35fcf94000ff1538b1' \
'40008bd83bdf754c393de4fb4000743356e8cef1ffff5985c00f8572ffffff8b45103b' \
'c70f8450ffffffc7000c000000e945ffffff33ff8b750c6a04e837e2ffff59c33bdf75' \
'0d8b45103bc77406c7000c0000008bc3e818c0ffffc36a106880c74000e8c6bfffff8b' \
'5d0885db750eff750ce8fdfdffff59e9cc0100008b750c85f6750c53e823c2ffff59e9' \
'b7010000833dbcfc4000030f859301000033ff897de483fee00f878a0100006a04e8a0' \
'e2ffff59897dfc53e8a5f2ffff598945e03bc70f849e0000003b35a8fc400077495653' \
'50e887f7ffff83c40c85c07405895de4eb3556e856faffff598945e43bc774278b43fc' \
'483bc672028bc65053ff75e4e8e014000053e855f2ffff8945e05350e87bf2ffff83c4' \
'18397de475483bf7750633f64689750c83c60f83e6f089750c5657ff35fcf94000ff15' \
'38b140008945e43bc774208b43fc483bc672028bc65053ff75e4e88c14000053ff75e0' \
'e82ef2ffff83c414c745fcfeffffffe82e000000837de000753185f675014683c60f83' \
'e6f089750c56536a00ff35fcf94000ff1540b140008bf8eb128b750c8b5d086a04e8d1' \
'e0ffff59c38b7de485ff0f85bf000000393de4fb4000742c56e822f0ffff5985c00f85' \
'd2feffffe894c0ffff397de0756c8bf0ff1580b0400050e83fc0ffff598906eb5f85ff' \
'0f8583000000e86fc0ffff397de07468c7000c000000eb7185f675014656536a00ff35' \
'fcf94000ff1540b140008bf885ff75563905e4fb4000743456e8b9efffff5985c0741f' \
'83fee076cd56e8a9efffff59e823c0ffffc7000c00000033c0e825beffffc3e810c0ff' \
'ffe97cffffff85ff7516e802c0ffff8bf0ff1580b0400050e8b2bfffff8906598bc7eb' \
'd26a1068a0c74000e8abbdffff33db895de46a01e8c3e0ffff59895dfc6a035f897de0' \
'3b3d000e41007d578bf7c1e602a1e4fd400003c6391874448b00f6400c83740f50e803' \
'2700005983f8ff7403ff45e483ff147c28a1e4fd40008b040683c02050ff1504b14000' \
'a1e4fd4000ff3406e8c1bfffff59a1e4fd4000891c0647eb9ec745fcfeffffffe80900' \
'00008b45e4e867bdffffc36a01e864dfffff59c38bff558bec53568b75088b460c8bc8' \
'80e10333db80f9027540a90801000074398b4608578b3e2bf885ff7e2c575056e8c301' \
'00005950e8bb0d000083c40c3bc7750f8b460c84c0790f83e0fd89460ceb07834e0c20' \
'83cbff5f8b46088366040089065e8bc35b5dc38bff558bec568b750885f6750956e835' \
'00000059eb2f56e87cffffff5985c0740583c8ffeb1ff7460c00400000741456e85a01' \
'000050e88526000059f7d8591bc0eb0233c05e5dc36a1468c0c74000e85cbcffff33ff' \
'897de4897ddc6a01e871dfffff59897dfc33f68975e03b35000e41000f8d83000000a1' \
'e4fd40008d04b03938745e8b00f6400c8374565056e87ec2ffff595933d2428955fca1' \
'e4fd40008b04b08b480cf6c183742f395508751150e84affffff5983f8ff741eff45e4' \
'eb19397d087514f6c102740f50e82fffffff5983f8ff75030945dc897dfce808000000' \
'46eb8433ff8b75e0a1e4fd4000ff34b056e887c2ffff5959c3c745fcfeffffffe81200' \
'0000837d08018b45e474038b45dce8ddbbffffc36a01e8daddffff59c36a01e81fffff' \
'ff59c38bff558bec8b450883f8fe750fe8a9bdffffc7000900000033c05dc35633f63b' \
'c67c083b05c0fc4000721ce88bbdffff5656565656c70009000000e868c0ffff83c414' \
'33c0eb1a8bc883e01fc1f9058b0c8de0fc4000c1e0060fbe44010483e0405e5dc38bff' \
'558bec8b45085633f63bc6751de843bdffff5656565656c70016000000e820c0ffff83' \
'c41483c8ffeb038b40105e5dc3cccccccccccccc8b4c2404f7c10300000074248a0183' \
'c10184c0744ef7c10300000075ef05000000008da424000000008da424000000008b01' \
'bafffefe7e03d083f0ff33c283c104a90001018174e88b41fc84c0743284e47424a900' \
'00ff007413a9000000ff7402ebcd8d41ff8b4c24042bc1c38d41fe8b4c24042bc1c38d' \
'41fd8b4c24042bc1c38d41fc8b4c24042bc1c38bff558bec83ec1053568b750c33db57' \
'8b7d103bf375143bfb76108b45083bc37402891833c0e9830000008b45083bc3740383' \
'08ff81ffffffff7f761be851bcffff6a165e53535353538930e82fbfffff83c4148bc6' \
'eb56ff75188d4df0e8c8c1ffff8b45f03958140f859c000000668b4514b9ff00000066' \
'3bc176363bf3740f3bfb760b575356e868aaffff83c40ce8febbffffc7002a000000e8' \
'f3bbffff8b00385dfc74078b4df8836170fd5f5e5bc9c33bf374323bfb772ce8d3bbff' \
'ff6a225e53535353538930e8b1beffff83c414385dfc0f8479ffffff8b45f8836070fd' \
'e96dffffff88068b45083bc37406c70001000000385dfc0f8425ffffff8b45f8836070' \
'fde919ffffff8d4d0c515357566a018d4d145153895d0cff7004ff15f0b040003bc374' \
'14395d0c0f855effffff8b4d083bcb74bd8901ebb9ff1580b0400083f87a0f8544ffff' \
'ff3bf30f8467ffffff3bfb0f865fffffff575356e891a9ffff83c40ce94fffffff8bff' \
'558bec6a00ff7514ff7510ff750cff7508e87cfeffff83c4145dc38bff558bec83ec10' \
'ff750c8d4df0e88fc0ffff0fb645088b4df08b89c80000000fb704412500800000807d' \
'fc0074078b4df8836170fdc9c38bff558bec6a00ff7508e8b9ffffff59595dc3cc568b' \
'4424140bc075288b4c24108b44240c33d2f7f18bd88b442408f7f18bf08bc3f7642410' \
'8bc88bc6f764241003d1eb478bc88b5c24108b54240c8b442408d1e9d1dbd1ead1d80b' \
'c975f4f7f38bf0f76424148bc88b442410f7e603d1720e3b54240c7708720f3b442408' \
'76094e2b4424101b54241433db2b4424081b54240cf7daf7d883da008bca8bd38bd98b' \
'c88bc65ec210008bff558bec51518b450c568b75088945f88b451057568945fce8a625' \
'000083cfff593bc77511e8feb9ffffc700090000008bc78bd7eb4aff75148d4dfc51ff' \
'75f850ff1544b140008945f83bc77513ff1580b0400085c0740950e8f0b9ffff59ebcf' \
'8bc6c1f8058b0485e0fc400083e61fc1e6068d4430048020fd8b45f88b55fc5f5ec9c3' \
'6a1468e8c74000e862b7ffff83ceff8975dc8975e08b450883f8fe751ce895b9ffff83' \
'2000e87ab9ffffc700090000008bc68bd6e9d000000033ff3bc77c083b05c0fc400072' \
'21e86bb9ffff8938e851b9ffffc700090000005757575757e82ebcffff83c414ebc88b' \
'c8c1f9058d1c8de0fc40008bf083e61fc1e6068b0b0fbe4c310483e1017526e82ab9ff' \
'ff8938e810b9ffffc700090000005757575757e8edbbffff83c41483caff8bc2eb5b50' \
'e80225000059897dfc8b03f644300401741cff7514ff7510ff750cff7508e8a9feffff' \
'83c4108945dc8955e0eb1ae8c2b8ffffc70009000000e8cab8ffff8938834ddcff834d' \
'e0ffc745fcfeffffffe80c0000008b45dc8b55e0e8a5b6ffffc3ff7508e83f25000059' \
'c38bff558becb8e41a0000e85ea7ffffa100e0400033c58945fc8b450c5633f6898534' \
'e5ffff89b538e5ffff89b530e5ffff397510750733c0e9e90600003bc67527e858b8ff' \
'ff8930e83eb8ffff5656565656c70016000000e81bbbffff83c41483c8ffe9be060000' \
'53578b7d088bc7c1f8058d3485e0fc40008b0683e71fc1e70603c78a582402dbd0fb89' \
'b528e5ffff889d27e5ffff80fb02740580fb0175308b4d10f7d1f6c1017526e8efb7ff' \
'ff33f68930e8d3b7ffff5656565656c70016000000e8b0baffff83c414e943060000f6' \
'40042074116a026a006a00ff7508e87efdffff83c410ff7508e8e1f9ffff5985c00f84' \
'9d0200008b06f6440704800f8490020000e81dacffff8b406c33c93948148d851ce5ff' \
'ff0f94c1508b06ff3407898d20e5ffffff154cb1400085c00f846002000033c9398d20' \
'e5ffff740884db0f8450020000ff1548b140008b9d34e5ffff89851ce5ffff33c08985' \
'3ce5ffff3945100f8642050000898544e5ffff8a8527e5ffff84c00f85670100008a0b' \
'8bb528e5ffff33c080f90a0f94c0898520e5ffff8b0603c78378380074158a50348855' \
'f4884df5836038006a028d45f450eb4b0fbec150e8fdfbffff5985c0743a8b8d34e5ff' \
'ff2bcb034d1033c0403bc80f86a50100006a028d8540e5ffff5350e85a25000083c40c' \
'83f8ff0f84b104000043ff8544e5ffffeb1b6a01538d8540e5ffff50e83625000083c4' \
'0c83f8ff0f848d04000033c050506a058d4df4516a018d8d40e5ffff5150ffb51ce5ff' \
'ff43ff8544e5ffffff15f0b040008bf085f60f845c0400006a008d853ce5ffff50568d' \
'45f4508b8528e5ffff8b00ff3407ff153cb0400085c00f84290400008b8544e5ffff8b' \
'8d30e5ffff03c139b53ce5ffff898538e5ffff0f8c1504000083bd20e5ffff000f84cd' \
'0000006a008d853ce5ffff506a018d45f4508b8528e5ffff8b00c645f40dff3407ff15' \
'3cb0400085c00f84d003000083bd3ce5ffff010f8ccf030000ff8530e5ffffff8538e5' \
'ffffe9830000003c0174043c0275210fb73333c96683fe0a0f94c14343838544e5ffff' \
'0289b540e5ffff898d20e5ffff3c0174043c027552ffb540e5ffffe84322000059663b' \
'8540e5ffff0f8568030000838538e5ffff0283bd20e5ffff0074296a0d5850898540e5' \
'ffffe81622000059663b8540e5ffff0f853b030000ff8538e5ffffff8530e5ffff8b45' \
'10398544e5ffff0f82f9fdffffe9270300008b0e8a13ff8538e5ffff88540f348b0e89' \
'440f38e90e03000033c98b0603c7f64004800f84bf0200008b8534e5ffff898d40e5ff' \
'ff84db0f85ca00000089853ce5ffff394d100f8620030000eb068bb528e5ffff8b8d3c' \
'e5ffff83a544e5ffff002b8d34e5ffff8d8548e5ffff3b4d1073398b953ce5ffffff85' \
'3ce5ffff8a124180fa0a7510ff8530e5ffffc6000d40ff8544e5ffff881040ff8544e5' \
'ffff81bd44e5ffffff13000072c28bd88d8548e5ffff2bd86a008d852ce5ffff50538d' \
'8548e5ffff508b06ff3407ff153cb0400085c00f84420200008b852ce5ffff018538e5' \
'ffff3bc30f8c3a0200008b853ce5ffff2b8534e5ffff3b45100f824cffffffe9200200' \
'00898544e5ffff80fb020f85d1000000394d100f864d020000eb068bb528e5ffff8b8d' \
'44e5ffff83a53ce5ffff002b8d34e5ffff8d8548e5ffff3b4d1073468b9544e5ffff83' \
'8544e5ffff020fb71241416683fa0a7516838530e5ffff026a0d5b668918404083853c' \
'e5ffff0283853ce5ffff02668910404081bd3ce5fffffe13000072b58bd88d8548e5ff' \
'ff2bd86a008d852ce5ffff50538d8548e5ffff508b06ff3407ff153cb0400085c00f84' \
'620100008b852ce5ffff018538e5ffff3bc30f8c5a0100008b8544e5ffff2b8534e5ff' \
'ff3b45100f823fffffffe940010000394d100f867c0100008b8d44e5ffff83a53ce5ff' \
'ff002b8d34e5ffff6a028d8548f9ffff5e3b4d10733c8b9544e5ffff0fb71201b544e5' \
'ffff03ce6683fa0a750e6a0d5b66891803c601b53ce5ffff01b53ce5ffff66891003c6' \
'81bd3ce5ffffa806000072bf33f6565668550d00008d8df0ebffff518d8d48f9ffff2b' \
'c1992bc2d1f8508bc1505668e9fd0000ff15f0b040008bd83bde0f84970000006a008d' \
'852ce5ffff508bc32bc6508d8435f0ebffff508b8528e5ffff8b00ff3407ff153cb040' \
'0085c0740c03b52ce5ffff3bde7fcbeb0cff1580b04000898540e5ffff3bde7f5c8b85' \
'44e5ffff2b8534e5ffff898538e5ffff3b45100f820affffffeb3f6a008d8d2ce5ffff' \
'51ff7510ffb534e5ffffff30ff153cb0400085c074158b852ce5ffff83a540e5ffff00' \
'898538e5ffffeb0cff1580b04000898540e5ffff83bd38e5ffff00756c83bd40e5ffff' \
'00742d6a055e39b540e5ffff7514e8c6b1ffffc70009000000e8ceb1ffff8930eb3fff' \
'b540e5ffffe8d2b1ffff59eb318bb528e5ffff8b06f644070440740f8b8534e5ffff80' \
'381a750433c0eb24e886b1ffffc7001c000000e88eb1ffff83200083c8ffeb0c8b8538' \
'e5ffff2b8530e5ffff5f5b8b4dfc33cd5ee8a69cffffc9c36a106808c84000e816afff' \
'ff8b450883f8fe751be852b1ffff832000e837b1ffffc7000900000083c8ffe99d0000' \
'0033ff3bc77c083b05c0fc40007221e829b1ffff8938e80fb1ffffc700090000005757' \
'575757e8ecb3ffff83c414ebc98bc8c1f9058d1c8de0fc40008bf083e61fc1e6068b0b' \
'0fbe4c310483e10174bf50e8e61c000059897dfc8b03f6443004017416ff7510ff750c' \
'ff7508e82ef8ffff83c40c8945e4eb16e8acb0ffffc70009000000e8b4b0ffff893883' \
'4de4ffc745fcfeffffffe8090000008b45e4e896aeffffc3ff7508e8301d000059c38b' \
'ff558becff05c8f540006800100000e83eb1ffff598b4d0889410885c0740d83490c08' \
'c7411800100000eb1183490c048d4114894108c74118020000008b4108836104008901' \
'5dc38bff558bec83ec14535657e82da2ffff8365fc00833dc4fb4000008bd80f858e00' \
'000068f0ba4000ff152cb140008bf885ff0f842a0100008b35acb0400068e4ba400057' \
'ffd685c00f841401000050e877a1ffffc70424d4ba400057a3c4fb4000ffd650e862a1' \
'ffffc70424c0ba400057a3c8fb4000ffd650e84da1ffffc70424a4ba400057a3ccfb40' \
'00ffd650e838a1ffff59a3d4fb400085c07414688cba400057ffd650e820a1ffff59a3' \
'd0fb4000a1d0fb40003bc3744f391dd4fb4000744750e87ea1ffffff35d4fb40008bf0' \
'e871a1ffff59598bf885f6742c85ff7428ffd685c074198d4df8516a0c8d4dec516a01' \
'50ffd785c07406f645f4017509814d1000002000eb39a1c8fb40003bc3743050e82ea1' \
'ffff5985c07425ffd08945fc85c0741ca1ccfb40003bc3741350e811a1ffff5985c074' \
'08ff75fcffd08945fcff35c4fb4000e8f9a0ffff5985c07410ff7510ff750cff7508ff' \
'75fcffd0eb0233c05f5e5bc9c38bff558bec8b45085333db56573bc374078b7d0c3bfb' \
'771be8adaeffff6a165e89305353535353e88bb1ffff83c4148bc6eb3c8b75103bf375' \
'048818ebda8bd0381a7404424f75f83bfb74ee8a0e880a42463acb74034f75f33bfb75' \
'108818e866aeffff6a225989088bf1ebb533c05f5e5b5dc38bff558bec53568b750833' \
'db57395d1475103bf37510395d0c751233c05f5e5b5dc33bf374078b7d0c3bfb771be8' \
'24aeffff6a165e89305353535353e802b1ffff83c4148bc6ebd5395d147504881eebca' \
'8b55103bd37504881eebd1837d14ff8bc6750f8a0a880840423acb741e4f75f3eb198a' \
'0a880840423acb74084f7405ff4d1475ee395d14750288183bfb758b837d14ff750f8b' \
'450c6a50885c06ff58e978ffffff881ee8aaadffff6a225989088bf1eb828bff558bec' \
'8b4d085333db56573bcb74078b7d0c3bfb771be884adffff6a165e89305353535353e8' \
'62b0ffff83c4148bc6eb308b75103bf375048819ebda8bd18a06880242463ac374034f' \
'75f33bfb75108819e849adffff6a225989088bf1ebc133c05f5e5b5dc3cc8bff558bec' \
'8b4d085633f63bce7c1e83f9027e0c83f9037514a150f24000eb28a150f24000890d50' \
'f24000eb1be806adffff5656565656c70016000000e8e3afffff83c41483c8ff5e5dc3' \
'8bff558bec83ec10ff75088d4df0e872b2ffff0fb6450c8b4df48a55148454011d751e' \
'837d100074128b4df08b89c80000000fb70441234510eb0233c085c0740333c040807d' \
'fc0074078b4df8836170fdc9c38bff558bec6a046a00ff75086a00e89affffff83c410' \
'5dc3cccccccc558bec57568b750c8b4d108b7d088bc18bd103c63bfe76083bf80f82a4' \
'01000081f900010000721f833de0fd4000007416575683e70f83e60f3bfe5e5f75085e' \
'5f5de98d1b0000f7c7030000007515c1e90283e20383f908722af3a5ff249514824000' \
'908bc7ba0300000083e904720c83e00303c8ff248528814000ff248d2482400090ff24' \
'8da88140009038814000648140008881400023d18a0688078a46018847018a4602c1e9' \
'0288470283c60383c70383f90872ccf3a5ff2495148240008d490023d18a0688078a46' \
'01c1e90288470183c60283c70283f90872a6f3a5ff2495148240009023d18a06880783' \
'c601c1e90283c70183f9087288f3a5ff2495148240008d49000b824000f8814000f081' \
'4000e8814000e0814000d8814000d0814000c88140008b448ee489448fe48b448ee889' \
'448fe88b448eec89448fec8b448ef089448ff08b448ef489448ff48b448ef889448ff8' \
'8b448efc89448ffc8d048d0000000003f003f8ff2495148240008bff248240002c8240' \
'00388240004c8240008b45085e5fc9c3908a0688078b45085e5fc9c3908a0688078a46' \
'018847018b45085e5fc9c38d49008a0688078a46018847018a46028847028b45085e5f' \
'c9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff' \
'2495b08340008bfff7d9ff248d608340008d49008bc7ba0300000083f904720c83e003' \
'2bc8ff2485b4824000ff248db083400090c4824000e8824000108340008a460323d188' \
'470383ee01c1e90283ef0183f90872b2fdf3a5fcff2495b08340008d49008a460323d1' \
'8847038a4602c1e90288470283ee0283ef0283f9087288fdf3a5fcff2495b083400090' \
'8a460323d18847038a46028847028a4601c1e90288470183ee0383ef0383f9080f8256' \
'fffffffdf3a5fcff2495b08340008d4900648340006c834000748340007c8340008483' \
'40008c83400094834000a78340008b448e1c89448f1c8b448e1889448f188b448e1489' \
'448f148b448e1089448f108b448e0c89448f0c8b448e0889448f088b448e0489448f04' \
'8d048d0000000003f003f8ff2495b08340008bffc0834000c8834000d8834000ec8340' \
'008b45085e5fc9c3908a46038847038b45085e5fc9c38d49008a46038847038a460288' \
'47028b45085e5fc9c3908a46038847038a46028847028a46018847018b45085e5fc9c3' \
'8bff558bec568b750885f60f8481010000ff7604e849a9ffffff7608e841a9ffffff76' \
'0ce839a9ffffff7610e831a9ffffff7614e829a9ffffff7618e821a9ffffff36e81aa9' \
'ffffff7620e812a9ffffff7624e80aa9ffffff7628e802a9ffffff762ce8faa8ffffff' \
'7630e8f2a8ffffff7634e8eaa8ffffff761ce8e2a8ffffff7638e8daa8ffffff763ce8' \
'd2a8ffff83c440ff7640e8c7a8ffffff7644e8bfa8ffffff7648e8b7a8ffffff764ce8' \
'afa8ffffff7650e8a7a8ffffff7654e89fa8ffffff7658e897a8ffffff765ce88fa8ff' \
'ffff7660e887a8ffffff7664e87fa8ffffff7668e877a8ffffff766ce86fa8ffffff76' \
'70e867a8ffffff7674e85fa8ffffff7678e857a8ffffff767ce84fa8ffff83c440ffb6' \
'80000000e841a8ffffffb684000000e836a8ffffffb688000000e82ba8ffffffb68c00' \
'0000e820a8ffffffb690000000e815a8ffffffb694000000e80aa8ffffffb698000000' \
'e8ffa7ffffffb69c000000e8f4a7ffffffb6a0000000e8e9a7ffffffb6a4000000e8de' \
'a7ffffffb6a8000000e8d3a7ffff83c42c5e5dc38bff558bec568b750885f674358b06' \
'3b0558ed4000740750e8b0a7ffff598b46043b055ced4000740750e89ea7ffff598b76' \
'083b3560ed4000740756e88ca7ffff595e5dc38bff558bec568b750885f6747e8b460c' \
'3b0564ed4000740750e86aa7ffff598b46103b0568ed4000740750e858a7ffff598b46' \
'143b056ced4000740750e846a7ffff598b46183b0570ed4000740750e834a7ffff598b' \
'461c3b0574ed4000740750e822a7ffff598b46203b0578ed4000740750e810a7ffff59' \
'8b76243b357ced4000740756e8fea6ffff595e5dc38bff558bec8b450885c0741283e8' \
'088138dddd0000750750e8dda6ffff595dc3cccccc558bec5633c05050505050505050' \
'8b550c8d49008a020ac0740983c2010fab0424ebf18b750883c9ff8d490083c1018a06' \
'0ac0740983c6010fa3042473ee8bc183c4205ec9c3cccccccccccccccccccc8b542404' \
'8b4c2408f7c203000000753c8b023a01752e0ac074263a610175250ae4741dc1e8103a' \
'410275190ac074113a6103751083c10483c2040ae475d28bff33c0c3901bc0d1e083c0' \
'01c3f7c20100000074188a0283c2013a0175e783c1010ac074dcf7c20200000074a466' \
'8b0283c2023a0175ce0ac074c63a610175c50ae474bd83c102eb888bff558bec5151a1' \
'00e0400033c58945fca1dcfb4000535633db578bf93bc3753a8d45f85033f646566834' \
'c4400056ff155cb1400085c074088935dcfb4000eb34ff1580b0400083f878750a6a02' \
'58a3dcfb4000eb05a1dcfb400083f8020f84cf0000003bc30f84c700000083f8010f85' \
'e8000000895df8395d1875088b078b40048945188b3558b1400033c0395d205353ff75' \
'100f95c0ff750c8d04c50100000050ff7518ffd68bf83bfb0f84ab0000007e3c81fff0' \
'ffff7f77348d443f083d000400007713e82c1500008bc43bc3741cc700cccc0000eb11' \
'50e8e6e0ffff593bc37409c700dddd000083c0088bd885db74698d043f506a0053e818' \
'93ffff83c40c5753ff7510ff750c6a01ff7518ffd685c07411ff75145053ff7508ff15' \
'5cb140008945f853e8d8fdffff8b45f859eb7533f6395d1c75088b078b401489451c39' \
'5d1875088b078b4004894518ff751ce8e31400005983f8ff750433c0eb473b4518741e' \
'53538d4d1051ff750c50ff7518e80b1500008bf083c4183bf374dc89750cff7514ff75' \
'10ff750cff7508ff751cff1554b140008bf83bf3740756e85aa4ffff598bc78d65ec5f' \
'5e5b8b4dfc33cde84a8fffffc9c38bff558bec83ec10ff75088d4df0e881a9ffffff75' \
'248d4df0ff7520ff751cff7518ff7514ff7510ff750ce816feffff83c41c807dfc0074' \
'078b4df8836170fdc9c3cccccccccccccccccccccccc558bec5633c050505050505050' \
'508b550c8d49008a020ac0740983c2010fab0424ebf18b75088bff8a060ac0740c83c6' \
'010fa3042473f18d46ff83c4205ec9c38bff558bec83ec14a100e0400033c58945fc53' \
'5633db578bf1391de0fb40007538535333ff47576834c44000680001000053ff1564b1' \
'400085c07408893de0fb4000eb15ff1580b0400083f878750ac705e0fb400002000000' \
'395d147e228b4d148b45104938187408403bcb75f683c9ff8b45142bc1483b45147d01' \
'40894514a1e0fb400083f8020f84ac0100003bc30f84a401000083f8010f85cc010000' \
'895df8395d2075088b068b40048945208b3558b1400033c0395d245353ff75140f95c0' \
'ff75108d04c50100000050ff7520ffd68bf83bfb0f848f0100007e436ae033d258f7f7' \
'83f80272378d443f083d000400007713e8b61200008bc43bc3741cc700cccc0000eb11' \
'50e870deffff593bc37409c700dddd000083c0088945f4eb03895df4395df40f843e01' \
'000057ff75f4ff7514ff75106a01ff7520ffd685c00f84e30000008b3564b140005353' \
'57ff75f4ff750cff7508ffd68bc8894df83bcb0f84c2000000f7450c00040000742939' \
'5d1c0f84b00000003b4d1c0f8fa7000000ff751cff751857ff75f4ff750cff7508ffd6' \
'e9900000003bcb7e456ae033d258f7f183f80272398d4409083d000400007716e8f711' \
'00008bf43bf3746ac706cccc000083c608eb1a50e8aeddffff593bc37409c700dddd00' \
'0083c0088bf0eb0233f63bf37441ff75f85657ff75f4ff750cff7508ff1564b1400085' \
'c074225353395d1c75045353eb06ff751cff7518ff75f85653ff7520ff15f0b0400089' \
'45f856e895faffff59ff75f4e88cfaffff8b45f859e959010000895df4895df0395d08' \
'75088b068b4014894508395d2075088b068b4004894520ff7508e890110000598945ec' \
'83f8ff750733c0e9210100003b45200f84db00000053538d4d1451ff751050ff7520e8' \
'ae11000083c4188945f43bc374d48b3560b140005353ff751450ff750cff7508ffd689' \
'45f83bc3750733f6e9b70000007e3d83f8e0773883c0083d000400007716e8e1100000' \
'8bfc3bfb74ddc707cccc000083c708eb1a50e898dcffff593bc37409c700dddd000083' \
'c0088bf8eb0233ff3bfb74b4ff75f85357e8c88effff83c40cff75f857ff7514ff75f4' \
'ff750cff7508ffd68945f83bc3750433f6eb25ff751c8d45f8ff75185057ff7520ff75' \
'ece8fd1000008bf08975f083c418f7de1bf62375f857e86af9ffff59eb1aff751cff75' \
'18ff7514ff7510ff750cff7508ff1560b140008bf0395df47409ff75f4e83aa0ffff59' \
'8b45f03bc3740c394518740750e827a0ffff598bc68d65e05f5e5b8b4dfc33cde8178b' \
'ffffc9c38bff558bec83ec10ff75088d4df0e84ea5ffffff75288d4df0ff7524ff7520' \
'ff751cff7518ff7514ff7510ff750ce828fcffff83c420807dfc0074078b4df8836170' \
'fdc9c36a106828c84000e8429dffff33c08b5d0833ff3bdf0f95c03bc7751de8639fff' \
'ffc700160000005757575757e840a2ffff83c41483c8ffeb53833dbcfc40000375386a' \
'04e829c0ffff59897dfc53e82ed0ffff598945e03bc7740b8b73fc83ee098975e4eb03' \
'8b75e4c745fcfeffffffe825000000397de075105357ff35fcf94000ff1568b140008b' \
'f08bc6e8029dffffc333ff8b5d088b75e46a04e8f7beffff59c36a02e83998ffff59c3' \
'8bff558bec81ec28030000a100e0400033c58945fcf605a0ed4000015674086a0ae868' \
'b4ffff59e8d3cbffff85c074086a16e8d5cbffff59f605a0ed4000020f84ca00000089' \
'85e0fdffff898ddcfdffff8995d8fdffff899dd4fdffff89b5d0fdffff89bdccfdffff' \
'668c95f8fdffff668c8decfdffff668c9dc8fdffff668c85c4fdffff668ca5c0fdffff' \
'668cadbcfdffff9c8f85f0fdffff8b75048d45048985f4fdffffc78530fdffff010001' \
'0089b5e8fdffff8b40fc6a508985e4fdffff8d85d8fcffff6a0050e86b8cffff8d85d8' \
'fcffff83c40c898528fdffff8d8530fdffff6a00c785d8fcffff1500004089b5e4fcff' \
'ff89852cfdffffff15a0b040008d8528fdffff50ff159cb040006a03e8a799ffffcccc' \
'cccc558bec535657556a006a0068788f4000ff7508e8461400005d5f5e5b8be55dc38b' \
'4c2404f7410406000000b80100000074328b4424148b48fc33c8e8ca88ffff558b6810' \
'8b5028528b502452e81400000083c4085d8b4424088b5424108902b803000000c35356' \
'578b44241055506afe68808f400064ff3500000000a100e0400033c4508d44240464a3' \
'000000008b4424288b58088b700c83feff743a837c242cff74063b74242c762d8d3476' \
'8b0cb3894c240c89480c837cb30400751768010100008b44b308e8490000008b44b308' \
'e85f000000ebb78b4c240464890d0000000083c4185f5e5bc333c0648b0d0000000081' \
'7904808f400075108b510c8b520c3951087505b801000000c35351bba4ed4000eb0b53' \
'51bba4ed40008b4c240c894b08894304896b0c55515058595d595bc20400ffd0c3cccc' \
'cccccccccccccc558bec57568b750c8b4d108b7d088bc18bd103c63bfe76083bf80f82' \
'a401000081f900010000721f833de0fd4000007416575683e70f83e60f3bfe5e5f7508' \
'5e5f5de98d0b0000f7c7030000007515c1e90283e20383f908722af3a5ff2495149240' \
'00908bc7ba0300000083e904720c83e00303c8ff248528914000ff248d2492400090ff' \
'248da89140009038914000649140008891400023d18a0688078a46018847018a4602c1' \
'e90288470283c60383c70383f90872ccf3a5ff2495149240008d490023d18a0688078a' \
'4601c1e90288470183c60283c70283f90872a6f3a5ff2495149240009023d18a068807' \
'83c601c1e90283c70183f9087288f3a5ff2495149240008d49000b924000f8914000f0' \
'914000e8914000e0914000d8914000d0914000c89140008b448ee489448fe48b448ee8' \
'89448fe88b448eec89448fec8b448ef089448ff08b448ef489448ff48b448ef889448f' \
'f88b448efc89448ffc8d048d0000000003f003f8ff2495149240008bff249240002c92' \
'4000389240004c9240008b45085e5fc9c3908a0688078b45085e5fc9c3908a0688078a' \
'46018847018b45085e5fc9c38d49008a0688078a46018847018a46028847028b45085e' \
'5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fc' \
'ff2495b09340008bfff7d9ff248d609340008d49008bc7ba0300000083f904720c83e0' \
'032bc8ff2485b4924000ff248db093400090c4924000e8924000109340008a460323d1' \
'88470383ee01c1e90283ef0183f90872b2fdf3a5fcff2495b09340008d49008a460323' \
'd18847038a4602c1e90288470283ee0283ef0283f9087288fdf3a5fcff2495b0934000' \
'908a460323d18847038a46028847028a4601c1e90288470183ee0383ef0383f9080f82' \
'56fffffffdf3a5fcff2495b09340008d4900649340006c934000749340007c93400084' \
'9340008c93400094934000a79340008b448e1c89448f1c8b448e1889448f188b448e14' \
'89448f148b448e1089448f108b448e0c89448f0c8b448e0889448f088b448e0489448f' \
'048d048d0000000003f003f8ff2495b09340008bffc0934000c8934000d8934000ec93' \
'40008b45085e5fc9c3908a46038847038b45085e5fc9c38d49008a46038847038a4602' \
'8847028b45085e5fc9c3908a46038847038a46028847028a46018847018b45085e5fc9' \
'c38bff558bec53568b75085733ff83cbff3bf7751ce80099ffff5757575757c7001600' \
'0000e8dd9bffff83c4140bc3eb42f6460c83743756e88fd9ffff568bd8e8770d000056' \
'e878dbffff50e89e0c000083c41085c07d0583cbffeb118b461c3bc7740a50e8f998ff' \
'ff59897e1c897e0c8bc35f5e5b5dc36a0c6848c84000e86096ffff834de4ff33c08b75' \
'0833ff3bf70f95c03bc7751de87d98ffffc700160000005757575757e85a9bffff83c4' \
'1483c8ffeb0cf6460c40740c897e0c8b45e4e86396ffffc356e8379cffff59897dfc56' \
'e82affffff598945e4c745fcfeffffffe805000000ebd58b750856e8859cffff59c36a' \
'106868c84000e8e495ffff8b450883f8fe7513e80d98ffffc7000900000083c8ffe9aa' \
'00000033db3bc37c083b05c0fc4000721ae8ec97ffffc700090000005353535353e8c9' \
'9affff83c414ebd08bc8c1f9058d3c8de0fc40008bf083e61fc1e6068b0f0fbe4c0e04' \
'83e10174c650e8c303000059895dfc8b07f6440604017431ff7508e8370300005950ff' \
'156cb1400085c0750bff1580b040008945e4eb03895de4395de47419e88b97ffff8b4d' \
'e48908e86e97ffffc70009000000834de4ffc745fcfeffffffe8090000008b45e4e85f' \
'95ffffc3ff7508e8f903000059c38bff558bec83ec145657ff75088d4dece8c89cffff' \
'8b45108b750c33ff3bc7740289303bf7752ce81997ffff5757575757c70016000000e8' \
'f699ffff83c414807df80074078b45f4836070fd33c0e9d8010000397d14740c837d14' \
'027cc9837d14247fc38b4dec538a1e897dfc8d7e0183b9ac000000017e178d45ec500f' \
'b6c36a0850e83e0900008b4dec83c40ceb108b91c80000000fb6c30fb7044283e00885' \
'c074058a1f47ebc780fb2d7506834d1802eb0580fb2b75038a1f478b451485c00f8c4b' \
'01000083f8010f844201000083f8240f8f3901000085c0752a80fb307409c745140a00' \
'0000eb348a073c78740d3c587409c7451408000000eb21c7451410000000eb0a83f810' \
'751380fb30750e8a073c7874043c587504478a1f478bb1c8000000b8ffffffff33d2f7' \
'75140fb6cb0fb70c4ef6c10474080fbecb83e930eb1bf7c10301000074318acb80e961' \
'80f9190fbecb770383e92083c1c93b4d147319834d18083945fc722775043bca762183' \
'4d1804837d100075238b45184fa8087520837d100074038b7d0c8365fc00eb5b8b5dfc' \
'0faf5d1403d9895dfc8a1f47eb8bbeffffff7fa804751ba801753d83e0027409817dfc' \
'00000080770985c0752b3975fc7626e87895fffff6451801c700220000007406834dfc' \
'ffeb0ff64518026a00580f95c003c68945fc8b451085c074028938f64518027403f75d' \
'fc807df80074078b45f4836070fd8b45fceb188b451085c074028930807df80074078b' \
'45f4836070fd33c05b5f5ec9c38bff558bec33c050ff7510ff750cff7508390550fb40' \
'0075076838e74000eb0150e8abfdffff83c4145dc38bff558bec8b4d085333db3bcb56' \
'577c5b3b0dc0fc400073538bc1c1f8058bf18d3c85e0fc40008b0783e61fc1e60603c6' \
'f640040174358338ff7430833d10e0400001751d2bcb7410497408497513536af4eb08' \
'536af5eb03536af6ff1570b140008b07830c06ff33c0eb15e87a94ffffc70009000000' \
'e88294ffff891883c8ff5f5e5b5dc38bff558bec8b450883f8fe7518e86694ffff8320' \
'00e84b94ffffc7000900000083c8ff5dc35633f63bc67c223b05c0fc4000731a8bc883' \
'e01fc1f9058b0c8de0fc4000c1e00603c1f64004017524e82594ffff8930e80b94ffff' \
'5656565656c70009000000e8e896ffff83c41483c8ffeb028b005e5dc36a0c6888c840' \
'00e8ac91ffff8b7d088bc7c1f8058bf783e61fc1e606033485e0fc4000c745e4010000' \
'0033db395e0875366a0ae8a4b4ffff59895dfc395e08751a68a00f00008d460c50e8b0' \
'c2ffff595985c07503895de4ff4608c745fcfeffffffe830000000395de4741d8bc7c1' \
'f80583e71fc1e7068b0485e0fc40008d44380c50ff15d4b040008b45e4e86c91ffffc3' \
'33db8b7d086a0ae864b3ffff59c38bff558bec8b45088bc883e01fc1f9058b0c8de0fc' \
'4000c1e0068d44010c50ff15d8b040005dc38bff558bec83ec10a100e0400033c58945' \
'fc5633f63935c0ed4000744f833d84ee4000fe7505e8cf070000a184ee400083f8ff75' \
'07b8ffff0000eb70568d4df0516a018d4d085150ff157cb1400085c07567833dc0ed40' \
'000275daff1580b0400083f87875cf8935c0ed400056566a058d45f4506a018d450850' \
'56ff1578b1400050ff15f0b040008b0d84ee400083f9ff74a2568d55f052508d45f450' \
'51ff1574b1400085c0748d668b45088b4dfc33cd5ee8bc7dffffc9c3c705c0ed400001' \
'000000ebe38bff558bec83ec1053568b750c33db3bf37415395d107410381e75128b45' \
'083bc3740533c966890833c05e5bc9c3ff75148d4df0e8c197ffff8b45f0395814751f' \
'8b45083bc37407660fb60e668908385dfc74078b45f8836070fd33c040ebca8d45f050' \
'0fb60650e8ebd6ffff595985c0747d8b45f08b88ac00000083f9017e25394d107c2033' \
'd2395d080f95c252ff750851566a09ff7004ff1558b1400085c08b45f075108b4d103b' \
'88ac0000007220385e01741b8b80ac000000385dfc0f8465ffffff8b4df8836170fde9' \
'59ffffffe88c91ffffc7002a000000385dfc74078b45f8836070fd83c8ffe93affffff' \
'33c0395d080f95c050ff75088b45f06a01566a09ff7004ff1558b1400085c00f853aff' \
'ffffebba8bff558bec6a00ff7510ff750cff7508e8d4feffff83c4105dc3558bec83ec' \
'08897dfc8975f88b750c8b7d088b4d10c1e907eb068d9b00000000660f6f06660f6f4e' \
'10660f6f5620660f6f5e30660f7f07660f7f4f10660f7f5720660f7f5f30660f6f6640' \
'660f6f6e50660f6f7660660f6f7e70660f7f6740660f7f6f50660f7f7760660f7f7f70' \
'8db6800000008dbf800000004975a38b75f88b7dfc8be55dc3558bec83ec1c897df489' \
'75f8895dfc8b5d0c8bc3998bc88b450833ca2bca83e10f33ca2bca998bf833fa2bfa83' \
'e70f33fa2bfa8bd10bd7754a8b75108bce83e17f894de83bf174132bf1565350e827ff' \
'ffff83c40c8b45088b4de885c974778b5d108b550c03d32bd18955ec03d82bd9895df0' \
'8b75ec8b7df08b4de8f3a48b4508eb533bcf7535f7d983c110894de48b750c8b7d088b' \
'4de4f3a48b4d08034de48b550c0355e48b45102b45e4505251e84cffffff83c40c8b45' \
'08eb1a8b750c8b7d088b4d108bd1c1e902f3a58bca83e103f3a48b45088b5dfc8b75f8' \
'8b7df48be55dc3cccccccccccccccccc518d4c24082bc883e10f03c11bc90bc159e98a' \
'7effff518d4c24082bc883e10703c11bc90bc159e9747effff8bff558bec6a0a6a00ff' \
'7508e86bfaffff83c40c5dc38bff558bec83ec0ca100e0400033c58945fc6a068d45f4' \
'506804100000ff7508c645fa00ff1550b1400085c0750583c8ffeb0a8d45f450e8aeff' \
'ffff598b4dfc33cde8817affffc9c38bff558bec83ec34a100e0400033c58945fc8b45' \
'108b4d188945d88b4514538945d08b00568945dc8b45085733ff894dcc897de0897dd4' \
'3b450c0f845f0100008b351cb140008d4de85150ffd68b1d58b1400085c0745e837de8' \
'0175588d45e850ff750cffd685c0744b837de80175458b75dcc745d40100000083feff' \
'750cff75d8e88ed1ffff8bf059463bf77e5b81fef0ffff7f77538d4436083d00040000' \
'772fe8cefeffff8bc43bc77438c700cccc0000eb2d5757ff75dcff75d86a01ff7508ff' \
'd38bf03bf775c333c0e9d100000050e86ccaffff593bc77409c700dddd000083c00889' \
'45e4eb03897de4397de474d88d04365057ff75e4e8967cffff83c40c56ff75e4ff75dc' \
'ff75d86a01ff7508ffd385c0747f8b5dcc3bdf741d5757ff751c5356ff75e457ff750c' \
'ff15f0b0400085c07460895de0eb5b8b1df0b04000397dd475145757575756ff75e457' \
'ff750cffd38bf03bf7743c566a01e8ed8effff59598945e03bc7742b5757565056ff75' \
'e457ff750cffd33bc7750eff75e0e8f78dffff59897de0eb0b837ddcff74058b4dd089' \
'01ff75e4e8e4e6ffff598b45e08d65c05f5e5b8b4dfc33cde8cd78ffffc9c38bff558b' \
'ec83ec1853ff75108d4de8e80393ffff8b5d088d43013d00010000770f8b45e88b80c8' \
'0000000fb70458eb75895d08c17d08088d45e8508b450825ff00000050e82cd2ffff59' \
'5985c074128a45086a028845f8885df9c645fa0059eb0a33c9885df8c645f900418b45' \
'e86a01ff7014ff70048d45fc50518d45f8508d45e86a0150e8f9e8ffff83c42085c075' \
'103845f474078b45f0836070fd33c0eb140fb745fc23450c807df40074078b4df08361' \
'70fd5bc9c38bff558bec568b75085756e852f8ffff5983f8ff7450a1e0fc400083fe01' \
'7509f6808400000001750b83fe02751cf640440174166a02e827f8ffff6a018bf8e81e' \
'f8ffff59593bc7741c56e812f8ffff5950ff1574b0400085c0750aff1580b040008bf8' \
'eb0233ff56e86ef7ffff8bc6c1f8058b0485e0fc400083e61fc1e60659c64430040085' \
'ff740c57e85d8cffff5983c8ffeb0233c05f5e5dc36a1068a8c84000e8e989ffff8b45' \
'0883f8fe751be8258cffff832000e80a8cffffc7000900000083c8ffe98e00000033ff' \
'3bc77c083b05c0fc40007221e8fc8bffff8938e8e28bffffc700090000005757575757' \
'e8bf8effff83c414ebc98bc8c1f9058d1c8de0fc40008bf083e61fc1e6068b0b0fbe4c' \
'310483e10174bf50e8b9f7ffff59897dfc8b03f644300401740eff7508e8cbfeffff59' \
'8945e4eb0fe8878bffffc70009000000834de4ffc745fcfeffffffe8090000008b45e4' \
'e87889ffffc3ff7508e812f8ffff59c38bff558bec568b75088b460ca883741ea80874' \
'1aff7608e88b8bffff81660cf7fbffff33c05989068946088946045e5dc333c050506a' \
'03506a0368000000406878c44000ff1580b14000a384ee4000c3a184ee4000568b3574' \
'b0400083f8ff740883f8fe740350ffd6a180ee400083f8ff740883f8fe740350ffd65e' \
'c3cccccc558bec5756538b4d100bc9744d8b75088b7d0cb741b35ab6208d49008a260a' \
'e48a0774270ac0742383c60183c7013ae772063ae3770202e63ac772063ac3770202c6' \
'3ae0750b83e90175d133c93ae07409b9ffffffff7202f7d98bc15b5e5fc9c3cccccccc' \
'cccccccccccccccccccccc8b4424088b4c24100bc88b4c240c75098b442404f7e1c210' \
'0053f7e18bd88b442408f764241403d88b442408f7e103d35bc21000cccccccccccccc' \
'cccccccccc8d42ff5bc38da424000000008d64240033c08a442408538bd8c1e0088b54' \
'2408f7c20300000074158a0a83c2013acb74cf84c97451f7c20300000075eb0bd8578b' \
'c3c1e310560bd88b0abffffefe7e8bc18bf733cb03f003f983f1ff83f0ff33cf33c683' \
'c20481e100010181751c250001018174d32500010101750881e60000008075c45e5f5b' \
'33c0c38b42fc3ac3743684c074ef3ae3742784e474e7c1e8103ac3741584c074dc3ae3' \
'740684e474d4eb965e5f8d42ff5bc38d42fe5e5f5bc38d42fd5e5f5bc38d42fc5e5f5b' \
'c3ff2534b1400000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000c6cc00' \
'00a8cc00008acc000076cc000060cc000044cc000038cc00002ecc00001ccc00000ccc' \
'0000f6cb0000e6cb0000d2cb0000e2cc00000000000094cb00007ecb0000accb000066' \
'cb000054cb00003ecb000028cb000014cb000000cb0000f0ca0000daca0000ccca0000' \
'beca0000b2ca0000a4ca000098ca0000a0cb000088ca000010cd00001ecd00002ecd00' \
'003ecd000050cd000064cd000078cd000094cd0000b2cd0000c6cd0000dacd0000eccd' \
'0000facd000006ce000014ce00001ece00002ece000044ce00004cce00005ace000066' \
'ce00007ece000096ce0000a6ce0000bcce0000d6ce0000eece000008cf00001ecf0000' \
'38cf00004acf000058cf00006acf000082cf000090cf00009ecf0000b8cf0000c8cf00' \
'00e2cf0000eecf0000f8cf000004d0000016d0000026d000004ed000005ad0000066d0' \
'000076d0000084d0000096d00000a6d00000b8d00000cad00000dcd00000f2d0000004' \
'd1000014d1000024d1000030d1000044d1000054d1000064d100007ad100008ad10000' \
'0000000000000000000000000000000037304000774240002958400001594000c64240' \
'00000000000000000010a24000e8304000000000000000000000000000000000005265' \
'6d436f6d53766300000053657276696365004120736572766963652043616e6e6f7420' \
'62652073746172746564206469726563746c792e0a000052656d436f6d5f7374646572' \
'7200000052656d436f6d5f737464696e000000005c5c2e5c706970655c257325732564' \
'0052656d436f6d5f7374646f7574000000257300005c5c2e5c706970655c52656d436f' \
'6d5f636f6d6d756e696361746f6e0000000058f24000b0f24000456e636f6465506f69' \
'6e7465720000004b00450052004e0045004c00330032002e0044004c004c0000000000' \
'4465636f6465506f696e746572000000466c734672656500466c7353657456616c7565' \
'00466c7347657456616c756500466c73416c6c6f6300000000436f724578697450726f' \
'6365737300006d00730063006f007200650065002e0064006c006c000000050000c00b' \
'000000000000001d0000c00400000000000000960000c004000000000000008d0000c0' \
'08000000000000008e0000c008000000000000008f0000c00800000000000000900000' \
'c00800000000000000910000c00800000000000000920000c008000000000000009300' \
'00c0080000000000000028006e0075006c006c00290000000000286e756c6c29000006' \
'0000060001000010000306000602100445454505050505053530005000000000282038' \
'5058070800373030575007000020200800000000086068606060600000787078787878' \
'08070800000700080808000008000800070800000072756e74696d65206572726f7220' \
'00000d0a0000544c4f5353206572726f720d0a00000053494e47206572726f720d0a00' \
'000000444f4d41494e206572726f720d0a000052363033340d0a416e206170706c6963' \
'6174696f6e20686173206d61646520616e20617474656d707420746f206c6f61642074' \
'686520432072756e74696d65206c69627261727920696e636f72726563746c792e0a50' \
'6c6561736520636f6e7461637420746865206170706c69636174696f6e277320737570' \
'706f7274207465616d20666f72206d6f726520696e666f726d6174696f6e2e0d0a0000' \
'0000000052363033330d0a2d20417474656d707420746f20757365204d53494c20636f' \
'64652066726f6d207468697320617373656d626c7920647572696e67206e6174697665' \
'20636f646520696e697469616c697a6174696f6e0a5468697320696e64696361746573' \
'20612062756720696e20796f7572206170706c69636174696f6e2e204974206973206d' \
'6f7374206c696b656c792074686520726573756c74206f662063616c6c696e6720616e' \
'204d53494c2d636f6d70696c656420282f636c72292066756e6374696f6e2066726f6d' \
'2061206e617469766520636f6e7374727563746f72206f722066726f6d20446c6c4d61' \
'696e2e0d0a000052363033320d0a2d206e6f7420656e6f75676820737061636520666f' \
'72206c6f63616c6520696e666f726d6174696f6e0d0a00000000000052363033310d0a' \
'2d20417474656d707420746f20696e697469616c697a652074686520435254206d6f72' \
'65207468616e206f6e63652e0a5468697320696e646963617465732061206275672069' \
'6e20796f7572206170706c69636174696f6e2e0d0a000052363033300d0a2d20435254' \
'206e6f7420696e697469616c697a65640d0a000052363032380d0a2d20756e61626c65' \
'20746f20696e697469616c697a6520686561700d0a0000000052363032370d0a2d206e' \
'6f7420656e6f75676820737061636520666f72206c6f77696f20696e697469616c697a' \
'6174696f6e0d0a0000000052363032360d0a2d206e6f7420656e6f7567682073706163' \
'6520666f7220737464696f20696e697469616c697a6174696f6e0d0a00000000523630' \
'32350d0a2d2070757265207669727475616c2066756e6374696f6e2063616c6c0d0a00' \
'000052363032340d0a2d206e6f7420656e6f75676820737061636520666f72205f6f6e' \
'657869742f617465786974207461626c650d0a0000000052363031390d0a2d20756e61' \
'626c6520746f206f70656e20636f6e736f6c65206465766963650d0a00000000523630' \
'31380d0a2d20756e65787065637465642068656170206572726f720d0a000000005236' \
'3031370d0a2d20756e6578706563746564206d756c7469746872656164206c6f636b20' \
'6572726f720d0a0000000052363031360d0a2d206e6f7420656e6f7567682073706163' \
'6520666f722074687265616420646174610d0a000d0a54686973206170706c69636174' \
'696f6e2068617320726571756573746564207468652052756e74696d6520746f207465' \
'726d696e61746520697420696e20616e20756e757375616c207761792e0a506c656173' \
'6520636f6e7461637420746865206170706c69636174696f6e277320737570706f7274' \
'207465616d20666f72206d6f726520696e666f726d6174696f6e2e0d0a000000523630' \
'30390d0a2d206e6f7420656e6f75676820737061636520666f7220656e7669726f6e6d' \
'656e740d0a0052363030380d0a2d206e6f7420656e6f75676820737061636520666f72' \
'20617267756d656e74730d0a00000052363030320d0a2d20666c6f6174696e6720706f' \
'696e7420737570706f7274206e6f74206c6f616465640d0a000000004d6963726f736f' \
'66742056697375616c20432b2b2052756e74696d65204c696272617279000000000a0a' \
'00002e2e2e003c70726f6772616d206e616d6520756e6b6e6f776e3e000052756e7469' \
'6d65204572726f72210a0a50726f6772616d3a20000000000000000102030405060708' \
'090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b' \
'2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e' \
'4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071' \
'72737475767778797a7b7c7d7e7f000680808680818000001003868086828014050545' \
'4545858585050000303080508088000800282738505780000700373030505088000000' \
'2028808880800000006068606868680808077870707770700808000008000800070800' \
'000047657450726f6365737357696e646f7753746174696f6e00476574557365724f62' \
'6a656374496e666f726d6174696f6e410000004765744c617374416374697665506f70' \
'7570000047657441637469766557696e646f77004d657373616765426f784100555345' \
'5233322e444c4c00000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000002000200020002000200020' \
'0020002000200028002800280028002800200020002000200020002000200020002000' \
'2000200020002000200020002000200020004800100010001000100010001000100010' \
'0010001000100010001000100010008400840084008400840084008400840084008400' \
'1000100010001000100010001000810081008100810081008100010001000100010001' \
'0001000100010001000100010001000100010001000100010001000100010010001000' \
'1000100010001000820082008200820082008200020002000200020002000200020002' \
'0002000200020002000200020002000200020002000200020010001000100010002000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000020002000200020002000200020002000200068002800' \
'2800280028002000200020002000200020002000200020002000200020002000200020' \
'0020002000200048001000100010001000100010001000100010001000100010001000' \
'1000100084008400840084008400840084008400840084001000100010001000100010' \
'0010008101810181018101810181010101010101010101010101010101010101010101' \
'0101010101010101010101010101010101010101100010001000100010001000820182' \
'0182018201820182010201020102010201020102010201020102010201020102010201' \
'0201020102010201020102010201100010001000100020002000200020002000200020' \
'0020002000200020002000200020002000200020002000200020002000200020002000' \
'2000200020002000200020002000200020004800100010001000100010001000100010' \
'0010001000100010001000100010001000100014001400100010001000100010001400' \
'1000100010001000100010000101010101010101010101010101010101010101010101' \
'0101010101010101010101010101010101010101010101100001010101010101010101' \
'0101010102010201020102010201020102010201020102010201020102010201020102' \
'0102010201020102010201020102010201100002010201020102010201020102010201' \
'010100000000808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c' \
'9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf' \
'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2' \
'e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405' \
'060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728' \
'292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f406162636465666768696a6b' \
'6c6d6e6f707172737475767778797a5b5c5d5e5f606162636465666768696a6b6c6d6e' \
'6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091' \
'92939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4' \
'b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7' \
'd8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa' \
'fbfcfdfeff808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d' \
'9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0' \
'c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3' \
'e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00010203040506' \
'0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829' \
'2a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c' \
'4d4e4f505152535455565758595a5b5c5d5e5f604142434445464748494a4b4c4d4e4f' \
'505152535455565758595a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192' \
'939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5' \
'b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8' \
'd9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafb' \
'fcfdfeff48483a6d6d3a737300000000646464642c204d4d4d4d2064642c2079797979' \
'004d4d2f64642f797900000000504d0000414d0000446563656d626572000000004e6f' \
'76656d626572000000004f63746f6265720053657074656d6265720000004175677573' \
'7400004a756c79000000004a756e6500000000417072696c0000004d61726368000000' \
'4665627275617279000000004a616e7561727900446563004e6f76004f637400536570' \
'00417567004a756c004a756e004d617900417072004d617200466562004a616e005361' \
'7475726461790000000046726964617900005468757273646179000000005765646e65' \
'7364617900000054756573646179004d6f6e646179000053756e646179000053617400' \
'467269005468750057656400547565004d6f6e0053756e000000000053756e4d6f6e54' \
'75655765645468754672695361740000004a616e4665624d61724170724d61794a756e' \
'4a756c4175675365704f63744e6f7644656300000000434f4e4f555424004800000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'000000000000000000000000000000000000000000e04000d0c4400003000000000000' \
'0000000000502b0000585d0000808f0000000000000000000000000000000000000000' \
'0000feffffff00000000d4ffffff00000000feffffffe3184000f718400000000000fe' \
'ffffff00000000d4ffffff00000000feffffff00000000cf1a400000000000feffffff' \
'00000000ccffffff00000000feffffff681d40007c1d400000000000feffffff000000' \
'00d4ffffff00000000feffffff0000000029214000feffffff0000000038214000feff' \
'ffff00000000d8ffffff00000000feffffff00000000eb224000feffffff00000000f7' \
'224000feffffff00000000d8ffffff00000000feffffff1b2640002f26400000000000' \
'feffffff00000000c8ffffff00000000feffffff00000000d528400000000000feffff' \
'ff00000000d4ffffff00000000feffffff00000000bd2d400000000000feffffff0000' \
'0000d4ffffff00000000feffffffe2414000fe41400000000000feffffff000000008c' \
'ffffff00000000feffffff5f4b4000634b400000000000feffffff00000000d4ffffff' \
'00000000feffffff00000000034e400000000000feffffff00000000d4ffffff000000' \
'00feffffff000000005851400000000000feffffff00000000d4ffffff00000000feff' \
'ffff000000002254400000000000feffffff00000000ccffffff00000000feffffff00' \
'000000f057400000000000feffffff00000000d4ffffff00000000feffffff00000000' \
'6859400000000000feffffff00000000d8ffffff00000000feffffffc6594000ca5940' \
'0000000000feffffff00000000c0ffffff00000000feffffff00000000c05b40000000' \
'0000feffffff00000000d0ffffff00000000feffffff505c4000675c400000000000fe' \
'ffffff00000000d4ffffff00000000feffffff000000002569400000000000feffffff' \
'00000000d4ffffff00000000feffffff00000000ef6a400000000000feffffff000000' \
'00d0ffffff00000000feffffff00000000546c400000000000feffffff00000000d0ff' \
'ffff00000000feffffff00000000c76d400000000000feffffff00000000ccffffff00' \
'000000feffffff00000000516f400000000000000000001d6f4000feffffff00000000' \
'ccffffff00000000feffffff000000008974400000000000feffffff00000000d0ffff' \
'ff00000000feffffff00000000987c400000000000feffffff00000000d0ffffff0000' \
'0000feffffff000000002c8e400000000000feffffff00000000d4ffffff00000000fe' \
'ffffff00000000ed94400000000000feffffff00000000d0ffffff00000000feffffff' \
'00000000cf95400000000000feffffff00000000d4ffffff00000000feffffff000000' \
'00c299400000000000feffffff00000000d0ffffff00000000feffffff00000000b6a1' \
'40003cc900000000000000000000c4cb00003cb0000000c90000000000000000000002' \
'cd000000b000000000000000000000000000000000000000000000c6cc0000a8cc0000' \
'8acc000076cc000060cc000044cc000038cc00002ecc00001ccc00000ccc0000f6cb00' \
'00e6cb0000d2cb0000e2cc00000000000094cb00007ecb0000accb000066cb000054cb' \
'00003ecb000028cb000014cb000000cb0000f0ca0000daca0000ccca0000beca0000b2' \
'ca0000a4ca000098ca0000a0cb000088ca000010cd00001ecd00002ecd00003ecd0000' \
'50cd000064cd000078cd000094cd0000b2cd0000c6cd0000dacd0000eccd0000facd00' \
'0006ce000014ce00001ece00002ece000044ce00004cce00005ace000066ce00007ece' \
'000096ce0000a6ce0000bcce0000d6ce0000eece000008cf00001ecf000038cf00004a' \
'cf000058cf00006acf000082cf000090cf00009ecf0000b8cf0000c8cf0000e2cf0000' \
'eecf0000f8cf000004d0000016d0000026d000004ed000005ad0000066d0000076d000' \
'0084d0000096d00000a6d00000b8d00000cad00000dcd00000f2d0000004d1000014d1' \
'000024d1000030d1000044d1000054d1000064d100007ad100008ad1000000000000e6' \
'014765744c6173744572726f720000d3035365744576656e7400004300436c6f736548' \
'616e646c6500fd024c6f63616c4672656500f9024c6f63616c416c6c6f63000033034f' \
'70656e50726f6365737300aa0147657443757272656e7450726f636573734964007200' \
'4372656174654576656e744100005600436f6e6e6563744e616d65645069706500008f' \
'004372656174654e616d656450697065410000c50147657445786974436f646550726f' \
'636573730000640457616974466f7253696e676c654f626a6563740094004372656174' \
'6550726f63657373410000bc02496e7465726c6f636b656444656372656d656e740000' \
'cd00446973636f6e6e6563744e616d656450697065008d04577269746546696c650068' \
'035265616446696c650000c002496e7465726c6f636b6564496e6372656d656e740000' \
'4b45524e454c33322e646c6c0000ba02536574536572766963655374617475730000d6' \
'0044656c65746553657276696365005300436c6f73655365727669636548616e646c65' \
'0000f4014f70656e53657276696365410000f2014f70656e53434d616e616765724100' \
'001a0146726565536964000201457175616c53696400001f00416c6c6f63617465416e' \
'64496e697469616c697a6553696400005401476574546f6b656e496e666f726d617469' \
'6f6e00f1014f70656e50726f63657373546f6b656e00007f0252656769737465725365' \
'72766963654374726c48616e646c65724100c102537461727453657276696365437472' \
'6c446973706174636865724100b002536574536563757269747944657363726970746f' \
'724461636c007101496e697469616c697a65536563757269747944657363726970746f' \
'72000041445641504933322e646c6c000005014578697454687265616400008d035265' \
'73756d655468726561640000a30043726561746554687265616400006f01476574436f' \
'6d6d616e644c696e6541002d045465726d696e61746550726f636573730000a9014765' \
'7443757272656e7450726f63657373003e04556e68616e646c6564457863657074696f' \
'6e46696c74657200001504536574556e68616e646c6564457863657074696f6e46696c' \
'74657200d1024973446562756767657250726573656e7400f9014765744d6f64756c65' \
'48616e646c65570000200247657450726f634164647265737300003404546c73476574' \
'56616c7565003204546c73416c6c6f6300003504546c7353657456616c756500330454' \
'6c734672656500ec035365744c6173744572726f720000ad0147657443757272656e74' \
'546872656164496400002104536c6565700004014578697450726f6365737300a10248' \
'656170467265650000d900456e746572437269746963616c53656374696f6e0000ef02' \
'4c65617665437269746963616c53656374696f6e00003b0247657453746448616e646c' \
'650000f4014765744d6f64756c6546696c654e616d654100004a0146726565456e7669' \
'726f6e6d656e74537472696e67734100bf01476574456e7669726f6e6d656e74537472' \
'696e6773004b0146726565456e7669726f6e6d656e74537472696e677357007a045769' \
'646543686172546f4d756c74694279746500c101476574456e7669726f6e6d656e7453' \
'7472696e6773570000e80353657448616e646c65436f756e740000d70147657446696c' \
'655479706500390247657453746172747570496e666f4100be0044656c657465437269' \
'746963616c53656374696f6e009f024865617043726561746500005704566972747561' \
'6c467265650054035175657279506572666f726d616e6365436f756e74657200660247' \
'65745469636b436f756e7400004f0247657453797374656d54696d65417346696c6554' \
'696d65005b014765744350496e666f005201476574414350000013024765744f454d43' \
'500000db02497356616c6964436f64655061676500f1024c6f61644c69627261727941' \
'0000b502496e697469616c697a65437269746963616c53656374696f6e416e64537069' \
'6e436f756e7400920352746c556e77696e64009d0248656170416c6c6f630054045669' \
'727475616c416c6c6f630000a402486561705265416c6c6f6300df0353657446696c65' \
'506f696e74657200008301476574436f6e736f6c65435000009501476574436f6e736f' \
'6c654d6f64650000e8014765744c6f63616c65496e666f4100003d0247657453747269' \
'6e67547970654100001a034d756c746942797465546f57696465436861720040024765' \
'74537472696e6754797065570000e1024c434d6170537472696e67410000e3024c434d' \
'6170537472696e67570000a6024865617053697a6500004101466c75736846696c6542' \
'7566666572730000fc0353657453746448616e646c65000082045772697465436f6e73' \
'6f6c6541009901476574436f6e736f6c654f7574707574435000008c04577269746543' \
'6f6e736f6c655700780043726561746546696c65410000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000004ee640bbb119bf44000000000000' \
'000001000000ffffffffffffffff032940000300000007000000780000000a00000001' \
'0000001600000002000000020000000300000002000000040000001800000005000000' \
'0d0000000600000009000000070000000c000000080000000c000000090000000c0000' \
'000a000000070000000b000000080000000c000000160000000d000000160000000f00' \
'000002000000100000000d00000011000000120000001200000002000000210000000d' \
'0000003500000002000000410000000d00000043000000020000005000000011000000' \
'520000000d000000530000000d0000005700000016000000590000000b0000006c0000' \
'000d0000006d00000020000000700000001c0000007200000009000000060000001600' \
'0000800000000a000000810000000a0000008200000009000000830000001600000084' \
'0000000d00000091000000290000009e0000000d000000a100000002000000a4000000' \
'0b000000a70000000d000000b700000011000000ce00000002000000d70000000b0000' \
'00180700000c0000000c0000000800000000fe40000000000000fe4000010100000000' \
'0000000000000010000000000000000000000000000000000000020000000100000000' \
'0000000000000000000000000000000000000000000000020000000200000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'00000000000000000000000000000000000000000000000000000088b3400078b34000' \
'0200000018b9400008000000ecb8400009000000c0b840000a00000028b84000100000' \
'00fcb7400011000000ccb7400012000000a8b74000130000007cb740001800000044b7' \
'4000190000001cb740001a000000e4b640001b000000acb640001c00000084b640001e' \
'00000064b640001f00000000b6400020000000c8b5400021000000d0b4400022000000' \
'30b440007800000020b440007900000010b440007a00000000b44000fc000000fcb340' \
'00ff000000ecb34000ffffffff800a0000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000001000000000000000000000000100000000000000010000000000000000000000' \
'0000000001000000000000000100000000000000000000000000000001000000000000' \
'0001000000000000000100000000000000000000000000000001000000000000000000' \
'0000000000000100000000000000010000000000000001000000000000000000000000' \
'0000000100000000000000010000000000000001000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000004be4000000000004300000000000000' \
'0100000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'00000000000000000000000000000000000050e6400000000000000000000000000050' \
'e6400000000000000000000000000050e6400000000000000000000000000050e64000' \
'00000000000000000000000050e6400000000000000000000000000001000000010000' \
'0000000000000000000000000058ed4000000000000000000000bc400088c0400008c2' \
'400098ec400058e640000100000058e6400040e7400000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000101010101010101010101010101010101010101010101010' \
'1010000000000000202020202020202020202020202020202020202020202020202000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'000000000000000000000000000000000000000000006162636465666768696a6b6c6d' \
'6e6f707172737475767778797a0000000000004142434445464748494a4b4c4d4e4f50' \
'5152535455565758595a00000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000101010101010101010101010101010101010101010101010101000000000000020' \
'2020202020202020202020202020202020202020202020202000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'00000000000000000000000000000000000000006162636465666768696a6b6c6d6e6f' \
'707172737475767778797a0000000000004142434445464748494a4b4c4d4e4f505152' \
'535455565758595a000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0040e7400001020408a4030000608279822100000000000000a6df000000000000a1a5' \
'000000000000819fe0fc00000000407e80fc00000000a8030000c1a3daa32000000000' \
'0000000000000000000000000000000000000081fe00000000000040fe000000000000' \
'b5030000c1a3daa320000000000000000000000000000000000000000000000081fe00' \
'000000000041fe000000000000b6030000cfa2e4a21a00e5a2e8a25b00000000000000' \
'0000000000000000000081fe000000000000407ea1fe000000005105000051da5eda20' \
'005fda6ada32000000000000000000000000000000000081d3d8dee0f90000317e81fe' \
'000000003d8e40003d8e40003d8e40003d8e40003d8e40003d8e40003d8e40003d8e40' \
'003d8e40003d8e4000feffffff0000000000bc400002be400030c440002cc4400028c4' \
'400024c4400020c440001cc4400018c4400010c4400008c4400000c44000f4c34000e8' \
'c34000e0c34000d4c34000d0c34000ccc34000c8c34000c4c34000c0c34000bcc34000' \
'b8c34000b4c34000b0c34000acc34000a8c34000a4c340009cc3400090c3400088c340' \
'0080c34000c0c3400078c3400070c3400068c340005cc3400054c3400048c340003cc3' \
'400038c3400034c3400028c3400014c3400008c3400009040000010000000000000098' \
'ec40002e00000054ed4000d8fb4000d8fb4000d8fb4000d8fb4000d8fb4000d8fb4000' \
'd8fb4000d8fb4000d8fb40007f7f7f7f7f7f7f7f58ed4000010000002e000000010000' \
'0000000000000000000300000020059319000000000000000000000000000000000000' \
'00000000000002000000000000008070000001000000f0f1ffff000000005053540000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000005044540000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'000000000000000000000000000000000000d8ed400018ee4000ffffffff0000000000' \
'000000ffffffff00000000000000000000000000000000fefffffffeffffffffffffff' \
'1e0000003b0000005a0000007800000097000000b5000000d4000000f3000000110100' \
'00300100004e0100006d010000ffffffff1e0000003a00000059000000770000009600' \
'0000b4000000d3000000f2000000100100002f0100004d0100006c0100000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000400000000' \
'0001001800000018000080000000000000000004000000000001000100000030000080' \
'000000000000000004000000000001000904000048000000581001005a010000e40400' \
'00000000003c617373656d626c7920786d6c6e733d2275726e3a736368656d61732d6d' \
'6963726f736f66742d636f6d3a61736d2e763122206d616e696665737456657273696f' \
'6e3d22312e30223e0d0a20203c7472757374496e666f20786d6c6e733d2275726e3a73' \
'6368656d61732d6d6963726f736f66742d636f6d3a61736d2e7633223e0d0a20202020' \
'3c73656375726974793e0d0a2020202020203c72657175657374656450726976696c65' \
'6765733e0d0a20202020202020203c726571756573746564457865637574696f6e4c65' \
'76656c206c6576656c3d226173496e766f6b6572222075694163636573733d2266616c' \
'7365223e3c2f726571756573746564457865637574696f6e4c6576656c3e0d0a202020' \
'2020203c2f72657175657374656450726976696c656765733e0d0a202020203c2f7365' \
'6375726974793e0d0a20203c2f7472757374496e666f3e0d0a3c2f617373656d626c79' \
'3e504150414444494e47585850414444494e4750414444494e47585850414444494e47' \
'50414444494e47585850414444494e4750414444494e47585850414444494e47504144' \
'44494e47585850414400100000a00100000d301e30253032303d30423047304e305830' \
'5e3064306a30703077309c30a130aa30b130b730be30c330c930d230d730de30e830f7' \
'300b31443154315e3171317d319131a231be31ca31ff3172328432a732c332cc321433' \
'19331f33293333333d33433349334f3355335a3363336a3374337a3380338a3398339f' \
'33a433cd33d433fc330e34403450347c3484348934ac34b134b634c834cd34d234dd34' \
'f8341235323550357735aa350736653689369136de36ec36f2361b375d3764376b3770' \
'3776377c3785378c37a937b137ef37063815381d383638413849385d3864386c387b38' \
'84389438ae38bd38c53830393739583960397039e039f039003a0b3a363ae33aee3aa0' \
'3b323c573c683c6f3c753c873c8f3c9a3ceb3cf03cfa3c343d393d403d463dbc3dc23d' \
'c83dce3dd43dda3de13de83def3df63dfd3d043e0b3e133e1b3e233e2f3e383e3d3e43' \
'3e4d3e563e613e6d3e723e823e873e8d3e933ea93eb03ebe3ec43ecf3edb3ef03ef73e' \
'0b3f123f393f3f3f4a3f563f6b3f723f863f8d3fa53fb63fbc3fc73fd13fd73fe33ff2' \
'3ff83f000000200000400100000d301e302a3038303e304a3050305d3067306e308630' \
'95309c30a930cc30e130073147314d3177317d319931b131d731513274327e32b632be' \
'320a331a3320332c333233423348335d336b3376337d3398339d33a533ab33b233b833' \
'bf33c533cd33d433d933e133ea33f633fb33003406340a34103415341b3420342f3445' \
'34503455346034653470347534823490349634a334c334c934e53498359d35af35cd35' \
'e135e7355b3664369136ac36b236bb36c236e43643374b375e3769376e377e3788378f' \
'379a37a337b937c437de37ea37f23702381738573864388e3893389e38a338c1387239' \
'7f39a1391a3a203a393a3f3ae93a063b623b3c3c443c5c3c743ccb3ce93c053d283d3b' \
'3d6a3d7c3dcb3dd13de23d0f3e183e243e5b3e643e703ea93eb23ebe3edd3eef3ec13f' \
'cb3fd83ff33ffa3f0000003000006c000000123032303830523061306e307a308a3091' \
'30a030ac30b930dd30ef30fd3012311c314231753184318d31b131e03122323432e032' \
'e832fd320833ef339134af34d534353548356335ae389e39283b573b7c3b5f3d5b3f5f' \
'3f633f673f6b3f6f3f733f773f00400000dc0000007f308630c8317d32c732cd32eb32' \
'22333a3345336933723379338233c233c733ef33143439344c34643476349a34ba34c9' \
'3401350b355b356635703581358c353f37503758375e3763376937d537db37f137fc37' \
'13381f382c3833386a38b938cc38fe381739253939395a3960399239e939f139313a3b' \
'3a633a7c3abd3aed3aff3a513b573b7a3b7f3ba03ba53bd93bde3bec3bfb3b1e3c2b3c' \
'373c3f3c473c533c773c7f3c8a3c973c9e3ca83cd23ce03ce63c093d103d293d3d3d43' \
'3d4c3d5f3d833d183e383e573e1c3f463f913fdd3f000000500000c00000002c307430' \
'da30f13002313e31c63103321a328d339e33d833e533ef33fd330634103444344f3459' \
'3472347c348f34b334ea341f353235a235bf3507367336923607371337263738375337' \
'5b3763377a379337af37b837be37c737cc37db3702382b383c3852385d38d738f03819' \
'391e3935398d39a939e039eb39f939fe39033a083a183a473a553a9c3aa13ae63aeb3a' \
'f23af73afe3a033b723b7b3b813b0b3c1a3c293c323c473c773c983ca53cdd3ce93cf5' \
'3d223e273e00600000b80000006a3078307e3098309d30ac30b530c230cd30df30f230' \
'fd30033109310e31173134313a3145314a3152315831623169317d3184318a3198319f' \
'31a431ad31ba31c031da31eb31f1310232673203360f3642366836a236e736ba38c538' \
'cd38e238f43844394a396a39a139b239fb39573a6c3ab23ab83ac43a193b4c3b843bef' \
'3bf53b463c4c3c703c933cc73ccd3cd93c203d343d553d613d883d953d9a3da83d833e' \
'a63eb13ed43e233f883fb53f00000070000064000000ac31ca31393346335f337d33bb' \
'33ea33a3340835bc35dc35cc36f5364e37dc38bc39853ab63acc3a0d3b2c3bc93bfd3b' \
'2c3ca93c013d0f3d153d253d2a3d423d483d573d5d3d6c3d723d803d893d983d9d3da7' \
'3db53df53d123e2f3e00800000cc000000003007300d30ca30ff3018311f3127312c31' \
'303134315d318331a131a831ac31b031b431b831bc31c031c4310e32143218321c3220' \
'3286329132ac32b332b832bc32c032e1320b333d33443348334c335033543358335c33' \
'6033aa33b033b433b833bc33ab35bd35cf35f13503361536273639364b365d3670377a' \
'3792379937a337ab37b837bf37ef378838fd38b939cb39d839e439ee39f639013a313a' \
'613af83aa83bcb3b493c1a3d9d3dd53d183e1e3e523e5d3e803e443f513f6c3fd13fdd' \
'3f000000900000c000000055306f307830ca30ff3018311f3127312c31303134315d31' \
'8331a131a831ac31b031b431b831bc31c031c4310e32143218321c32203286329132ac' \
'32b332b832bc32c032e1320b333d33443348334c335033543358335c336033aa33b033' \
'b433b833bc337f34fb3427354f35863590351b3822384638563871389138e738f83833' \
'394f39aa39b539e339f139003a0e3a163a233a413a4b3a543a5f3a743a7b3a813a973a' \
'b23a573bc53bab3dc83df43d2d3e3a3e193f283f00a00000240000006e30ab30b530cd' \
'30f6302a315931003206320b32113218322a32c03300b000001c000000943198319c31' \
'a031a431b031b43168326c32000000c000005c000000bc34c034043508352835443548' \
'356835743590359c35b435b835d835f8351436183634363836583678369836b836d836' \
'f436f836183734373837583778379837b837d837e43700382038403860388038a038c0' \
'3800e00000e80000001c30a031a831203424342c3434343c3444344c3454345c346434' \
'6c3474347c3484348c3494349c34a434ac34b434bc34c434cc34d434dc344836b036c0' \
'36d036e036f03614372037243728372c37303738373c37683b603c643c683c6c3c703c' \
'743c783c7c3c803c843c903c943c983c9c3ca03ca43ca83cac3cb03cb43cb83cbc3cc0' \
'3cc43cc83ccc3cd03cd43cd83cdc3ce03ce43ce83cec3cf03cf43cf83cfc3c003d043d' \
'083d0c3d103d143d183d1c3d203d243d283d2c3d303d343d383d3c3d403d503d583d5c' \
'3d603d643d683d6c3d703d743d783d7c3d883d583e5c3e000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'0000000000000000000000000000000000000000000000000000000000000000000000' \
'00000000000000000000' \


class RemComMessagePayload(Structure):
    structure = (
        ('CommandLength','<L=0'),
        ('WorkingDir','260s=""'),
        ('Priority','<L=0x20'),
        ('ProcessID','<L=0x01'),
        ('Machine','260s=""'),
        ('NoWait','<L=0'),
        ('LogonFlags','<L=0'),
        ('User','260s=""'),
        ('Password','260s=""'),
    )

class RemComResponse(Structure):
    structure = (
        ('ErrorCode','<L=0'),
        ('ReturnCode','<L=0'),
    )

RemComSTDOUT         = "RemCom_stdout"
RemComSTDIN          = "RemCom_stdin"
RemComSTDERR         = "RemCom_stderr"

class RemComPipe:
    def __init__(self, tid, fid_main):
        self.tid = tid
        self.fid_main = fid_main

class RemComMessage:
    def __init__(self, s):
        self.__payload = RemComMessagePayload()
        self.__readBufferSize = 512
        self.__s = s
        # sys.getsizeof(self.__payload) returns 64, so it is apparently only counting the string fields as 4 bytes each
        self.__payloadSize = 1060 # 4 260-byte strings plus 5 4-byte integer fields

    def getCommand(self):
        return self.__command

    def setCommand(self, command):
        self.__command = command
        self.__payload['CommandLength'] = len(command)

    def getLogonFlags(self):
        return self.__payload['LogonFlags']

    def setLogonFlags(self, logonFlags):
        self.__packet['LogonFlags'] = LogonFlags

    def getMachine(self):
        return self.__payload['Machine']

    def setMachine(self, machine):
        self.__payload['Machine'] = machine

    def shouldWait(self):
        return self.__payload['NoWait']

    def setNoWait(self, noWait):
        self.__payload['NoWait'] = noWait

    def getPassword(self):
        return self.__payload['Password']

    def setPassword(self, password):
        self.__payload['Password'] = password

    def getPriority(self):
        return self.__payload['Priority']

    def setPriority(self, priority):
        self.__payload['Priority'] = priority

    def getProcessId(self):
        return self.__payload['ProcessID']

    def setProcessId(self, processId):
        self.__payload['ProcessID'] = processId

    def getUser(self):
        return self.__payload['User']

    def setUser(self, user):
        self.__payload['User'] = user

    def getWorkingDirectory(self):
        return self.__payload['WorkingDirectory']

    def setWorkingDirectory(self, workingDirectory):
        self.__payload['WorkingDirectory'] = workingDirectory

    def receive(self, pipe):
        LOG.debug("Receiving message")
        if not self.__receiveHeader(pipe):
            return False;
        if not self.__writeAck(pipe):
            return False;
        if not self.__receiveCommandText(pipe):
            return False;
        if not self.__writeAck(pipe):
            return False;
        return True

    def send(self, pipe):
        LOG.debug("Sending message")
        if not self.__sendHeader(pipe):
            return False;
        if not self.__readAck(pipe):
            return False;
        if not self.__sendCommandText(pipe):
            return False;
        return self.__readAck(pipe)

    def createPipeName(self, baseName):
        pipeName = '\%s%s%d' % (baseName, self.__payload['Machine'], self.__payload['ProcessID'])
        LOG.debug("createNamedPipe(baseName='%s', Machine='%s', ProcessID='%d') -> %s"
        % (baseName, self.__payload['Machine'], self.__payload['ProcessID'], pipeName))
        return pipeName

    #
    # Private
    #

    def __receiveCommandText(self, pipe):
        commandText = self.__readBytes(pipe, self.__payload['CommandLength'], "command bytes")
        self.setCommand(commandText)
        return True

    def __sendCommandText(self, pipe):
        return self.__writeBytes(pipe, self.__command, self.__payload['CommandLength'], "command bytes")

    def __receiveHeader(self, pipe):
        bytes = self.__readBytes(pipe, self.__payloadSize, "header bytes")
        self.__payload = RemComMessagePayload(bytes)
        return True

    def __sendHeader(self, pipe):
        return self.__writeBytes(pipe, self.__payload, self.__payloadSize, "header bytes")

    def __readAck(self, pipe):
        response = RemComResponse();
        bytes = self.__readBytes(pipe, 8, "ack bytes")
        response = RemComResponse(bytes)
        if response['ErrorCode'] != 0:
            return False
        return True

    def __writeAck(self, pipe):
        response = RemComResponse();
        response['ErrorCode'] = 0
        response['ReturnCode'] = 0
        return self.__writeBytes(pipe, response, 8, "ack bytes")
    
    def __readBytes(self, pipe, bytesToRead, suffix):
        LOG.debug("Reading %d %s" % (bytesToRead, suffix))
        bytes = self.__s.readNamedPipe(pipe.tid, pipe.fid_main, bytesToRead)
        return bytes

    def __writeBytes(self, pipe, bytes, bytesToWrite, suffix):
        LOG.debug("Writing %d %s" % (bytesToWrite, suffix))
        bytesWritten = self.__s.writeNamedPipe(pipe.tid, pipe.fid_main, str(bytes), bytesToWrite)
        return True

lock = Lock()

class PSEXEC:
    def __init__(self, command, path, exeFile, copyFile, port=445,
                 username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None):
        self.__username = username
        self.__password = password
        self.__port = port
        self.__command = command
        self.__path = path
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__exeFile = exeFile
        self.__copyFile = copyFile
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, remoteName, remoteHost):

        stringbinding = 'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)

        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.doStuff(rpctransport)

    def openPipe(self, s, tid, pipe, accessMask):
        pipeReady = False
        tries = 50
        while pipeReady is False and tries > 0:
            try:
                s.waitNamedPipe(tid,pipe)
                pipeReady = True
            except:
                tries -= 1
                time.sleep(2)
                pass

        if tries == 0:
            logging.critical('Pipe not ready, aborting')
            raise

        fid = s.openFile(tid,pipe,accessMask, creationOption = 0x40, fileAttributes = 0x80)

        return fid

    def doStuff(self, rpctransport):

        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception as e:
            #import traceback
            #traceback.print_exc()
            logging.critical(str(e))
            sys.exit(1)

        global dialect
        dialect = rpctransport.get_smb_connection().getDialect()

        try:
            unInstalled = False
            s = rpctransport.get_smb_connection()

            # We don't wanna deal with timeouts from now on.
            s.setTimeout(100000)
            if self.__exeFile is None:
                installService = ServiceInstall(rpctransport.get_smb_connection(), RemComSvc(), 'ArxRemComSvc', 'ArxRemComSvc.exe', False, False)
            else:
                try:
                    f = open(self.__exeFile)
                except Exception as e:
                    logging.critical(str(e))
                    sys.exit(1)
                installService = ServiceInstall(rpctransport.get_smb_connection(), f, 'ArxRemComSvc', 'ArxRemComSvc.exe')

            needinstall = False
# The first parameter here tells the check whether or not to start the service if it exists.
            resp = installService.checkService(not installService._reInstall)
            if resp:
                if installService._reInstall:
                    installService.uninstall()
                    needinstall = True
            else:
                needinstall = True
            if needinstall:
                if installService.install() is False:
                    return

            if self.__exeFile is not None:
                f.close()

            # Check if we need to copy a file for execution
            if self.__copyFile is not None:
                installService.copy_file(self.__copyFile, installService.getShare(), os.path.basename(self.__copyFile))
                # And we change the command to be executed to this filename
                self.__command = os.path.basename(self.__copyFile) + ' ' + self.__command

            logging.debug("Connecting to IPC$")
            tid = s.connectTree('IPC$')
            fid_main = self.openPipe(s,tid,'\RemCom_comm',0x12019f)

            logging.debug("Creating message instance")
            message = RemComMessage(s)
            pid = os.getpid()

            machine = ''.join([random.choice(string.letters) for _ in range(4)])
            logging.debug("Setting machine to %s" % (str(machine)))
            message.setMachine(machine)
            message.setUser(self.__username)
            message.setPassword(self.__password)
            if self.__path is not None:
                logging.debug("Setting working directory to %s" % (self.__path))
                message.setWorkingDirectory(self.__path)
            logging.debug("Setting command: %s" % (self.__command))
            message.setCommand(self.__command)
            logging.debug("Setting process id to %d" % (pid))
            message.setProcessId(pid)
            logging.debug("Creating pseudo-pipe")
            pipe = RemComPipe(tid, fid_main)
            message.send(pipe)

            # Here we'll store the command we type so we don't print it back ;)
            # ( I know.. globals are nasty :P )
            global LastDataSent
            LastDataSent = ''

            # Create the pipes threads
            stdin_pipe = RemoteStdInPipe(rpctransport, message.createPipeName(RemComSTDIN),
                                         smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, installService.getShare())
            stdin_pipe.start()
            stdout_pipe = RemoteStdOutPipe(rpctransport, message.createPipeName(RemComSTDOUT),
                                           smb.FILE_READ_DATA)
            stdout_pipe.start()
            stderr_pipe = RemoteStdErrPipe(rpctransport, message.createPipeName(RemComSTDERR),
                                           smb.FILE_READ_DATA)
            stderr_pipe.start()
            
            # And we stay here till the end
            ans = s.readNamedPipe(tid,fid_main,8)

            if len(ans):
                retCode = RemComResponse(ans)
                logging.debug("Process %s finished with ErrorCode: %d, ReturnCode: %d" % (
                self.__command, retCode['ErrorCode'], retCode['ReturnCode']))
            if installService._unInstall:
                installService.uninstall()
            if self.__copyFile is not None:
                # We copied a file for execution, let's remove it
                s.deleteFile(installService.getShare(), os.path.basename(self.__copyFile))
            unInstalled = True
            sys.exit(retCode['ErrorCode'] if retCode['ErrorCode'] else retCode['ReturnCode'])

        except SystemExit:
            raise
        except Exception as e:
            logging.critical("Got an exception")
            logging.critical(type(e))
            logging.critical(str(e))
            raise
        except:
            #import traceback
            #traceback.print_exc()
            if unInstalled is False and installService._reInstall:
                installService.uninstall()
                if self.__copyFile is not None:
                    s.deleteFile(installService.getShare(), os.path.basename(self.__copyFile))
            sys.stdout.flush()
            sys.exit(1)

class Pipes(Thread):
    def __init__(self, transport, pipe, permissions, share=None):
        Thread.__init__(self)
        self.server = 0
        self.transport = transport
        self.credentials = transport.get_credentials()
        self.tid = 0
        self.fid = 0
        self.share = share
        self.port = transport.get_dport()
        self.pipe = pipe
        self.permissions = permissions
        self.daemon = True

    def connectPipe(self):
        try:
            lock.acquire()
            global dialect
            #self.server = SMBConnection('*SMBSERVER', self.transport.get_smb_connection().getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
            self.server = SMBConnection(self.transport.get_smb_connection().getRemoteName(), self.transport.get_smb_connection().getRemoteHost(),
                                        sess_port=self.port, preferredDialect=dialect)
            user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
            if self.transport.get_kerberos() is True:
                self.server.kerberosLogin(user, passwd, domain, lm, nt, aesKey, kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
            else:
                self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree('IPC$') 

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions, creationOption = 0x40, fileAttributes = 0x80)
            self.server.setTimeout(1000000)
        except:
            import traceback
            traceback.print_exc()
            logging.error("Something wen't wrong connecting the pipes(%s), try again" % self.__class__)


class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    global LastDataSent
                    if ans != LastDataSent:
                        sys.stdout.write(ans.decode('cp437'))
                        sys.stdout.flush()
                    else:
                        # Don't echo what I sent, and clear it up
                        LastDataSent = ''
                    # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars, 
                    # it will give false positives tho.. we should find a better way to handle this.
                    if LastDataSent > 10:
                        LastDataSent = ''
                except:
                    pass

class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    sys.stderr.write(str(ans))
                    sys.stderr.flush()
                except:
                    pass

class RemoteShell(cmd.Cmd):
    def __init__(self, server, port, credentials, tid, fid, share, transport):
        cmd.Cmd.__init__(self, False)
        self.prompt = '\x08'
        self.server = server
        self.transferClient = None
        self.tid = tid
        self.fid = fid
        self.credentials = credentials
        self.share = share
        self.port = port
        self.transport = transport
#        self.intro = '[!] Press help for extra shell commands'

    def connect_transferClient(self):
        #self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port = self.port, preferredDialect = SMB_DIALECT)
        self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port=self.port,
                                            preferredDialect=dialect)
        user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials
        if self.transport.get_kerberos() is True:
            self.transferClient.kerberosLogin(user, passwd, domain, lm, nt, aesKey,
                                              kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
        else:
            self.transferClient.login(user, passwd, domain, lm, nt)

    def do_help(self, line):
        print("""
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (%s)
 get {file}                 - downloads pathname RELATIVE to the connected share (%s) to the current local dir 
 ! {cmd}                    - executes a local shell cmd
""" % (self.share, self.share))
        self.send_data('\r\n', False)

    def do_shell(self, s):
        os.system(s)
        self.send_data('\r\n')

    def do_get(self, src_path):
        try:
            if self.transferClient is None:
                self.connect_transferClient()

            import ntpath
            filename = ntpath.basename(src_path)
            fh = open(filename,'wb')
            logging.info("Downloading %s\%s" % (self.share, src_path))
            self.transferClient.getFile(self.share, src_path, fh.write)
            fh.close()
        except Exception as e:
            logging.critical(str(e))
            pass

        self.send_data('\r\n')
 
    def do_put(self, s):
        try:
            if self.transferClient is None:
                self.connect_transferClient()
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = '/'

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            f = dst_path + '/' + src_file
            pathname = string.replace(f,'/','\\')
            logging.info("Uploading %s to %s\%s" % (src_file, self.share, dst_path))
            self.transferClient.putFile(self.share, pathname.decode(sys.stdin.encoding), fh.read)
            fh.close()
        except Exception as e:
            logging.error(str(e))
            pass

        self.send_data('\r\n')

    def do_lcd(self, s):
        if s == '':
            print(os.getcwd())
        else:
            os.chdir(s)
        self.send_data('\r\n')

    def emptyline(self):
        self.send_data('\r\n')
        return

    def default(self, line):
        self.send_data(line.decode('UTF-8').encode('cp437')+'\r\n')

    def send_data(self, data, hideOutput = True):
        if hideOutput is True:
            global LastDataSent
            LastDataSent = data
        else:
            LastDataSent = ''
        self.server.writeFile(self.tid, self.fid, data)

class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None):
        self.shell = None
        Pipes.__init__(self, transport, pipe, permisssions, share)

    def run(self):
        self.connectPipe()
        self.shell = RemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.share, self.transport)
        self.shell.cmdloop()

if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
#    print version.BANNER

###
# The following are set based on options from the generating PHP.
# Also note that the reInstall and unInstall init parameters used
# for the ServiceInstall class are set by the PHP.
###
    debug = False
    if debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        print 'Running script from STDIN'
    else:
        logging.getLogger().setLevel(logging.INFO)

    command = 'ipconfig'
    username = r'tom'
    domain = r''
    password = os.environ.get('ARX_PY_PWD');
    if password == None:
        password = ''
    remoteName = target_ip = r'tom-think'
    port = 445
###
# The following are hard coded and not set by the generating PHP.
# We don't attempt to use these features.
###
    path = file = c = hashes = aesKey = dc_ip = None
    k = False
    no_pass = False

    if password == '' and username != '' and hashes is None and no_pass is False and aesKey is None:
        from getpass import getpass
        password = getpass("Enter password: ")

    executer = PSEXEC(command, path, file, c, port, username, password, domain, hashes,
                      aesKey, k, dc_ip)
    executer.run(remoteName, target_ip)





