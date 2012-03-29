#
#  Tor SEER 1.67 Agent.
#    By Erik Kline <ekline@lasr.cs.ucla.edu>
#  Setups up a Tor Network.  Currently only supports one directory node.
#  When Start is run, it should install Tor if not already installed, 
#  write configuration files for the directory, relays and client.  Finally,
#  start all the tor daemons.
#
#  Currently, only works on Ubuntu because it installs Tor using APT.
#    Should be fixed to use auto software install script
#
#  Code Based on Tor Setup Script 
#    by John Hickey <jjh@deterlab.net> and Genevieve Bartlett <bartlett@isi.edu>
#
#  Modifications by Chris Wacek (SAFER/SAFEST) <cwacek@cs.georgetown.edu>
#   * 10/10/11 - Added HUP command .
#   * 10/10/11 - Added support for modified Tor binaries.
#   * 10/12/11 - Added support for control messages to be sent to selected Tor Nodes.
#   * 10/13/11 - Added support for deleting Tor cache files.
#   * 10/13/11 - Made START/STOP more robust by removing init.d reliance; added KILL to make sure its dead if necessary.
#   * 10/14/11 - Added options for client and relay specific configuration options. 
#   * 10/18/11 - Added support to save relevant Tor data files to a specified directory.
#   * 10/26/11 - Changed directory file locking to use flufl-lock to avoid NFS race condition that
#                caused the lock to fail
#   * 10/24/11 - Added functionality that makes sure tsocks is installed (and then makes sure that
#                its configuration is ok).
#
#

from util.platform import spawn
from backend.agent import Agent
from backend.variables import *
from backend.addon import services
from testbed import testbed
from string import Template
import apt
import os
from subprocess import Popen, call
import subprocess
import time
from calendar import timegm
import shutil
import re
import sys
import pexpect
import socket,struct

class TorAgent(Agent):
    """ Tor Agent to setup a Tor net on an experiment """
    
    DEPENDS = []
    SOFTWARE = ['flufl-lock']
    
    AGENTGROUP = 'Configuration'
    AGENTTYPE = 'TOR'
    NICENAME = 'Tor'
    COMMANDS = ['START', 'STOP','KILL','HUP',"SEND_CTRL_MSG","RM_CACHE","SAVE_DATA"]
    VARIABLES = [
        #IntVar('directory_count', None, 'DirectoryCount', 'Number of directories'),
        NodeListVar('directory', None, 'Directory', 'Select the nodes that will be the Tor Directory'),
        NodeListVar('relays', None, 'Relays', 'Select the nodes that will be the Tor Relays'),
        NodeListVar('clients', None, 'Client', 'Select the node that will be the client'),
        StringVar('template_dir', None, 'TemplateDir', 'Directory for Tor template'),
        StringVar('tor_binary', None, 'Tor Binary', 'The path of a modified Tor binary to use'),
        StringListVar('env_var_export',None,"Environment Variables","Comma separated list of environment variables to export 'VAR=blahblahblah'"),
        StringVar('save_data_dir',None,"Save Directory", "The path to save logs to if requested"),
        StringListVar('client_config_list',None,"Client Config","Comma separated list of Tor configuration options "),
        StringListVar('relay_config_list',None,"Relay Config","Comma separated list of Tor configuration options for relays"),
        Title("Control Port Messaging"),
        NodeListVar('ctl_dst', None, 'Control Targets','The nodes to send control messages to'),
        StringVar("ctl_msg",None,'Control Port Message','The command to send to the control port. You will not see the response, so be don\' send GETINFO or similar')
        ]

    DATA_DIR = "/var/lib/tor"
    TOR_GENCERT="/usr/bin/tor-gencert"
    TOR_BIN="/usr/sbin/tor"
    TOR_RC="/etc/tor/torrc"
    CONTROL_DIR="/var/run/tor"
    TOR_LOG='/var/log/tor/log'
    TOR_CACHE={'files':[
                    'cached-certs',
                    'log',
                    'v3-status-votes',
                    'state',
                    'cached-consensus',
                    'cached-descriptors',
                    'cached-descriptors.new',
                    'cached-extrainfo',
                    'cached-extrainfo.new',
                    'cached-microdescs',
                    'cached-microdescs.new',
                    'cached-microdesc-consensus',
                    'cached-consensus.new' 
                    ],
                'dirs':[
                    'cached-status'
                    ]
              }

    def __init__(self):
        Agent.__init__(self)

        self.beenSetup = False
        self.tor_pid = None
        directorylinedir = "/proj/%s/exp/%s" % (testbed.project, testbed.experiment)
        self.dirline_file = "%s/dirfile" % directorylinedir
        self.dirline_lock = "%s/dirlock" % directorylinedir
        self.dirline_sem = "%s/dirsem" %directorylinedir

    def get_ip_address(self):
        """Get one of our IP addresses that is not in the control net"""
        
        mask1 = struct.unpack('L', socket.inet_aton("192.0.0.0"))[0]
        mask2 = struct.unpack('L', socket.inet_aton("172.0.0.0"))[0]

        for ip in testbed.getLocalIPList():
            addr = struct.unpack('L',socket.inet_aton(ip))[0]  
            #mask out 192 and 172 blocks.
            if((addr & mask1) != mask1 and (addr & mask2) != mask2):
                self.log.info("Found IP %s" % ip)
                return ip
            
        return "0.0.0.0"
    
    def write_config(self, template_file, destination, **vars):
        """Write out the tor rc file"""

        self.log.info("Writing tor rc file")
        
        template_file = "%s/%s" % (self.template_dir, template_file)
        
        self.log.info("Opening template file %s." % template_file)
        try:
            template = Template(open(template_file).read())
        except Exception as e:
            self.log.info("Failed reading template file %s: %s" % (template_file, str(e)))
            sys.exit(1)
            
        config = template.substitute(vars)

        self.log.info("Checking that destination directory exists")
        dest_path = os.path.dirname(destination)

        if not os.path.exists(dest_path):
            os.makedirs(dest_path)
            
        self.log.info("Writing tor rc file to %s" % destination)
        try:
            rc = open(destination, "w")
            rc.write(config)
        except Exception as e:
            self.log.info("Failed to write tor rc file %s: %s" %(template_file, str(e)))
            self.log.info("Is tor installed (use -i)?")
            sys.exit(1)


    def install_packages(self, names):
        """Use python-apt to install a list of packages, such as tor"""
        # THIS ONLY WORKS ON UBUNTU
        
        self.log.info("Install packages")
        
        cache = apt.Cache()
        
        self.log.info("Updating apt cache")

        try:
            cache.update()
        except Exception as e:
            self.log.info("Failed to update the apt cache: %s" % str(e))
            self.log.info("Are you running as root?")

        cache.open(None)

        self.log.info("Marking packages")

        for name in names:
            try:
                pkg = cache[name]
                
                if not pkg.is_installed:
                    self.log.info("Marking %s for installation" % name)
                    pkg.mark_install()

            except Exception as e:
                self.log.info("Problem looking up or marking %s for installation: %s" % (name, str(e)))

        self.log.info("Installing packages...")

        try:
            cache.commit()
        except Exception as e:
            self.log.info("Failed to install packages: %s" % str(e))
            self.log.info("Are you running as root?")

    def simple_run(self, cmd, die=True):
        """Basic function to run a command and log it"""
        try:
            self.log.info("Calling %s " % (cmd))
            with open(os.devnull,'w') as stderr_null:
                p = Popen(cmd.split(),stdout=subprocess.PIPE,stderr=stderr_null)
                output =  p.communicate()
                if p.returncode != 0:
                    self.log.warning("'%s' returned non-zero [%s]"%(cmd,p.returncode))
                try:
                    command_output = output[0]
                except Exception as e:
                    self.log.error("BAD Error: %s"%e)
        except subprocess.CalledProcessError as e:
            self.log.error("Command %s failed: [%s] %s" % (cmd, str(e.returncode),str(e.output)))
            raise
        
        return command_output

    def isRunning(self):
        try:
            if self.tor_pid:
                return True
        except Exception:
            pass
        return False

    def start_tor(self):
        self.log.info("Starting Tor")
        if self.env_var_export is not None and len(self.env_var_export) > 0:
            cmd = ['sudo']
            cmd.extend(self.env_var_export)
            cmd.extend([self.TOR_BIN,"-f",self.TOR_RC])
        else:
            cmd = ['sudo',self.TOR_BIN,"-f",self.TOR_RC]
        self.log.info("Starting Tor with command: %s [pid: %s]" % (cmd,self.tor_pid))
        self.tor_pid = Popen(cmd).pid 

    def stop_tor(self,force=False):
        if force:
            call(['sudo','killall','-9','tor'])
            self.tor_pid = None
        elif self.isRunning():
            self.log.info("Stopping Tor")
            try:
                self.simple_run('sudo kill %s' % (self.tor_pid),die=False)
            except CalledProcessError:
                self.log.error("Force-killing Tor")
                self.stop_tor(force=True)
            self.tor_pid = None
        else:
            self.log.info("Tor not running; not stopped")

    def restart_tor(self):
        self.stop_tor()
        time.sleep(2)
        self.start_tor()

    def get_directory_line(self):
        self.log.info("Spin-waiting for directory file")
        attempts = 0
        while (os.path.exists(self.dirline_sem) or not os.path.exists(self.dirline_file)):
            time.sleep(5)
            attempts += 1
            if attempts > (12*2): #2 minutes spent waiting (12*5secs*2)
                raise Exception("Spent over 2 minute waiting for directory lines. Exiting")
            continue

        self.log.info("Obtaining directory lines")

        f = open(self.dirline_file, "r")
        dirline = f.read()
        f.close()
        self.log.info("Got Dirline")
        return dirline

    def remove_if_exists(self,f):
        try:
            os.remove(f)
            ret = 0
        except OSError as e:
            ret = -1
        finally:
            return ret

    def setup(self):
        """ Setup our nodes with Tor """
        #HACK UP DIRECTORY FILE
        directorylinedir = "/proj/%s/exp/%s" % (testbed.project, testbed.experiment)
        self.dirline_file = "%s/dirfile" % directorylinedir
        self.dirline_lock = "%s/dirlock" % directorylinedir
        self.dirline_sem = "%s/dirsem" %directorylinedir
        self.remove_if_exists(self.dirline_file)
        self.remove_if_exists(self.dirline_lock)
        self.remove_if_exists(self.dirline_sem)

        
        self.log.info("In Setup")

        self.install_packages(('tor', 'tsocks','libgmp3-dev'))
        #Make sure nothing is running after the package is started
        self.stop_tor(force=True)

        try:
            self.simple_run("sudo rm -rf %s" % self.DATA_DIR)
            self.simple_run("sudo mkdir -p %s" % self.DATA_DIR)
            self.simple_run("sudo chown -R root:root %s" % self.DATA_DIR)
            self.simple_run("sudo chown -R root:root %s" % self.CONTROL_DIR)
        except Exception as e:
            self.log.error("Error setting permissions on data directory %s" % self.DATA_DIR)
            raise

        if self.tor_binary:
            copied = False
            attempts = 25
            self.log.info("Replacing %s with %s" % (self.TOR_BIN, self.tor_binary))
            while not copied and attempts > 0:
                try:
                    shutil.copy2(self.TOR_BIN,"/tmp/tor_bin")
                    shutil.copy(self.tor_binary,self.TOR_BIN)
                    shutil.copystat("/tmp/tor_bin",self.TOR_BIN)
                    copied = True
                except IOError as (errno,strerr):
                    self.log.info("Error copying tor binary (%s: %s)" %(errno,strerr) )
                    if errno == 26:
                        self.stop_tor(force=True)
                    attempts -= 1
                    time.sleep(2)
        if self.clients and self.clients.myNodeMemberOf():
            try:
                shutil.copy("%s/tsocks.conf" % self.template_dir, "/etc/tsocks.conf")
            except Exception as e:
                self.log.info("Failed to copy tsocks config file: %s" % e)

        if(self.directory and self.directory.myNodeMemberOf()):
            #if a directory, also write the directory config
            try:
                import flufl.lock
            except ImportError:
                sys.path.append("/opt/local/egg/flufl-lock.egg")
                import flufl.lock

            self.dirline_mutex = flufl.lock.Lock(self.dirline_lock)
            address = self.get_ip_address()

            self.write_config("torrc-directory.template", self.TOR_RC, ip_address=address,extra_options="")
            self.log.info("  Setup Directory")
        
        self.log.info("Setup Complete")
        self.beenSetup = True
    
    def isSetup(self):
        return self.beenSetup

    def handleSEND_CTRL_MSG(self):
        """ Send a message to the control port of selected Tor instances """

        if not self.ctl_dst.myNodeMemberOf():
            return
        if self.ctl_dst and self.ctl_msg :
            self.log.info("Sending control message to selected Tor nodes")
            #if not self.isSetup():
            #    self.log.warning("Tor not setup. Cannot send control port messages")
            #    return

            self.log.warning("Looking for the control port")
            controlPort = None
            controlAddr = None
            
            f = open(self.TOR_RC,'r')
            for line in f:
                if line.startswith("ControlPort"):
                    controlPort = line.split()[1]
                if line.startswith("ControlListenAddress"):
                    controlAddr = line.split()[1]

            if controlPort is None:
                self.log.warning("%s is not running a control port" % (testbed.getNodeName()))
                return
            
            if controlAddr is None:
                controlAddr = '127.0.0.1'
            try: 
                child = pexpect.spawn('nc %s %s' % (controlAddr, controlPort))
                child.sendline('authenticate ""')
                exp_result = child.expect(['250 OK',pexpect.EOF,pexpect.TIMEOUT])
                if exp_result == 1:
                    raise Exception("Pexpect ended with EOF")
                elif exp_result == 2:
                    raise Exception("Pexpect timed out")

                child.sendline('%s' % (self.ctl_msg))
                i = child.expect(['2\d\d [\d\w]+','[56]\d\d [\d\w]+'])
                if i==0:
                    self.log.info('Response: %s',child.after)
                    child.close()
                else: 
                    child.close()
                    raise Exception("Command failed: %s " % (child.before))
            except Exception as e:
                self.log.warning("Unable to send control port message: %s" % e)
                return

        else:
            self.log.warning("Need both destination and message to send control port message. (dest: %s, msg: %s" %(self.ctl_dst, self.ctl_msg))

    def handleSAVE_DATA(self):
        """Save log data from the tor instances to the directory 
           specified by the 'save_data_dir' directory. Will not do anything if Tor
           is running."""

        is_client = (self.clients and self.clients.myNodeMemberOf())
        is_dir = (self.directory and self.directory.myNodeMemberOf())
        is_relay = (self.relays and self.relays.myNodeMemberOf())
        
        if not is_client and not is_relay and not is_dir:
            return

        if self.isRunning():
            raise Exception("Will not save data while Tor is running")

        if not self.save_data_dir or not os.path.exists(self.save_data_dir):
            raise Exception("SAVE_DATA command requires 'save_data_dir' to be specified and valid")

        ts = time.gmtime()
        minute_round = (ts[4]/5) * 5 if ts[4] != 0 else 0
        timesecs = time.mktime((ts[0],ts[1],ts[2],ts[3],minute_round + 5,0,ts[6],ts[7],ts[8]))
        path = "%s/%s/%s/%s" % (self.save_data_dir,testbed.experiment,int(timesecs),testbed.getNodeName())

        failed = False
        try:
            shutil.copytree(self.DATA_DIR,path)
        except shutil.Error as e:
            self.log.warning("Error copying data: %s" % (",".join(e)))
            failed = True
        try:
            shutil.copy(self.TOR_LOG,path)
        except shutil.Error as e:
            self.log.warning("Error copying data: %s" % (",".join(e)))
            failed = True
        try:
            shutil.copy(self.TOR_RC,path)
        except shutil.Error as e:
            self.log.warning("Error copying data: %s" % (",".join(e)))
            failed = True
        try:
            shutil.copy("/local/logs/daemon.log",path)
        except shutil.Error as e:
            self.log.warning("Error copying data: %s" % (",".join(e)))
            failed = True 

        if failed is True:
            raise Exception ("Failed to copy all items")

        self.log.info("Copied %s to %s" % (self.DATA_DIR, path))

    def handleRM_CACHE(self):
        """Cleanup the relay's history by removing log files, cached descriptors, etc in the 
           data directory. If Tor is running, don't do anything"""

        if (self.isRunning()):
            raise Exception("You really dont' want to clean the directory with Tor running")

        if not os.path.exists(self.DATA_DIR):
            self.log.info("No data directory to clean. Exiting")
            return

        failed = list()
        for cachefile in self.TOR_CACHE['files']:
            try:
                os.remove("%s/%s" %(self.DATA_DIR,cachefile))
            except OSError:
                failed.append(cachefile)
        
        for cachedir in self.TOR_CACHE['dirs']:
            try:
                shutil.rmtree("%s/%s" % (self.DATA_DIR,cachedir))
            except (shutil.Error, OSError):
                failed.append(cachedir)

        try:
            os.remove("%s" % self.TOR_LOG)
        except OSError:
            failed.append(self.TOR_LOG)

        self.log.debug("Failed to remove %s" %(','.join(failed)))
        self.log.info("Removed Tor Cache files")

    def handleSTART(self):
        """ Handle the start message """

        if(self.isRunning()):
               self.log.info("Already running")
               return
        
        self.log.info("Hello");

        if(not self.isSetup()):
            self.setup()

        # Multiplex for different Node types

        if(self.directory and self.directory.myNodeMemberOf()):
            self.log.info("Directory")
            self.directoryExec()
            
        if(self.relays and self.relays.myNodeMemberOf()):
            self.log.info("Relay")
            self.relayExec()

        if(self.clients and self.clients.myNodeMemberOf()):
            self.log.info("Client")
            self.clientExec()
    
    def handleHUP(self):
        """ Handle the Hup message """
        if self.isRunning():
            self.log.info("Hupping")
            try:
                self.simple_run("sudo kill -s SIGHUP %s" % (self.tor_pid))
            except Exception as e:
                self.log.error("Failed to HUP: %s" % e)
        else:
            self.log.info("Not currently running, did not HUP")

    def handleKILL(self):
        """Handle the KILL message by killing Tor"""
        self.stop_tor(force=True)
        self.beenSetup = False
        self.log.info("Killed") 
    
    def handleSTOP(self):
        """ Handle the Stop message """
        self.log.info("Stopping")
  
        #  Getting rid of our Kludgy hack file
        if(self.directory and self.directory.myNodeMemberOf() and os.path.exists(self.dirline_file)):
            try:
                os.remove(self.dirline_file)
            except Exception as e:
                self.log.info("Exception when removing dirline_file: %s" % e)
                pass

            try:
                os.remove(self.dirline_lock)
            except Exception as e:
                self.log.info("Exception when removing dirline_lock: %s" % e)
                pass
            
            try:
                os.remove(self.dirline_sem)
            except Exception as e:
                self.log.info("Exception when removing dirline_sem: %s" % e)
                pass

        self.stop_tor()
        self.beenSetup = False
        self.log.info("Stopped")

    def relayExec(self):
        """ Start a Relay """

        address = self.get_ip_address()
        dirline = self.get_directory_line()

        if self.relay_config_list is not None and len(self.relay_config_list) > 0:
            opts = "\n".join(self.relay_config_list)
        else:
            opts = ""

        self.write_config("torrc-relay.template", self.TOR_RC, ip_address=address, directory_line=dirline,extra_options=opts)
        self.restart_tor()
        self.log.info("  Relay Done")

    def clientExec(self):
        """ Start a Client """

        address = self.get_ip_address()
        dirline = self.get_directory_line()

        if self.client_config_list is not None and len(self.client_config_list) > 0:
            opts = "\n".join(self.client_config_list)
        else:
            opts = "" 

        self.write_config("torrc-client.template", self.TOR_RC, ip_address=address, directory_line=dirline,extra_options=opts)

        self.restart_tor()
        self.log.info("  Client Done")

    def directoryExec(self):
        """ Start the Directory Server"""
        address = self.get_ip_address()

        self.stop_tor()

        #Fix for data directory issues. Starting Tor forces it to create the 
        # data directory.
        self.start_tor()
        self.stop_tor()

        # Key Directory

        keydir = self.DATA_DIR + "/keys"

        try:
            if os.path.exists(keydir):
                self.log.info("Removing old key directory %s" % keydir)
                shutil.rmtree(keydir)

            self.log.info("Creating key directory %s" % keydir)
            os.mkdir(keydir)
        except Exception as e:
            self.log.error("Failed to create key directory: %s" % str(e))
            
        # Create Identity Key
        self.log.info("Creating directory server identity key")

        try:
            cmd = "%s --create-identity-key" % self.TOR_GENCERT

            self.log.info("Calling %s in %s" % (cmd, keydir))

            child = pexpect.spawn(cmd, cwd=keydir)
    
            child.expect("Enter PEM pass phrase:", timeout=120)
            child.sendline("asdf")
            child.expect("Verifying - Enter PEM pass phrase:", timeout=120)
            child.sendline("asdf")
            
            # If we don't wait for EOF, we get no keys!
            child.expect(pexpect.EOF)

        except Exception as e:
            self.log.error("Failed to generate directory server identity key: %s" % str(e))
            sys.exit(1)

        self.log.info("Setting %s to ownership by user root." % keydir)
        
 
        #:wGet the directory server fingerprint
        # tor --quiet --list-fingerprint --DataDirectory /var/lib/tor -f /etc/tor/torrc
        self.write_config("torrc-directory.template", self.TOR_RC, ip_address=address,extra_options="")
        self.log.info("Getting directory server fingerprint")
        try:
            if self.env_var_export is not None and len(self.env_var_export) > 0:
                cmd = 'sudo'
                for var in self.env_var_export:
                    cmd += " %s" %var
                cmd += " %s --quiet --list-fingerprint -f %s " %(self.TOR_BIN,self.TOR_RC)
            else:
                cmd = "sudo tor --quiet --list-fingerprint -f %s" % self.TOR_RC
            (nodename, fingerprint) = self.simple_run(cmd).strip().split(' ', 1)
        except Exception as e:
            self.log.error("Failed to obtain fingerprint: %s" % e)
            raise
        self.log.info("Server fingerprint is: %s" % fingerprint)
   
        # Get the v3ident fingerprint from DATA_DIR/keys/authority_certificate
        #
        
        try:
            authority_certificate = open("%s/keys/authority_certificate" % self.DATA_DIR).read()
            regex = re.compile("fingerprint (\w+)", re.MULTILINE)
            match = regex.search(authority_certificate)
            v3ident = match.group(1)
        except Exception as e:
            self.log.error("Failed to find v3ident fingerprint: %s" % str(e))
            sys.exit(1)

        # Save Directory information
    
        self.log.info("Saving info")

        name = testbed.nodename

        dir_line = "DirServer %s v3ident=%s orport=%s %s:%s %s" % (name, v3ident, "9001", address, "5000", fingerprint)


        #HUGE HACK
        #Pass Directory information to other nodes via shared file
        # Should be done via messaging.

        try:
            self.log.info("Acquiring dirline lock")
            self.dirline_mutex.lock()
            
            semval = 0

            if(not os.path.exists(self.dirline_sem)):
                sem = open(self.dirline_sem, 'w')
                semstr = "%d" % len(self.directory) 
                self.log.info("Writing dirsem as %s" % semstr)
                semval = len(self.directory)
                sem.write(semstr)
                sem.close()
            else:
                sem = open(self.dirline_sem, 'r')
                semstr = sem.read()
                self.log.info("Read dirsem as %s" % semstr)
                semval = int(semstr)
                sem.close()

            dir_line2 = "%s\n" % dir_line
            dir_line = dir_line2

            self.log.info("Writing dirline")
            if os.path.exists(self.dirline_file):
                f = open(self.dirline_file, 'a')
            else:
                f = open(self.dirline_file, 'w')
            f.write(dir_line)
            f.close()

            self.log.info("Decrementing semaphore")
            semval = semval - 1
            if(semval <= 0):
                os.remove(self.dirline_sem)
            else:
                sem = open(self.dirline_sem, 'w')
                semstr = "%d" % semval
                sem.write(semstr)
                sem.close()

            self.log.info("Removing lock file")
            self.dirline_mutex.unlock()
                   
        except Exception as e:
            self.log.error("Problem with DIR File: %s" % str(e))
        

        # Get everyone elses dir info and change config file
        dirline2 = self.get_directory_line()

        if self.relay_config_list is not None and len(self.relay_config_list) > 0:
            opts = "\n".join(self.relay_config_list)
        else:
            opts = "" 

        self.write_config("torrc-multidirectory.template", self.TOR_RC, ip_address=address, directory_line=dirline2,extra_options=opts)

        # Start Tor
        self.start_tor()

        self.log.info("Directory Server UP")


